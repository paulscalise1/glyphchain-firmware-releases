#!/usr/bin/env python3
"""Validate and package a Glyphchain application HEX for release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import zlib
from datetime import datetime, timezone
from pathlib import Path

APPLICATION_START = 0x1000
APPLICATION_CAPACITY = 44 * 1024
APPLICATION_END = APPLICATION_START + APPLICATION_CAPACITY
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


class PackageError(ValueError):
    pass


def parse_intel_hex(source: bytes) -> bytes:
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PackageError("The firmware HEX is not valid UTF-8 text.") from error

    upper_address = 0
    memory: dict[int, int] = {}
    found_eof = False

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if found_eof:
            raise PackageError(f"Record found after EOF on line {line_number}.")
        if not line.startswith(":"):
            raise PackageError(f"Malformed Intel HEX record on line {line_number}.")

        try:
            record = bytes.fromhex(line[1:])
        except ValueError as error:
            raise PackageError(f"Invalid hexadecimal data on line {line_number}.") from error

        if len(record) < 5:
            raise PackageError(f"Intel HEX record is too short on line {line_number}.")

        byte_count = record[0]
        if len(record) != byte_count + 5:
            raise PackageError(f"Intel HEX byte count is invalid on line {line_number}.")
        if sum(record) & 0xFF:
            raise PackageError(f"Intel HEX checksum is invalid on line {line_number}.")

        record_address = int.from_bytes(record[1:3], "big")
        record_type = record[3]
        data = record[4:-1]

        if record_type == 0x00:
            base_address = upper_address + record_address
            for offset, byte in enumerate(data):
                address = base_address + offset
                if address in memory:
                    raise PackageError(f"Overlapping data at address 0x{address:08X}.")
                if not APPLICATION_START <= address < APPLICATION_END:
                    raise PackageError(
                        f"Data at 0x{address:08X} is outside the OTA application region. "
                        "Use Glyphchain-Firmware.hex, not Glyphchain-OTA-Factory.hex."
                    )
                memory[address] = byte
        elif record_type == 0x01:
            if byte_count != 0:
                raise PackageError(f"Invalid EOF record on line {line_number}.")
            found_eof = True
        elif record_type == 0x02:
            if len(data) != 2:
                raise PackageError(f"Invalid extended segment record on line {line_number}.")
            upper_address = int.from_bytes(data, "big") << 4
        elif record_type == 0x04:
            if len(data) != 2:
                raise PackageError(f"Invalid extended linear record on line {line_number}.")
            upper_address = int.from_bytes(data, "big") << 16
        elif record_type in (0x03, 0x05):
            if len(data) != 4:
                raise PackageError(f"Invalid start-address record on line {line_number}.")
        else:
            raise PackageError(
                f"Unsupported Intel HEX record type 0x{record_type:02X} "
                f"on line {line_number}."
            )

    if not found_eof:
        raise PackageError("The firmware HEX has no EOF record.")
    if not memory:
        raise PackageError("The firmware HEX contains no application data.")

    first_address = min(memory)
    last_address = max(memory)
    if first_address != APPLICATION_START:
        raise PackageError(
            f"The application begins at 0x{first_address:08X}, expected 0x{APPLICATION_START:08X}."
        )

    image_length = last_address - APPLICATION_START + 1
    if image_length < 8 or image_length > APPLICATION_CAPACITY or image_length % 4:
        raise PackageError(
            f"The decoded image length ({image_length}) is invalid for the OTA protocol."
        )

    image = bytearray([0xFF]) * image_length
    for address, byte in memory.items():
        image[address - APPLICATION_START] = byte

    entry_instruction = int.from_bytes(image[0:4], "little")
    if entry_instruction in (0, 0xFFFFFFFF):
        raise PackageError("The application entry instruction is invalid.")

    marker_address = int.from_bytes(image[4:8], "little")
    marker_offset = marker_address - APPLICATION_START
    if (
        marker_address < APPLICATION_START
        or marker_address % 4
        or marker_offset < 0
        or marker_offset + 4 > image_length
        or int.from_bytes(image[marker_offset : marker_offset + 4], "little") != 0xFFFFFFFF
    ):
        raise PackageError("The application-ready marker is invalid.")

    return bytes(image)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hex", required=True, type=Path, dest="hex_path")
    parser.add_argument("--version", required=True)
    parser.add_argument("--build-number", required=True, type=int)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--model", default="G1")
    parser.add_argument("--hardware-revision", default="v1.0.0")
    parser.add_argument("--ota-protocol-version", default=2, type=int)
    parser.add_argument("--signing-key-id", default="glyphchain-release-2026-01")
    parser.add_argument("--release-notes", default="")
    parser.add_argument("--mandatory", action="store_true")
    parser.add_argument("--output-directory", type=Path, default=Path("dist"))
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()

    if not VERSION_PATTERN.fullmatch(arguments.version):
        raise PackageError("Version must use semantic versioning, for example 1.0.1.")
    if arguments.build_number < 1:
        raise PackageError("Build number must be at least 1.")
    if arguments.model != "G1":
        raise PackageError("This distribution contract currently supports model G1 only.")
    if not 1 <= arguments.ota_protocol_version <= 255:
        raise PackageError("OTA protocol version must fit in one byte.")
    if not arguments.base_url.startswith("https://"):
        raise PackageError("Base URL must use HTTPS.")
    if "factory" in arguments.hex_path.name.lower():
        raise PackageError("Factory images cannot be distributed through application OTA.")

    source = arguments.hex_path.read_bytes()
    image = parse_intel_hex(source)

    version = arguments.version
    stem = f"glyphchain-g1-v{version}"
    release_directory = arguments.output_directory / f"firmware-v{version}"
    release_directory.mkdir(parents=True, exist_ok=True)

    firmware_name = "Glyphchain-Firmware.hex"
    firmware_path = release_directory / firmware_name
    shutil.copyfile(arguments.hex_path, firmware_path)

    sha256 = hashlib.sha256(source).hexdigest()
    crc32 = zlib.crc32(image) & 0xFFFFFFFF
    download_url = f"{arguments.base_url.rstrip('/')}/{firmware_name}"
    release_id = f"glyphchain-g1-v{version}"

    manifest = {
        "schemaVersion": 1,
        "releaseID": release_id,
        "version": version,
        "buildNumber": arguments.build_number,
        "signingKeyID": arguments.signing_key_id,
        "model": arguments.model,
        "hardwareRevision": arguments.hardware_revision,
        "otaProtocolVersion": arguments.ota_protocol_version,
        "applicationStart": APPLICATION_START,
        "applicationCapacity": APPLICATION_CAPACITY,
        "mandatory": arguments.mandatory,
        "publishedAt": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "releaseNotes": arguments.release_notes,
        "image": {
            "fileName": firmware_name,
            "format": "intel-hex",
            "downloadURL": download_url,
            "downloadSize": len(source),
            "imageLength": len(image),
            "crc32": f"{crc32:08X}",
            "sha256": sha256,
        },
    }

    manifest_path = release_directory / f"{stem}.manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    checksum_path = release_directory / f"{stem}.sha256"
    checksum_path.write_text(f"{sha256}  {firmware_name}\n", encoding="ascii")

    print(f"Firmware: {firmware_path}")
    print(f"Manifest: {manifest_path}")
    print(f"Checksum: {checksum_path}")
    print(f"Decoded image: {len(image)} bytes")
    print(f"OTA CRC32: {crc32:08X}")
    print("Sign the manifest before publishing the release.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, PackageError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
