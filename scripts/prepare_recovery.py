#!/usr/bin/env python3
"""Validate and package a Glyphchain factory HEX as a USB recovery image.

The recovery image is flashed over USB by pvs64.com/glyphchain/recover through
the chip's ROM bootloader. It is never sent over BLE: the apps read only the
application manifest and the stable/beta channels, never these files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

# Everything below the saved-image store at 0x50000: JumpIAP, the application,
# the IAP, the fixed BLE library, and the system frames.
FACTORY_LIMIT = 0x50000
APPLICATION_START = 0x1000
APPLICATION_END = APPLICATION_START + 44 * 1024
REQUIRED_REGIONS = (
    (0x00000, "JumpIAP"),
    (0x01000, "application"),
    (0x0C000, "IAP"),
    (0x10000, "BLE library"),
)
FACTORY_NAME = "Glyphchain-OTA-Factory.hex"
APPLICATION_NAME = "Glyphchain-Firmware.hex"
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


class PackageError(ValueError):
    pass


def read_intel_hex(source: bytes, limit: int) -> dict[int, int]:
    """Decode Intel HEX into {address: byte}, rejecting data at or above limit."""
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
                if address >= limit:
                    raise PackageError(
                        f"Data at 0x{address:08X} is outside the region below 0x{limit:08X}."
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
                f"Unsupported Intel HEX record type 0x{record_type:02X} on line {line_number}."
            )

    if not found_eof:
        raise PackageError("The firmware HEX has no EOF record.")
    if not memory:
        raise PackageError("The firmware HEX contains no data.")
    return memory


def application_bytes(memory: dict[int, int]) -> bytes:
    """The application region as the OTA image lays it out (gaps read 0xFF)."""
    addresses = [a for a in memory if APPLICATION_START <= a < APPLICATION_END]
    if not addresses:
        raise PackageError("The factory HEX contains no application.")
    end = max(addresses) + 1
    return bytes(memory.get(a, 0xFF) for a in range(APPLICATION_START, end))


def check_factory(memory: dict[int, int]) -> None:
    for start, name in REQUIRED_REGIONS:
        if start not in memory:
            raise PackageError(f"The factory HEX is missing the {name} at 0x{start:05X}.")

    app = application_bytes(memory)
    entry = int.from_bytes(app[0:4], "little")
    if entry in (0, 0xFFFFFFFF):
        raise PackageError("The application entry instruction is invalid.")
    marker_address = int.from_bytes(app[4:8], "little")
    offset = marker_address - APPLICATION_START
    if (
        marker_address % 4
        or offset < 8
        or offset + 4 > len(app)
        or int.from_bytes(app[offset : offset + 4], "little") != 0xFFFFFFFF
    ):
        raise PackageError("The application-ready marker is invalid.")


def check_matches_application(memory: dict[int, int], application_hex: Path) -> None:
    """The factory image must carry the same application as the OTA release."""
    ota = read_intel_hex(application_hex.read_bytes(), APPLICATION_END)
    if application_bytes(ota) != application_bytes(memory):
        raise PackageError(
            f"The application inside the factory HEX does not match {application_hex.name}. "
            "Build both from the same `make rebuild`."
        )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hex", required=True, type=Path, dest="hex_path")
    parser.add_argument("--version", required=True)
    parser.add_argument("--build-number", required=True, type=int)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--model", default="G1")
    parser.add_argument("--hardware-revision", default="v1.0.0")
    parser.add_argument("--signing-key-id", default="glyphchain-release-2026-01")
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
    if not arguments.base_url.startswith("https://"):
        raise PackageError("Base URL must use HTTPS.")

    source = arguments.hex_path.read_bytes()
    memory = read_intel_hex(source, FACTORY_LIMIT)
    check_factory(memory)

    version = arguments.version
    stem = f"glyphchain-g1-v{version}"
    release_directory = arguments.output_directory / f"firmware-v{version}"
    release_directory.mkdir(parents=True, exist_ok=True)

    application_hex = release_directory / APPLICATION_NAME
    if application_hex.exists():
        check_matches_application(memory, application_hex)
        print(f"Application region matches {application_hex}")
    else:
        print(f"warning: {application_hex} not found; run prepare_release.py first to cross-check")

    factory_path = release_directory / FACTORY_NAME
    shutil.copyfile(arguments.hex_path, factory_path)

    sha256 = hashlib.sha256(source).hexdigest()
    manifest = {
        "schemaVersion": 1,
        "kind": "glyphchain-recovery",
        "releaseID": f"glyphchain-g1-v{version}",
        "version": version,
        "buildNumber": arguments.build_number,
        "signingKeyID": arguments.signing_key_id,
        "model": arguments.model,
        "hardwareRevision": arguments.hardware_revision,
        "chip": "CH592",
        "publishedAt": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "image": {
            "fileName": FACTORY_NAME,
            "format": "intel-hex",
            "downloadURL": f"{arguments.base_url.rstrip('/')}/{FACTORY_NAME}",
            "downloadSize": len(source),
            "flashEnd": max(memory) + 1,
            "sha256": sha256,
        },
    }

    manifest_path = release_directory / f"{stem}.recovery.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    print(f"Factory image: {factory_path}")
    print(f"Recovery manifest: {manifest_path}")
    print(f"Flash data ends at 0x{max(memory) + 1:05X}")
    print("Sign the recovery manifest before publishing the release.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, PackageError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
