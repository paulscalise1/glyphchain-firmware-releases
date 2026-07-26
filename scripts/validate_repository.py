#!/usr/bin/env python3
"""Perform dependency-free safety checks on distribution metadata."""

from __future__ import annotations

import base64
import binascii
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SENSITIVE_PATTERNS = (
    (
        "absolute macOS user path",
        re.compile(b"/" + b"Users" + b"/" + rb"[^/\s]+/"),
    ),
    (
        "private source-repository reference",
        re.compile(b"ble-keychain" + b"-vscode"),
    ),
    (
        "personal email address",
        re.compile(b"paulscalise" + b"@" + b"icloud\\.com"),
    ),
    (
        "PEM private-key material",
        re.compile(b"-----BEGIN " + rb"[A-Z0-9 ]*" + b"PRIVATE KEY-----"),
    ),
    (
        "GitHub token",
        re.compile(b"github_" + rb"pat_[A-Za-z0-9_]{20,}"),
    ),
    (
        "GitHub classic token",
        re.compile(b"gh" + rb"[pousr]_[A-Za-z0-9]{30,}"),
    ),
    (
        "AWS access key",
        re.compile(b"AK" + rb"IA[0-9A-Z]{16}"),
    ),
    (
        "assigned secret-key value",
        re.compile(b"SECRET" + rb"[_-]?KEY\s*="),
    ),
)


def tracked_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [
        ROOT / raw_path.decode("utf-8")
        for raw_path in result.stdout.split(b"\0")
        if raw_path
    ]


def main() -> int:
    errors: list[str] = []

    try:
        repository_paths = tracked_paths()
    except (OSError, UnicodeError, subprocess.CalledProcessError) as error:
        print(f"error: unable to list tracked files: {error}", file=sys.stderr)
        return 1

    for path in (path for path in repository_paths if path.suffix == ".json"):
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            errors.append(f"{path.relative_to(ROOT)}: {error}")

    for channel_name in ("stable", "beta"):
        path = ROOT / "channels" / f"{channel_name}.json"
        try:
            channel = json.loads(path.read_text(encoding="utf-8"))
            if channel.get("schemaVersion") != 1:
                errors.append(f"{path.relative_to(ROOT)}: unsupported schemaVersion")
            if channel.get("channel") != channel_name:
                errors.append(f"{path.relative_to(ROOT)}: channel name does not match file")
            release = channel.get("release")
            if release is not None:
                required = {
                    "releaseID",
                    "version",
                    "buildNumber",
                    "manifestURL",
                    "signatureURL",
                }
                missing = required.difference(release)
                if missing:
                    errors.append(
                        f"{path.relative_to(ROOT)}: missing release fields "
                        + ", ".join(sorted(missing))
                    )
                for key in ("manifestURL", "signatureURL"):
                    if not str(release.get(key, "")).startswith("https://"):
                        errors.append(f"{path.relative_to(ROOT)}: {key} must use HTTPS")
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            errors.append(f"{path.relative_to(ROOT)}: {error}")

    keyring_path = ROOT / "keys" / "keyring.json"
    try:
        keyring = json.loads(keyring_path.read_text(encoding="utf-8"))
        if keyring.get("schemaVersion") != 1:
            errors.append("keys/keyring.json: unsupported schemaVersion")

        seen_key_ids: set[str] = set()
        active_key_count = 0
        for key in keyring.get("keys", []):
            key_id = key.get("keyID")
            if not isinstance(key_id, str) or not key_id:
                errors.append("keys/keyring.json: keyID is missing")
                continue
            if key_id in seen_key_ids:
                errors.append(f"keys/keyring.json: duplicate key ID {key_id}")
            seen_key_ids.add(key_id)

            if key.get("algorithm") != "Ed25519":
                errors.append(f"keys/keyring.json: {key_id} must use Ed25519")
            if key.get("status") == "active":
                active_key_count += 1

            public_key_file = key.get("publicKeyFile")
            if not isinstance(public_key_file, str):
                errors.append(f"keys/keyring.json: {key_id} has no publicKeyFile")
                continue
            public_key_path = ROOT / "keys" / public_key_file
            try:
                encoded_key = public_key_path.read_text(encoding="utf-8").strip()
                raw_key = base64.b64decode(encoded_key, validate=True)
                if len(raw_key) != 32:
                    errors.append(
                        f"{public_key_path.relative_to(ROOT)}: "
                        "Ed25519 public key must be 32 bytes"
                    )
            except (OSError, UnicodeError, binascii.Error) as error:
                errors.append(f"{public_key_path.relative_to(ROOT)}: {error}")

        if active_key_count != 1:
            errors.append("keys/keyring.json: exactly one signing key must be active")
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        errors.append(f"keys/keyring.json: {error}")

    for path in repository_paths:
        lowered = path.name.lower()
        if lowered.endswith(".hex"):
            errors.append(
                f"{path.relative_to(ROOT)}: firmware belongs in GitHub Release assets"
            )
        if "factory" in lowered and lowered.endswith((".hex", ".bin")):
            errors.append(f"{path.relative_to(ROOT)}: factory image must not be distributed")
        if (
            lowered.endswith((".pem", ".key", ".p8", ".p12", ".pfx", ".jks", ".keystore"))
            or "private-key" in lowered
            or "private_key" in lowered
            or "secret-key" in lowered
            or "secret_key" in lowered
            or lowered == ".env"
            or lowered.startswith(".env.")
        ):
            errors.append(f"{path.relative_to(ROOT)}: possible private signing key")
        if lowered.endswith(".b64") and not lowered.endswith("-public-key.b64"):
            errors.append(f"{path.relative_to(ROOT)}: unrecognized Base64 key material")

        try:
            content = path.read_bytes()
        except OSError as error:
            errors.append(f"{path.relative_to(ROOT)}: {error}")
            continue
        for description, pattern in SENSITIVE_PATTERNS:
            if pattern.search(content):
                errors.append(f"{path.relative_to(ROOT)}: possible {description}")

    if errors:
        print("\n".join(f"error: {error}" for error in errors), file=sys.stderr)
        return 1

    print("Distribution metadata checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
