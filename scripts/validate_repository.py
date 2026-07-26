#!/usr/bin/env python3
"""Perform dependency-free safety checks on distribution metadata."""

from __future__ import annotations

import base64
import binascii
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    errors: list[str] = []

    for path in ROOT.rglob("*.json"):
        if ".git" in path.parts or "dist" in path.parts:
            continue
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

    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "dist" in path.parts:
            continue
        lowered = path.name.lower()
        if lowered.endswith(".hex"):
            errors.append(
                f"{path.relative_to(ROOT)}: firmware belongs in GitHub Release assets"
            )
        if "factory" in lowered and lowered.endswith((".hex", ".bin")):
            errors.append(f"{path.relative_to(ROOT)}: factory image must not be distributed")
        if lowered.endswith((".pem", ".key", ".p8")) or "private-key" in lowered:
            errors.append(f"{path.relative_to(ROOT)}: possible private signing key")

    if errors:
        print("\n".join(f"error: {error}" for error in errors), file=sys.stderr)
        return 1

    print("Distribution metadata checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
