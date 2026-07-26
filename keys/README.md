# Firmware verification keys

This directory contains public Ed25519 verification keys. Public keys are not
secret and are intentionally tracked so clients can pin approved signing
identities.

`keyring.json` maps manifest key IDs to public-key files and records whether
each identity is active or retired. Private keys, seeds, credentials, and
recovery copies must never be committed or attached to a release.
