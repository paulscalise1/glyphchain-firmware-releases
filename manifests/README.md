# Release manifests

Every GitHub Release contains:

```text
Glyphchain-Firmware.hex
glyphchain-g1-vX.Y.Z.manifest.json
glyphchain-g1-vX.Y.Z.manifest.sig
glyphchain-g1-vX.Y.Z.sha256
```

The detached `.sig` is an Ed25519 signature over the exact bytes of the
`.manifest.json` file. The manifest contains the SHA-256 and OTA CRC32 of the
firmware, so modifying either the metadata or firmware invalidates validation.

Versioned manifests belong to immutable GitHub Releases. They do not need to be
duplicated on the main branch.
