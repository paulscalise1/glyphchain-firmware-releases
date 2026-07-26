# Glyphchain Firmware Releases

Official public distribution metadata and release assets for Glyphchain device
firmware. Firmware source code, factory-programming images, credentials, and
private signing material are not part of this repository.

## Release assets

Each published firmware release contains:

```text
Glyphchain-Firmware.hex
glyphchain-g1-vX.Y.Z.manifest.json
glyphchain-g1-vX.Y.Z.manifest.sig
glyphchain-g1-vX.Y.Z.sha256
```

`Glyphchain-Firmware.hex` contains only the application region accepted by the
device's BLE update protocol. Factory, bootstrap, IAP, and vendor-library images
are not distributed here.

## Authenticity

Every release manifest is signed with Ed25519. The manifest binds the firmware
version, target model and hardware revision, OTA protocol version, application
limits, decoded image length, CRC32, and SHA-256 digest.

Trusted public keys and their lifecycle state are published in `keys/`. Clients
must pin an approved public key and verify the detached manifest signature
before accepting a downloaded firmware image. A checksum file by itself is not
an authenticity guarantee.

## Channels

`channels/stable.json` and `channels/beta.json` identify the current release for
each update channel. A `null` release means that no public update has been
promoted to that channel.

## License

Copyright © 2026 Paul Scalise. All rights reserved.

Lawful Glyphchain device owners may inspect, modify, and install firmware on
devices they own or are authorized to control. See the
[Glyphchain Device Owner Firmware License](LICENSE) for the complete terms.
