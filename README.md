# Glyphchain Firmware Releases

Official public distribution metadata and release assets for Glyphchain device
firmware. Firmware source code, credentials, and private signing material are
not part of this repository.

## Release assets

Each published firmware release contains:

```text
Glyphchain-Firmware.hex
glyphchain-g1-vX.Y.Z.manifest.json
glyphchain-g1-vX.Y.Z.manifest.sig
glyphchain-g1-vX.Y.Z.sha256
Glyphchain-OTA-Factory.hex
glyphchain-g1-vX.Y.Z.recovery.json
glyphchain-g1-vX.Y.Z.recovery.sig
```

`Glyphchain-Firmware.hex` contains only the application region accepted by the
device's BLE update protocol.

`Glyphchain-OTA-Factory.hex` is the complete recovery image (bootstrap,
application, IAP, BLE library, and built-in frames). It is flashed over USB
through the chip's ROM bootloader by the recovery page at
<https://pvs64.com/glyphchain/recover>, and is never sent over BLE. Its own
signed manifest, `*.recovery.json`, is distinct from the application manifest.

## Authenticity

Every release manifest is signed with Ed25519. The application manifest binds
the firmware version, target model and hardware revision, OTA protocol version,
application limits, decoded image length, CRC32, and SHA-256 digest. The
recovery manifest binds the version, model, hardware revision, chip, and the
factory image's SHA-256 digest, and is marked `"kind": "glyphchain-recovery"`
so it cannot be mistaken for an application manifest.

Trusted public keys and their lifecycle state are published in `keys/`. Clients
must pin an approved public key and verify the detached manifest signature
before accepting a downloaded firmware image. A checksum file by itself is not
an authenticity guarantee.

## Channels

`channels/stable.json` and `channels/beta.json` identify the current release for
each update channel. `channels/recovery.json` identifies the recovery image used
by the USB recovery page. A `null` release means that nothing has been promoted
to that channel.

## License

Copyright © 2026 Paul Scalise. All rights reserved.

Lawful Glyphchain device owners may inspect, modify, and install firmware on
devices they own or are authorized to control. See the
[Glyphchain Device Owner Firmware License](LICENSE) for the complete terms.
