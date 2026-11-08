# ESP32-S3 NFC / PKI Lab

A self-contained feasibility demo: an ESP32-S3 reads ISO14443A cards using a PN532, hosts a local dashboard, inspects public EMV data, and demonstrates signing and verification using synthetic keys. No cloud, processor, external web assets, or delegated computation.

## Hardware

| ESP32-S3 | PN532 |
| --- | --- |
| GPIO35 | SDA |
| GPIO36 | SCL |
| GND | GND |
| Board-appropriate supply | VCC |

Set the PN532 module switches/jumpers to **I2C** (7-bit address `0x24`). Use 3.3 V logic and pull-ups to 3.3 V; check your module's power specification. IRQ/reset are not required: the driver polls the PN532 I2C status byte. Wiring is configured in `setup()` in `src/main.cpp`.

**Check your ESP32-S3 module:** GPIO35/36 can be occupied by octal flash/PSRAM on some modules. These pins must be available on your exact board. The build uses `esp32-s3-devkitc-1` with explicit **4 MB flash** and `default.csv` (4 MB) partition overrides, with no PSRAM dependency. The stock board definition otherwise assumes 8 MB. Change the board configuration if your flash/USB hardware differs.

## Build and flash

Requires Python 3.12 and PlatformIO Core 6.1.18:

```sh
python -m pip install platformio==6.1.18 esptool==4.8.1
python scripts/test_tlv.py
pio run
pio run -t upload --upload-port /dev/YOUR_PORT
pio device monitor --baud 115200
```

Open the serial monitor and reset the board. It prints the randomly generated WiFi password. Join **ESP32-NFC-Lab**, then open **http://192.168.4.1**. Password and demo keys change on every restart. The board operates as an access point; internet access is not needed. The UI is compiled into firmware, so no filesystem upload is needed.

Hold one card steady and press **Scan card**. Inspection takes several seconds; the synchronous web server may pause while PN532 commands complete. Use **Clear** to discard the last result. There is no scan history or persistent card database. A missing reader can be retried with Scan after correcting wiring.

## Card inspection

The bounded APDU sequence is:

1. ISO14443A discovery: show UID (which can change and is not proof of identity).
2. SELECT `2PAY.SYS.DDF01` and select the first advertised payment AID.
3. Parse PDOL; issue GET PROCESSING OPTIONS with zero amount, a hardware-random unpredictable number, and minimal terminal data.
4. Read at most 32 AFL records. Show application label, masked PAN (last four only), AIP, CA key index, issuer/ICC certificates and any signed dynamic application data encountered.

The UI shows command status words, not raw APDU traces or full PAN/track data. Full responses exist transiently in RAM while parsing and are not logged or persisted. No protected files are accessed, no PIN is attempted, and no GENERATE AC or write commands are sent. **GPO may change a payment card's internal state or counters even with zero amount.** This is inspection, not a guaranteed stateless read operation.

Limits: ISO14443A only, first payment app only, short APDUs, at most 120 PDOL data bytes, 32 records, bounded TLV recursion, no GET RESPONSE/6C retry, no scheme-specific contactless kernel. Unsupported cards and mobile wallets may fail or return limited data. Non-payment ISO14443A tags show their UID and an unavailable-directory status. PAR is deliberately not used as an access identifier; its availability and cross-device stability are not universal.

## Signing demo: what is actually verified

**Run signing & verification** performs real ECDSA P-256 / SHA-256 operations on the ESP32 using mbedTLS:

- Root signs the issuer's public key; verify with root public key.
- Issuer signs the synthetic card's public key; verify with issuer public key.
- Synthetic card signs a fresh 32-byte challenge; verify with card public key.
- Verify that the same signature fails against a changed challenge and a new challenge.

The dashboard exposes public keys, signatures, challenge, and all five pass/fail results. Private keys remain in ESP32 RAM and are regenerated at boot. These simple public-key endorsements illustrate a PKI chain; they are not X.509 or EMV certificates. The freshly generated root is a local demo trust anchor, not a scheme CA. This demonstrates signature mathematics and freshness; a deployed protocol must also track issued challenges and bind them to sessions.

**Live payment-card authentication is not implemented.** Certificate and signature bytes from a real card are explicitly unverified. This project does not recover EMV RSA issuer/ICC public keys, provision/validate scheme CAPKs, build offline-authentication record hashes, request DDA, or implement fDDA/CDA verification. A real card's private key cannot be extracted; the synthetic demo does not use it. Offline authentication would also not establish issuer approval, revocation status, cardholder identity, or resistance to live relay attacks. This firmware must not open an actual door on the basis of a UID, masked PAN, certificate presence, or synthetic demo result.

For a next hardware feasibility step, capture which target cards provide certificates and AIP, then implement one specified contactless kernel and validate it with known cryptographic test vectors and supported test cards. The earlier chat's claim that processor zero-value checks and PAR universally solve entry identification was too broad; this project makes no such assumption.

## CI and release artifacts

The repository starts on `master`. `.github/workflows/firmware.yml` builds master pushes, pull requests to master, `v*` tags, published releases, and manual runs. It runs the host TLV tests, compiles firmware, packages it, and uploads a downloadable Actions artifact. Tag pushes create a GitHub release if needed; published releases attach to their existing release. Both attach the individual images, merged image, ELF, flash layout, README, and SHA256 checksums. The workflow needs repository contents write permission for release uploads.

After creating a GitHub repository and configuring `origin`:

```sh
git push -u origin master
git tag v0.1.0
git push origin v0.1.0
```

Package locally after a build:

```sh
python scripts/package.py
python -m esptool --chip esp32s3 --port /dev/YOUR_PORT write_flash 0x0 firmware/merged.bin
```

Merged image layout: bootloader `0x0`, partitions `0x8000`, Arduino boot selector `0xe000`, application `0x10000`. Flashing can overwrite existing firmware/settings. Individual images can instead be flashed at the offsets in `flash-layout.json`.

## Validation

Host tests exercise the actual TLV parser, including truncation, indefinite length rejection, oversized tags, nested templates and long-form lengths. A successful firmware build checks compilation/linking; hardware verification still requires the physical board, PN532 and cards. On hardware, check reader detection, scan a non-payment tag, scan your own supported payment card, confirm PAN masking, run the PKI demo (all five booleans should be true), clear the result, and reboot to confirm new keys/password.

## References

- [PN532 user manual (NXP)](https://www.nxp.com/docs/en/user-guide/141520.pdf): host framing, I2C status polling, InListPassiveTarget and InDataExchange.
- [Adafruit PN532 implementation](https://github.com/adafruit/Adafruit-PN532): reference for PN532 commands and transport behavior.
- [EMV specifications (EMVCo)](https://www.emvco.com/specifications/): Book 2 security/key management and Book 3 application protocol. The synthetic ECDSA workflow deliberately does not claim EMV conformance.

## Recovery from a flash-size boot loop

`Detected size(4096k) smaller than ... header(8192k)` means an 8 MB image was flashed to a 4 MB chip. This build now explicitly uses 4 MB for the image header and partition table. Reflash the complete rebuilt image (including bootloader and partitions), not just the application binary:

```sh
python -m esptool --chip esp32s3 --port /dev/YOUR_PORT write_flash 0x0 firmware/merged.bin
```

Alternatively use `pio run -t upload --upload-port /dev/YOUR_PORT`, which writes the bootloader and partitions as well. If the board keeps rebooting during connection, hold BOOT, tap RESET, then release BOOT to enter the ROM downloader.

The `do_core_init ... flash_ret == ESP_OK` assertion follows the flash-size probe failure. Correct that mismatch first. If a core-dump warning alone remains after normal boot is restored, stale flash data may need clearing. A full `erase_flash` also removes all saved settings; it is not required as the first recovery step.
