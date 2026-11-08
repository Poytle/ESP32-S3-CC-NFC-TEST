# ESP32-S3 NFC / PKI Lab

An entirely local ESP32-S3 / PN532 feasibility demo. Tap a card to read public EMV data, stream it to a web dashboard, and request a card signature when DDA is supported. No cloud or payment processor is involved.

## Hardware

| ESP32-S3 | PN532 |
| --- | --- |
| GPIO35 | SDA |
| GPIO36 | SCL |
| GND | GND |
| Module-appropriate supply | VCC |

Set the PN532 switches/jumpers to **I2C**, address `0x24`, then power-cycle. Use 3.3 V logic and pull-ups to 3.3 V. IRQ/reset are not required. Some ESP32-S3 memory variants reserve GPIO35/36; check that these pins are available on your module.

The build uses `esp32-s3-devkitc-1` with **4 MB flash** and a 4 MB `default.csv` partition override, without PSRAM. This overrides the board definition's stock 8 MB assumption.

## Build and flash

Requires Python 3.12, a C++ compiler for host tests, and Node.js 20+ for UI tests:

```sh
python -m pip install platformio==6.1.18 esptool==4.8.1
python scripts/test_tlv.py
node --test tests/ui.test.cjs
pio run
pio run -t upload --upload-port /dev/YOUR_PORT
pio device monitor --baud 115200
```

Join **ESP32-NFC-Lab** (open WiFi, no password), then open **http://192.168.4.1**. Internet access and a filesystem upload are not needed. HTML and JavaScript are embedded into the application image.

Package a merged image after compiling:

```sh
python scripts/package.py
python -m esptool --chip esp32s3 --port /dev/YOUR_PORT write_flash 0x0 firmware/merged.bin
```

The merged image includes bootloader `0x0`, partitions `0x8000`, Arduino boot selector `0xe000`, and application `0x10000`. Packaging rejects incorrect flash-size headers and partitions extending past 4 MB. Flashing replaces existing firmware. If a reboot loop prevents connection, hold BOOT, tap RESET, then release BOOT to enter the ROM downloader.

## Tap and push workflow

1. Firmware polls the PN532 approximately every 500 ms while idle. A newly detected UID starts inspection. Holding the same card in place does not repeatedly scan/sign; remove it for two absent polls and tap again. **Scan again** forces another scan.
2. SELECT PPSE (`2PAY.SYS.DDF01`), select the first advertised payment application, send zero-amount GET PROCESSING OPTIONS, then read up to 32 AFL records.
3. Push the initial scan to connected clients over **WebSocket port 81** (`ws://192.168.4.1:81/`). No browser polling is used for card data.
4. For Visa applications, collect fDDA signature data requested during GPO. For other applications, after completed inspection check the AIP DDA bit and send **INTERNAL AUTHENTICATE** with a fresh challenge when the DDOL is supported.
5. Push the signing status, challenge, APDU status words and signature bytes as an update to the same card row.

Keep the card on the reader until signing completes. Unsupported DDA, unsupported DDOL, card rejection, partial inspection and transport failure are explicit outcomes. A signature supplied during inspection (for example, fDDA during GPO) is displayed with its source command; when present, it is used as the signing result and no separate INTERNAL AUTHENTICATE is requested.

The synchronous NFC driver can pause HTTP handling while a command completes. WebSocket clients are serviced between APDUs. The firmware retries reader initialization every five seconds after a transport error.

## Card list and data

Rows use the **full PAN** decoded from `5A` or `57`; two PANs sharing the same last four digits remain separate. When no PAN is available, UID is the explicit fallback. Changing a UID does not create another row when the PAN stays the same. PANs are displayed in full as requested. Different physical cards/wallet tokens may present different PANs; PAN/UID matching is not proof of identity or authenticity.

Each row includes application, tap count, scan status and signing status. Expand **Fields & signing** for every returned primitive TLV (known and unknown tags), hex bytes, printable text where applicable, challenge, signature and APDU results. This includes publicly returned PAN, track data, expiry, labels, capability fields and certificates when present. Constructed TLVs are traversed, rather than duplicated as whole raw blobs.

The device retains four distinct cards in RAM for reconnects, replacing older slots. Tap counts cover the retained device entry. A browser tab holds up to 32 rows. No browser storage, flash database, or serial card-data log is used. **Clear cards** clears the device history and all connected UIs. Data, including full PANs, is visible to clients of the open local network.

Per scan, at most 128 unique primitive tag/value pairs and 8 KB of hex values are retained; truncation is indicated in the UI. Other limits: ISO14443A only, first payment app only, short APDUs, 120 PDOL bytes, 32 AFL records and bounded TLV nesting. PN532 response chaining is collected up to eight fragments / 1024 bytes. No APDU GET RESPONSE / `6C` retry or scheme-specific contactless kernel is implemented. A nonpayment tag shows its UID and an unavailable-directory result.

## Signing and verification

The standalone signing path for non-Visa applications sends `00 88 00 00 Lc <DDOL input> 00` only when a completed scan advertises DDA. It supports card DDOL `9F3704` (a four-byte unpredictable number). If the card omits DDOL, the terminal default `9F3704` is used. Unknown/malformed DDOLs are reported as unsupported; no signing command is sent. Responses in template `80` or signed dynamic application data `9F4B` are displayed.

**Receiving a signature is not verifying it.** Real EMV RSA issuer/ICC certificate recovery, scheme CAPK provisioning, offline record hashes and signature validation are not implemented. DDA support in AIP does not guarantee that a contactless application will accept INTERNAL AUTHENTICATE. fDDA/CDA and issuer authorization are not implemented. This demo must not authorize real entry based on these results.

The separate **synthetic PKI demonstration** retains the original on-device ECDSA P-256 / SHA-256 workflow: root signs issuer public key, issuer signs demo-card public key, demo-card signs a fresh challenge; both chain links and the signature are verified, and modified/fresh challenges reject the original signature. Keys are regenerated at boot. These simple endorsements are not EMV/X.509 certificates and do not involve the tapped card.

No GENERATE AC, PIN attempts, protected-file access, card writes or payment authorization are issued. GPO and signing requests may change internal card state/counters.

## WebSocket events

The server sends JSON `{ "type": "card", "card": { ... } }` for initial scans and signing updates, using the same `scanId` for both. A repeated tap gets a new scan ID. Events include `key`, `pan` (when available), `uid`, `taps`, `fields`, `steps`, `signingStatus`, and available signing data. `reader` events report reader health; `clear` clears history. A new socket connection receives reader health and each retained card. The browser reconnects automatically, ignores older scan versions of a known card, and resets its list when the reader reports a new boot ID.

HTTP endpoints remain: `GET /`, `GET /api/state` (latest scan diagnostics), `POST /api/scan`, `POST /api/clear`, `POST /api/demo` (synthetic demo).

## CI and releases

Git is initialized on `master`. The GitHub Actions workflow tests and builds master pushes, PRs targeting master, `v*` tags, published releases and manual dispatches. It uploads Actions artifacts and attaches the merged image, individual images, ELF, flash layout, README and SHA256 checksums to releases. A `v*` tag creates a release if needed. Release uploads require repository contents write permission.

Once `origin` is configured and the changes are committed:

```sh
git push -u origin master
git tag v0.1.0
git push origin v0.1.0
```

## Validation and troubleshooting

Host tests cover TLV boundaries, malformed lengths, PAN extraction/padding, DDOL challenge construction, PN532 short/extended frames, transient readiness failures, full-frame read recovery, persistent failures, chained responses, NAD stripping, RF error codes and response limits. UI tests cover PAN deduplication, signing updates to an existing row, equal last-four collisions, stale updates, UID fallback and bounded lists. Firmware compilation and artifact validation do not replace physical hardware tests.

On hardware, connect two dashboard tabs, tap one supported card, confirm both receive one row before the signing result, remove and retap it, and confirm the same row's count increments. Verify unsupported signing statuses, reconnect snapshots, and clear propagation. Keep the card present until completion.

- `Detected size(4096k) ... header(8192k)`: flash the complete rebuilt 4 MB merged image, including bootloader/partitions. Uploading only the application leaves the old bootloader in place.
- `Wire.cpp ... i2cRead returned Error -1`: bus read failed; inspect `readerError`. Check I2C mode, wiring, module power, pull-ups and pin availability. Power-cycle after mode changes. A PN532 must ACK at `0x24`; card presence is not needed for initialization.

The driver reads a response header, requests PN532 NACK retransmission, then reads the exact frame length, rather than clocking a fixed oversized response. It tolerates up to two transient address/read failures during readiness polling, then stops after the third. A failed response-frame read is retried once using PN532 NACK retransmission, which fetches the saved response without executing the card command again.

## References

- [NXP PN532 user manual](https://www.nxp.com/docs/en/user-guide/141520.pdf)
- [ESPHome PN532 I2C transport](https://github.com/esphome/esphome/blob/dev/esphome/components/pn532_i2c/pn532_i2c.cpp)
- [Arduino WebSockets](https://github.com/Links2004/arduinoWebSockets)
- [EMVCo specifications](https://www.emvco.com/specifications/) — Books 2 and 3 describe dynamic authentication and the application protocol.

### Interrupted inspection diagnostics

An interrupted record read now reports `READ RECORD SFI=<n> record=<n>` with the failure reason. Expand APDU results for `transportPhase`, `i2cReadRequested`, `i2cReadReceived`, and `pn532Status` when available. Partial public fields remain visible; signing is skipped after incomplete inspection.

A reported read failure after earlier `9000` results indicates a host-side read/transport failure, not an APDU rejection. Readiness polling tolerates short address-NACK windows documented by NXP. A failed full response read gets one saved-frame retransmission attempt. Remaining failures are reported rather than restarting the whole payment-card sequence. The Arduino I2C layer can still print a low-level error for an attempt that the driver subsequently recovers.

The driver also handles the PN532 status MI bit as a continuation indication rather than an error, collecting the remaining response with an empty InDataExchange request. PN532 RF errors retain their numeric status and a decoded explanation. These recovery paths are host-tested; the exact cause of an intermittent physical I2C failure still requires the new diagnostics and hardware verification.

### Fixed: requested 270 bytes, received 14

Arduino-ESP32 2.x has legacy two-argument `Wire.requestFrom` overloads returning `uint8_t`. The driver selected one of these: the actual read could succeed with all 270 bytes buffered, while the return count wrapped to 14 (`270 % 256`). The driver then incorrectly rejected and discarded the successful read.

The driver now explicitly calls `requestFrom(uint16_t address, size_t length, bool stop)`, which returns `size_t`. The host Wire stub mirrors the real overloads, and regression tests reproduce the old 270-to-14 behavior and validate reads across the 255/256 boundary and the exact 270-byte frame. Retry logic alone cannot correct an 8-bit return-value truncation.

### Contactless signing results

The AIP DDA bit does not guarantee that a contactless application accepts standalone INTERNAL AUTHENTICATE. Visa fDDA generates its signature during GPO, as described in [Visa TADG section 5.2.5](https://usa.visa.com/content/dam/VCOM/regional/na/us/partner-with-us/documents/transaction-acceptance-device-guide.pdf). The Visa capture profile described below requests fDDA, but full scheme-specific kernel processing and verification are not implemented. If inspection already returns signed dynamic data, the UI reports that result and source without issuing an extra DDA request.

When standalone signing is attempted, its response is shown directly in the row and retained in `signingResponse`. Rejections show the status word and explanation, while transport failures show the transport detail. No standalone DDA advertised does not mean the card has no authentication capability; other modes may require a different protocol.

### Visa `6A81` and the fDDA capture profile

`6A81` on INTERNAL AUTHENTICATE means the requested function is unsupported. Visa contactless fDDA generates its signature as part of GPO, so the firmware now selects that capture path for the Visa RID `A000000003`. It no longer sends standalone INTERNAL AUTHENTICATE to Visa applications.

When the card requests four-byte TTQ (`9F66`) in its PDOL, the experimental Visa capture profile supplies `27800000`: the existing qVSDC flags plus ODA-for-online and online-cryptogram-required. GPO also supplies a fresh unpredictable number, zero amount and configured currency where requested by the PDOL. The sent PDOL values are exposed as `terminalData`; `fddaRequested`, `terminalTtq` and `signingMethod` explain the chosen path. The returned `9F4B` and its source command are displayed without cryptographic verification. No signature returned is reported explicitly, rather than inferred as a successful authentication.

This profile deliberately prompts signature generation for a protocol capture experiment. It does not implement the capabilities of a compliant fDDA verifier. GPO can generate local payment cryptograms and update counters; nothing is sent to an issuer, processor or network. Full EMV certificate recovery, trust-chain checks and signature validation remain unimplemented.

References: [Visa TADG section 5.2.5](https://usa.visa.com/content/dam/VCOM/regional/na/us/partner-with-us/documents/transaction-acceptance-device-guide.pdf) describes GPO-based fDDA; [RFUID's EMV implementation](https://github.com/marksteward/RFUID/blob/master/emv.py) documents the TTQ flag layout used for this experimental capture profile.
