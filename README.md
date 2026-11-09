# ESP32-S3 NFC public-key enrollment and retap verification

A local feasibility demo: recover an EMV card's RSA public key, explicitly enroll it after a verified dynamic signature, then verify fresh signatures against that saved key on retaps. All NFC, RSA recovery, hashing, verification, storage and web hosting run on the ESP32. PAN selects the enrollment; it never authenticates a tap.

## Use it

1. Flash the image below, join **ESP32-NFC-Lab** (open WiFi, no password), and open **https://192.168.4.1:433**. Port 80 redirects to this address.
2. Run **RSA verifier self-test**. It exercises the actual ESP32 verifier with synthetic public-only RSA fixtures, including rejection cases.
3. Tap a card. If not already enrolled, its row shows the required **CAPK RID and index**.
4. Obtain the matching scheme CA public key through a source you trust. Import its public modulus/exponent in the CAPK form. There are no bundled production scheme keys, and the firmware does not download keys.
5. Retap. The ESP recovers the issuer key and ICC key, checks certificate hashes and PAN bindings, then verifies the dynamic signature against the current challenge. The row exposes the recovered RSA modulus, exponent and SHA-256 fingerprint.
6. Press **Enroll public key** after signature verification succeeds. Remove the card and retap: **RETAP VERIFIED** requires a fresh valid signature under the enrolled key. Changing the key under the same PAN does not silently replace enrollment.

Example CAPK schema (placeholders are not usable keys):

```json
{
  "rid": "A000000003",
  "index": "HEX_CA_INDEX_FROM_CARD",
  "modulus": "HEX_PUBLIC_RSA_MODULUS_FROM_CAPK_SOURCE",
  "exponent": "03"
}
```

RID is five bytes (10 hex characters), index one byte (two hex characters); modulus is 64–256 bytes, exponent `03` or `010001`. One CAPK configuration is retained; it can be replaced to enroll a card under a different root. Existing enrolled keys do not depend on keeping that CAPK configured for retaps.

## Hardware

| ESP32-S3 | PN532 |
| --- | --- |
| GPIO35 | SDA |
| GPIO36 | SCL |
| GND | GND |
| Module-appropriate supply | VCC |

Select PN532 **I2C mode**, then power-cycle. Address is `0x24`. Use 3.3 V logic/pull-ups and verify supply requirements for your module. IRQ/reset wires are not needed. Some ESP32-S3 memory variants reserve GPIO35/36; verify those pins are available.

The project uses `esp32-s3-devkitc-1` with explicit **4 MB flash** and a 4 MB `default.csv` partition override, without PSRAM. This overrides the board definition's stock 8 MB assumption.

## Build and flash

Requires Python 3.12, a host C++ compiler and OpenSSL development headers for crypto tests, and Node.js 20+ for UI tests. On macOS, the host crypto test discovers Homebrew OpenSSL 3 automatically. Linux CI uses system OpenSSL development libraries.

```sh
python -m pip install platformio==6.1.18 esptool==4.8.1
python scripts/test_tlv.py
python scripts/test_pki.py
node --test tests/ui.test.cjs
pio run
pio run -t upload --upload-port /dev/YOUR_PORT
```

Or package and flash the complete image:

```sh
python scripts/package.py
python -m esptool --chip esp32s3 --port /dev/YOUR_PORT write_flash 0x0 firmware/merged.bin
```

Image layout: bootloader `0x0`, partitions `0x8000`, Arduino boot selector `0xe000`, application `0x10000`. Packaging rejects incorrect flash-size headers and partitions beyond 4 MB. Flashing replaces existing firmware. Hold BOOT, tap RESET, release BOOT if you need the ROM downloader during a boot loop. The UI is embedded; no filesystem upload is needed.

## Verification implemented

- Raw RSA public operations using mbedTLS on ESP32. This is EMV recovered-message verification, not PKCS#1 v1.5/PSS verification.
- SHA-1 EMV issuer (`90`, `92`, `9F32`) and ICC (`9F46`, `9F48`, `9F47`) certificate recovery. Checks include formats, algorithms, lengths, key padding, PAN/issuer prefix binding and certificate hashes.
- Offline static authentication input assembled from AFL-designated records. For SFI 1–10, exclude record template `70` and length; for SFI 11–30, include the whole record. Append AIP for static tag list `9F4A=82`. Unsupported tag lists and missing required records fail recovery.
- DDA signed dynamic data verification using the current four-byte terminal challenge. DDOL `9F3704` or the terminal default is supported.
- Visa fDDA v1 verification binds the GPO unpredictable number, amount, currency and Card Authentication Related Data (`9F69`, version 01). Missing/unsupported inputs fail explicitly. Visa GPO uses an experimental TTQ `27800000` capture profile and does not send standalone INTERNAL AUTHENTICATE.
- Signature format, dynamic-data bounds, padding and full hash comparison. An old signature does not verify under a different challenge; wrong enrolled keys fail.
- Explicit enrollment after initial successful certificate-hash recovery and fresh signature verification. Eight public keys maximum, saved in NVS. Enrollment is selected by SHA-256 of AID and PAN, and stores public key, fingerprint and AID. The digest is a lookup identifier, not a claim that PAN cannot be guessed.

Unenrolled cards require certificate recovery. Enrolled retaps verify with the saved key directly. `signatureVerified` records the cryptographic result; `retapVerified` is true only when that result is valid **and** the key was already enrolled. `chainTrusted` stays false because full bank trust policy is not implemented.

## Scope and limits

This verifies **continuity of the enrolled private key**, not bank approval, cardholder identity or absence of a live relay. CAPK provenance, certificate date/expiry policy and revocation are not validated. Certificate expiry encoding is checked but expiry dates are not enforced. Matching certificate hashes under a user-provided root is separate from trusting that root. Do not use this open-admin lab firmware as a deployed door controller.

Supported cards must expose certificates at enrollment and return a supported dynamic signature. An online-only card or a card requiring CDA, XDA, ECC or another scheme-specific flow may remain unsupported. RSA moduli up to 256 bytes, exponents 3/65537 and SHA-1 EMV formats are supported; legacy fDDA variants without required version-01 inputs are rejected.

No GENERATE AC, PIN attempt, protected-file access or card write is issued. GPO/signature requests can generate local payment cryptograms and change card state/counters; nothing is submitted to a bank or processor.

The access point has no password as requested. HTTPS encrypts UI/API traffic, and WSS carries scan updates on the same TLS origin. Connected clients can still open the UI and change configuration/enrollment; admin authentication is not implemented.

## Reader and dashboard

Idle polling is about every 500 ms. A new UID starts SELECT PPSE, selects the first payment application, sends zero-amount GPO and reads up to 32 AFL records. Hold the card until proof verification finishes. Holding the same card does not repeatedly sign; remove for two absent polls and tap again. **Scan again** forces another scan.

The initial scan is pushed over WSS on HTTPS port 433 (`/ws`), followed by signing and verification updates. Rows are deduplicated by full PAN with UID fallback. All returned primitive EMV fields are available as hex/printable text, including full PANs as requested. One scan retains up to 128 tag/value pairs and 8 KB of hex values with an explicit truncation indicator.

Four scans are retained in device RAM for reconnects; a tab holds up to 32. No browser storage is used. **Clear cards** clears scan history only. Enrollment and the configured CAPK persist in NVS across reboots; use **Forget enrollment** to remove a saved key. Replacing a CAPK does not replace existing enrolled keys.

Other bounds: ISO14443A only, first AID only, 120 PDOL bytes, eight PN532 response fragments / 1024 APDU response bytes, 8 KB offline record data, bounded TLV recursion. GET RESPONSE / `6C` retry and complete scheme kernels are not implemented.

## API and events

HTTPS on port 433: `GET /`, `GET /api/state`, `POST /api/scan`, `POST /api/clear`.

PKI: `GET /api/pki`, `POST /api/pki/capk` (CAPK JSON), `POST /api/pki/enroll` (`id`, `scanId`), `POST /api/pki/forget` (`id`), `POST /api/pki/selftest`.

WebSocket messages use `{ "type": "card", "card": { ... } }` for scans/proofs. `reader` reports health and boot ID; `pki` reports public configuration/enrollment; `clear` clears history. Connection restores health, configuration and retained cards. The browser ignores older scan IDs and clears its scan list when boot ID changes.

The older `POST /api/demo` ECDSA demonstration remains separate and cannot enroll/authenticate real cards.

## Validation and CI

`test_pki.py` runs the same verification core against public-only synthetic RSA fixtures using host OpenSSL. Positive tests recover both certificate keys and verify DDA/fDDA. Negative tests reject wrong keys, changed challenges/amounts/card data, modified signatures, invalid padding, wrong static hashes, PAN mismatch, missing remainders and out-of-range signatures. The on-device self-test runs those checks through mbedTLS. No physical-card verification success is claimed by host tests.

TLV/PN532 tests cover malformed data, PAN extraction, DDOL construction, extended I2C frames, 270-byte count handling, retries and chaining. Node tests cover PAN deduplication and stale updates. The fixture generator can regenerate synthetic public test data using Python cryptography; ephemeral private keys are never written.

GitHub Actions runs tests/builds on `master` pushes, PRs, `v*` tags, published releases and manual dispatches. It uploads Actions artifacts and attaches merged/individual images, ELF, README, flash layout and checksums to releases. A `v*` tag creates a release if needed. Configure `origin`, commit, then push `master` and a version tag to run it.

Hardware acceptance: run RSA self-test; import a matching CAPK; enroll your supported card after proof succeeds; remove/retap and check `retapVerified=true`; reboot and retap to confirm persistence; test a different card and a same-PAN key change as failures; forget enrollment and confirm it no longer passes as an enrolled retap.

## Troubleshooting

- `Detected size(4096k) ... header(8192k)`: flash the complete rebuilt 4 MB merged image, including bootloader and partitions.
- I2C errors: inspect transport phase, requested/received counts and decoded PN532 status in APDU results. Check power, wiring, mode and pull-ups. The reader must ACK at `0x24`; no card is needed for initialization.
- The former `requested 270, received 14` bug selected an Arduino Wire overload with an 8-bit return count. The driver now explicitly uses the `size_t` overload; regression tests model the actual overloads.
- `6A81` on INTERNAL AUTHENTICATE means the requested function is unsupported. Visa takes the fDDA/GPO path; other cards may require unsupported modes.
- Missing CAPK blocks initial public-key recovery. Missing certificates/static records, or unsupported/missing signature input, are shown separately from cryptographic failures.

## References

- [EMV Book 2, Security and Key Management](https://ptacts.uspto.gov/ptacts/public-informations/petitions/1558054/download-documents?artifactId=MrNZBNn78RF-1VEZWu0XN9m1pt23J5Fz8RKgYXm7ZFtD9ydS6NEEF7w) — certificate recovery, static data and DDA formats.
- [Visa TADG section 5.2.5](https://usa.visa.com/content/dam/VCOM/regional/na/us/partner-with-us/documents/transaction-acceptance-device-guide.pdf) — GPO-based fDDA.
- [NXP PN532 user manual](https://www.nxp.com/docs/en/user-guide/141520.pdf) — host transport and chaining.
- [Proxmark EMV PKI implementation](https://github.com/Proxmark/proxmark3/blob/master/client/emv/emv_pki.c) — reference for EMV hash-input ordering. This project's verifier is independently implemented.
- [RFUID EMV implementation](https://github.com/marksteward/RFUID/blob/master/emv.py) — experimental TTQ capture parameters.

## HTTPS and clipboard debug export

Open **https://192.168.4.1:433**. Port **433** is intentional. Every request on port 80 redirects with HTTP 308 to that HTTPS origin, preserving its path/query. The application and API are served over TLS; scan updates use **wss://192.168.4.1:433/ws**. Port 81 is no longer used. Responses disable browser caching.

The ESP32 generates its own RSA-2048 / SHA-256 self-signed certificate on first startup and saves that certificate and private key in the separate `nfctls` NVS namespace. Generation can take several seconds. The certificate includes the access-point IP as a Subject Alternative Name and remains stable across reboots. Browsers display a self-signed certificate warning until an exception/trust decision is made. Certificate initialization failure is reported on serial; port 80 returns 503 if HTTPS could not start. Existing card enrollments use their separate `nfcpki` namespace.

**Copy full scan data** in a card's Details copies its complete retained scan JSON. **Copy all scan data** copies every scan retained in the tab. The export includes all retained primitive fields, APDU status/errors, signing data, recovered public keys, verification flags, and device build/reader metadata. It includes full PANs. Existing scan capture bounds/truncation indicators apply; clipboard export does not capture additional card data.

Clipboard handling first uses `navigator.clipboard.writeText`, then a browser copy fallback. If browser permissions or certificate treatment block both, a selected read-only JSON text area appears for manual copying. No external service or browser storage is used.

Hardware checks after flashing:

```sh
curl -I http://192.168.4.1/
# Expect 308 and Location: https://192.168.4.1:433/
curl -k https://192.168.4.1:433/api/pki
```

Then load the dashboard, confirm live WSS updates on a tap, copy one/all scans and paste the JSON into an editor. Reboot and confirm the TLS certificate identity remains the same. Large WSS updates are base64-chunked below TLS record limits and reassembled before rendering; HTTP bodies are streamed in bounded writes. Host tests cover full-object export, UTF-8 chunk reassembly, and clipboard success/denial/fallback behavior; the TLS handshake and clipboard behavior on your actual browser still require hardware testing.

TLS uses pinned `esp32_https_server` / compatibility wrapper 1.0.0 with the project's pinned Arduino-ESP32 2.0.17 framework. The project provides the legacy `hwcrypto/sha.h` include path through the framework's ESP32-S3 `sha/sha_dma.h` API. JSON request bodies are cached per handler because the compatibility wrapper otherwise consumes them on first read.

## Visa RID A000000003 / index 09 capture validation

`config/capk-visa-09.json` contains the public reference key for this RID/index, taken from Proxmark3's public CAPK list. Its 248-byte modulus and exponent `03` have the listed EMV SHA-1 checksum `1FF80A40173F52D7D27E0F26A146A1C8CCB29046`. That list gives an expiry of **2022-12-31**; current official scheme validity/provenance has not been established. This reference is for the key-continuity experiment, with `chainTrusted=false`; it is not a claim of current bank trust. The firmware does not automatically install it. Paste its JSON into the CAPK form and press Save CAPK, then retap and explicitly enroll after signature verification succeeds.

A supplied real Visa capture was checked independently with Python integer RSA/SHA-1 operations and with the actual C++ verification core on the host: issuer certificate hash, ICC certificate hash and online fDDA signature all verified; changing the challenge rejected the captured signature. This is validation of that captured proof, not a claim that a new physical retap has already been tested. The capture and PAN are not included in tracked test fixtures.

The capture exposed two verifier assumptions now corrected against Kernel 3: Card Authentication Related Data (`9F69`) can be **5–16 bytes**, including the common seven-byte form; and online fDDA with CID=ARQC requires signed-data format **95**, whereas offline TC/classic DDA use **05**. The expected format is selected from the protocol context, not accepted interchangeably. The full related-data bytes remain in the signature hash, and any returned CTQ is checked against the signed CTQ when present.

Synthetic public-only regression vectors cover seven-byte related data, online format 95, wrong-format rejection, invalid CID/short related data, and changed challenge/transaction data. The on-device RSA self-test includes these cases.
