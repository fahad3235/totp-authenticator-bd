# TOTP Authenticator BD

Offline bilingual (EN / বাংলা) TOTP authenticator that runs entirely in your browser. Add a two-factor account with a Base32 secret or an `otpauth://` link and get live 6- or 8-digit codes with a countdown ring — no account, no server, no network requests.

Live demo: https://fahad3235.github.io/totp-authenticator-bd/

## Problem

Two-factor codes usually need a phone app or a server round-trip. This is a zero-install, zero-network alternative: open the page, add your secret, and the codes are computed locally with WebCrypto. Your secrets never leave the device.

## Features

- **Live TOTP codes (RFC 6238)** — SHA-1 / SHA-256 / SHA-512, 6 or 8 digits, 30s or 60s period, countdown ring + seconds remaining, auto-refresh.
- **Add accounts two ways** — manual entry (issuer, account, Base32 secret, algorithm, digits, period) or paste an `otpauth://` link; the link is parsed and the form is pre-filled.
- **Tap-to-copy** — click a code (or its Copy button) to copy it; the copied value is always plain ASCII digits.
- **Search, sort, edit, delete** — accounts sorted by issuer + name; delete needs a second tap to confirm.
- **Show / hide secret** — secrets are masked by default; the `otpauth://` URI for each account is shown for re-import elsewhere.
- **Export / import JSON** — strict validation (wrong app, wrong version, bad account, duplicates all rejected with a message); erase-all needs the word `DELETE`.
- **Demo account** — the RFC 6238 test secret, clearly labelled DEMO, so you can see a live code and verify the math (at Unix time 59 its 8-digit SHA-1 code is `94287082`).
- **Bilingual EN / বাংলা** — full UI toggle, Bengali digits for displayed codes and countdowns, preference persisted.
- **Offline & private** — zero network requests; secrets live only in this browser's `localStorage`.

## Stack

- Static HTML + CSS + vanilla JS (no build step, no dependencies)
- WebCrypto (`crypto.subtle` HMAC) for code generation
- Node.js test harness: `node tests/logic.test.js`, headless-Chrome CDP smoke test `node tests/smoke.js`

## Prerequisites

- Any modern browser (WebCrypto required — Chrome, Firefox, Safari, Edge).
- Node.js 18+ only for running the tests.

## Install & run

No install. Open `index.html` directly in a browser, or serve the folder:

```bash
python3 -m http.server 8000
# open http://localhost:8000
```

## Development

```bash
node tests/logic.test.js   # unit tests (RFC 6238 vectors, Base32, URI parsing, validation)
node tests/smoke.js        # headless-Chrome smoke test (raw CDP, file://, ?asof=59)
```

`?asof=<unix-seconds>` freezes displayed time (test hook — a "TEST MODE — time frozen" badge appears).

## Environment

None. There are no secrets, API keys, or environment variables. Everything runs client-side.

## Testing

- **Unit: 66/66 passed** (`node tests/logic.test.js`) — all 18 RFC 6238 Appendix B vectors (SHA-1/SHA-256/SHA-512 × 6 timestamps), 6-digit truncation, leading-zero preservation, period boundaries, Base32 round-trip and rejection cases, `otpauth://` parse/build, account validation, import validation, demo-account vector. Two recalled vector values were corrected against an independent Python HMAC computation (SHA-256 at t=1234567890 is `91819424`, at t=2000000000 is `90698825`; SHA-1 at t=1111111111 is `14050471`).
- **Smoke: 39/39 passed** (`node tests/smoke.js`, raw CDP, headless_shell-1187, `file://?asof=59`) — 0 console/page errors, zero non-file network requests; demo code `9428 7082` at t=59, manual-account code matches an independent `node:crypto` computation, validation/duplicate/search/URI-parse/edit/BN-toggle/export/persistence/erase/import/delete flows, 390px no-overflow.
- See [TEST_RESULTS.md](TEST_RESULTS.md) for the full report.

## Deployment

Static site — any static host works. GitHub Pages: enable Pages on `main` / root.

## Limitations

- Secrets are stored in the browser's `localStorage` in plain text. Anyone with access to this browser can read them. Use a device lock; do not use on a shared computer. There is no password/PIN lock and no cloud backup — export your JSON and keep it somewhere safe.
- Only TOTP is supported (no HOTP/counter-based codes — `otpauth://hotp/` links are rejected with a clear message).
- The device clock must be correct (NTP-synced); a clock off by 30+ seconds produces codes your service will reject.
- Issuer-less `otpauth://` links get their issuer from the account's email domain, or `Unknown` if there is none.
- QR-code scanning is not included — paste the `otpauth://` link or type the secret instead. (The per-account `otpauth://` URI is shown so you can copy it into another app.)

## Status

Complete MVP. Ships empty (no accounts) except for the optional, clearly-labelled RFC 6238 demo account.
