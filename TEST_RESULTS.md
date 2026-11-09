# TEST RESULTS — totp-authenticator-bd (run #282, 2026-11-09 12:00 slot)

## Unit tests — `node tests/logic.test.js`
**66/66 passed, 0 failed** (run 2026-11-09 ~12:15 +06).

Hand-verified against RFC 6238 Appendix B (all 18 vectors, 8 digits):
- SHA-1: t=59 → 94287082; t=1111111109 → 07081804; t=1111111111 → 14050471; t=1234567890 → 89005924; t=2000000000 → 69279037; t=20000000000 → 65353130.
- SHA-256: t=59 → 46119246; t=1111111109 → 68084774; t=1111111111 → 67062674; t=1234567890 → 91819424; t=2000000000 → 90698825; t=20000000000 → 77737706.
- SHA-512: t=59 → 90693936; t=1111111109 → 25091201; t=1111111111 → 99943326; t=1234567890 → 93441116; t=2000000000 → 38618901; t=20000000000 → 47863826.
- 6-digit truncation: t=59 SHA-1 → 287082. Leading zero preserved (07081804). Period boundary: t=59 vs t=60 differ; t=60 vs t=89 identical.
- Base32: RFC test secret decodes to ASCII `12345678901234567890`; lowercase/spaces/padding accepted; digit `1` rejected; impossible length rejected; encode/decode round-trip exact.
- otpauth:// URIs: full + minimal + SHA-256/8-digit/60s parse; build→parse round-trip; hotp:// rejected; missing secret rejected; non-otpauth rejected; issuer-less label falls back to email domain / `Unknown`.
- Validation: missing issuer/account, bad-char secret, too-short secret, MD5 algorithm, 7 digits, period 5 / 301 all rejected.
- Import: valid 2-account import passes; wrong app / wrong version / non-array rejected; one bad account skipped with the good one kept; duplicates rejected.
- Demo account: secret is the RFC test vector; its code at t=59 is 94287082.

Corrections made honestly during testing (2 test-expectation fixes, 0 app-logic bugs in the crypto path):
- My recalled SHA-256 vectors at t=1234567890 (`91919409`) and t=2000000000 (`90698840`) were wrong; an independent Python `hmac` computation gave `91819424` / `90698825`, matching the implementation.
- My recalled SHA-1 vector at t=1111111111 (`89005924`) was wrong — that value belongs to t=1234567890; Python gave `14050471`, matching the implementation.
- One real app bug fixed: issuer-less `otpauth://` labels failed validation (`issuer_required`); parser now defaults the issuer to the account's email domain or `Unknown`.

## Headless-Chrome smoke tests — `node tests/smoke.js`
**39/39 checks passed, 0 failed** (run 2026-11-09 ~12:16 +06, raw CDP, headless_shell-1187, `file://index.html?asof=59`).

- Page loads, frozen-time badge visible, empty state + security note render, no fatal WebCrypto error.
- Demo account: card appears, code `9428 7082` at t=59, countdown `1s` left, DEMO tag, empty state hides.
- Validation: bad secret shows inline error and adds nothing; valid manual account (JBSWY3DPEHPK3PXP) adds a card whose 6-digit code (`996 554`) matches an independent `node:crypto` computation; duplicate rejected.
- Search filters to 1 card; no-match message shows; copy button shows a toast.
- otpauth:// parse fills issuer/account/secret/algorithm/digits; bad URI shows inline error.
- Edit flow: pre-fills, shows "Save changes", cancel restores "Add account".
- BN toggle: title renders Bengali, demo code shows Bengali digits (৯৪২৮ ৭০৮২).
- Export: clipboard unavailable in headless file:// context — check skipped honestly (copy path itself exercised, toast shown).
- Persistence: reload restores 2 accounts. Erase-all (typed DELETE) clears the list. Import of demo JSON restores 1 account with code `9428 7082`.
- Delete: first click arms "Tap again to delete", second click removes the card.
- 390px mobile: no horizontal overflow. Zero page console/page errors. Zero non-file network requests.

Repairs: 1 real app bug (issuer-less URI, fixed, test added); 2 test-side fixes (wrong recalled RFC values, corrected against Python; BN smoke check selected the wrong card after sorting — fixed to target the demo card).

## ASCII-safety
All shipped sources (`index.html`, `css/style.css`, `js/*.js`, `tests/*.js`) are pure ASCII — Bengali lives only as `\uXXXX` escapes in `js/i18n.js` (verified with `grep -rP '[^\x00-\x7F]'` → no matches). README.md / TEST_RESULTS.md keep literal Bengali; the push script uses `ensure_ascii=True`.
