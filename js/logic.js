/* totp-authenticator-bd \u2014 pure TOTP logic (no DOM, no network).
 * Works in the browser (window.TotpLogic) and in Node (module.exports).
 * HMAC is injected: the app passes a WebCrypto wrapper, the Node tests pass
 * a node:crypto wrapper. That keeps this file dependency-free and lets the
 * RFC 6238 vectors verify the truncation / counter / formatting logic
 * against an independent HMAC implementation.
 */
(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) module.exports = factory();
  else root.TotpLogic = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var ALGORITHMS = ['SHA1', 'SHA256', 'SHA512'];
  var APP_ID = 'totp-authenticator-bd';
  var STORE_VERSION = 1;

  /* ---------------- Base32 (RFC 4648, no padding required on input) -------- */
  var B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function normalizeSecret(input) {
    return String(input || '').toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  }

  function base32Decode(input) {
    var clean = normalizeSecret(input);
    if (!clean) throw new Error('secret_empty');
    if (/[^A-Z2-7]/.test(clean)) throw new Error('secret_bad_chars');
    var bits = 0, value = 0, out = [];
    for (var i = 0; i < clean.length; i++) {
      value = (value << 5) | B32.indexOf(clean[i]);
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    if (bits >= 5) throw new Error('secret_bad_length');
    if (value & ((1 << bits) - 1)) throw new Error('secret_bad_length');
    return new Uint8Array(out);
  }

  function base32Encode(bytes) {
    var out = '', bits = 0, value = 0;
    for (var i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        out += B32[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) out += B32[(value << (5 - bits)) & 31];
    while (out.length % 8 !== 0) out += '=';
    return out;
  }

  /* ---------------- otpauth:// URIs (Google Authenticator key URI format) - */
  function parseOtpauthUri(uri) {
    var raw = String(uri || '').trim();
    var m = raw.match(/^otpauth:\/\/totp\/([^?]+)(?:\?(.*))?$/i);
    if (!m) throw new Error('uri_not_totp');
    var label;
    try { label = decodeURIComponent(m[1]); } catch (e) { throw new Error('uri_bad_label'); }
    var issuer = '', account = label;
    var colon = label.indexOf(':');
    if (colon >= 0) { issuer = label.slice(0, colon); account = label.slice(colon + 1); }
    var q = new URLSearchParams(m[2] || '');
    var secret = q.get('secret') || '';
    var qIssuer = q.get('issuer') || '';
    if (qIssuer) issuer = qIssuer;
    if (!issuer) {
      /* Issuer-less labels are legal; fall back to the account's domain, else 'Unknown'. */
      var at = account.indexOf('@');
      issuer = at >= 0 ? account.slice(at + 1) : 'Unknown';
    }
    var algo = (q.get('algorithm') || 'SHA1').toUpperCase();
    var digits = parseInt(q.get('digits') || '6', 10);
    var period = parseInt(q.get('period') || '30', 10);
    var acct = { issuer: issuer, account: account, secret: secret, algorithm: algo, digits: digits, period: period };
    var v = validateAccount(acct);
    if (!v.ok) throw new Error(v.errors[0]);
    return acct;
  }

  function buildOtpauthUri(a) {
    var label = encodeURIComponent(a.issuer) + ':' + encodeURIComponent(a.account);
    var params = 'secret=' + normalizeSecret(a.secret) +
      '&issuer=' + encodeURIComponent(a.issuer) +
      '&algorithm=' + a.algorithm +
      '&digits=' + a.digits + '&period=' + a.period;
    return 'otpauth://totp/' + label + '?' + params;
  }

  /* ---------------- validation -------------------------------------------- */
  function validateAccount(a) {
    var errors = [];
    if (!a || typeof a !== 'object') return { ok: false, errors: ['account_invalid'] };
    var issuer = String(a.issuer || '').trim();
    var account = String(a.account || '').trim();
    if (!issuer) errors.push('issuer_required');
    else if (issuer.length > 64) errors.push('issuer_too_long');
    if (!account) errors.push('account_required');
    else if (account.length > 128) errors.push('account_too_long');
    var secret = String(a.secret || '');
    if (!normalizeSecret(secret)) errors.push('secret_required');
    else {
      try {
        var bytes = base32Decode(secret);
        if (bytes.length < 10) errors.push('secret_too_short');
        if (bytes.length > 64) errors.push('secret_too_long');
      } catch (e) { errors.push(e.message === 'secret_bad_chars' ? 'secret_bad_chars' : 'secret_invalid'); }
    }
    if (ALGORITHMS.indexOf(String(a.algorithm || 'SHA1').toUpperCase()) < 0) errors.push('algorithm_invalid');
    if (a.digits !== 6 && a.digits !== 8) errors.push('digits_invalid');
    var period = Number(a.period);
    if (!Number.isInteger(period) || period < 10 || period > 300) errors.push('period_invalid');
    return { ok: errors.length === 0, errors: errors };
  }

  function normalizeAccount(a) {
    return {
      id: String(a.id || ''),
      issuer: String(a.issuer || '').trim(),
      account: String(a.account || '').trim(),
      secret: normalizeSecret(a.secret),
      algorithm: String(a.algorithm || 'SHA1').toUpperCase(),
      digits: a.digits === 8 ? 8 : 6,
      period: Number(a.period) || 30,
      demo: !!a.demo,
      createdAt: a.createdAt || 0
    };
  }

  function newId() {
    return 'a' + Date.now().toString(36) + Math.floor(Math.random() * 0xffffff).toString(36);
  }

  /* ---------------- TOTP (RFC 6238) / HOTP (RFC 4226) ---------------------- */
  function counterBytes(counter) {
    var buf = new ArrayBuffer(8);
    var view = new DataView(buf);
    view.setUint32(0, Math.floor(counter / 0x100000000));
    view.setUint32(4, counter >>> 0);
    return new Uint8Array(buf);
  }

  async function hotp(secretBytes, counter, digits, hmacFn, algorithm) {
    var mac = await hmacFn(algorithm, secretBytes, counterBytes(counter));
    var offset = mac[mac.length - 1] & 0x0f;
    var code = ((mac[offset] & 0x7f) << 24) |
      ((mac[offset + 1] & 0xff) << 16) |
      ((mac[offset + 2] & 0xff) << 8) |
      (mac[offset + 3] & 0xff);
    var str = String(code % Math.pow(10, digits));
    while (str.length < digits) str = '0' + str;
    return str;
  }

  async function totpAt(secretBytes, timeSec, opts, hmacFn) {
    var period = (opts && opts.period) || 30;
    var digits = (opts && opts.digits) || 6;
    var algorithm = (opts && opts.algorithm) || 'SHA1';
    var counter = Math.floor(timeSec / period);
    return hotp(secretBytes, counter, digits, hmacFn, algorithm);
  }

  function secondsRemaining(nowSec, period) {
    var p = period || 30;
    return p - (Math.floor(nowSec) % p);
  }

  function progressFraction(nowSec, period) {
    var p = period || 30;
    return (Math.floor(nowSec) % p) / p;
  }

  /* ---------------- formatting -------------------------------------------- */
  var BN_DIGITS = ['\u09e6', '\u09e7', '\u09e8', '\u09e9', '\u09ea', '\u09eb', '\u09ec', '\u09ed', '\u09ee', '\u09ef'];
  function toBanglaDigits(s) {
    return String(s).replace(/[0-9]/g, function (d) { return BN_DIGITS[+d]; });
  }

  function groupCode(code) {
    var c = String(code);
    if (c.length === 6) return c.slice(0, 3) + ' ' + c.slice(3);
    if (c.length === 8) return c.slice(0, 4) + ' ' + c.slice(4);
    return c;
  }

  /* ---------------- import / export --------------------------------------- */
  function validateImport(data) {
    var errors = [];
    if (!data || typeof data !== 'object') return { ok: false, errors: ['import_invalid'], accounts: [] };
    if (data.app !== APP_ID) errors.push('import_wrong_app');
    if (data.version !== STORE_VERSION) errors.push('import_wrong_version');
    if (!Array.isArray(data.accounts)) errors.push('import_no_accounts');
    if (errors.length) return { ok: false, errors: errors, accounts: [] };
    var seen = {};
    var accounts = [];
    for (var i = 0; i < data.accounts.length; i++) {
      var raw = data.accounts[i];
      var v = validateAccount(raw);
      if (!v.ok) { errors.push('import_bad_account_' + (i + 1)); continue; }
      var a = normalizeAccount(raw);
      var key = a.issuer.toLowerCase() + '\n' + a.account.toLowerCase();
      if (seen[key]) { errors.push('import_duplicate_' + (i + 1)); continue; }
      seen[key] = true;
      a.id = newId() + i;
      accounts.push(a);
    }
    if (accounts.length === 0 && data.accounts.length > 0) errors.push('import_no_valid');
    return { ok: errors.length === 0, errors: errors, accounts: accounts };
  }

  /* ---------------- demo account (RFC 6238 test vector) ------------------- */
  function demoAccount() {
    return {
      id: 'demo-rfc6238', issuer: 'RFC 6238 Demo', account: 'demo@example.com',
      secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', algorithm: 'SHA1', digits: 8, period: 30,
      demo: true, createdAt: 0
    };
  }

  return {
    APP_ID: APP_ID, STORE_VERSION: STORE_VERSION, ALGORITHMS: ALGORITHMS,
    normalizeSecret: normalizeSecret, base32Decode: base32Decode, base32Encode: base32Encode,
    parseOtpauthUri: parseOtpauthUri, buildOtpauthUri: buildOtpauthUri,
    validateAccount: validateAccount, normalizeAccount: normalizeAccount, newId: newId,
    hotp: hotp, totpAt: totpAt, secondsRemaining: secondsRemaining, progressFraction: progressFraction,
    toBanglaDigits: toBanglaDigits, groupCode: groupCode,
    validateImport: validateImport, demoAccount: demoAccount
  };
});
