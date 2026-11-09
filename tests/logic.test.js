// totp-authenticator-bd — Node unit tests for js/logic.js (pure logic).
// Usage: node tests/logic.test.js  (exits non-zero on failure)
const crypto = require('node:crypto');
const L = require('../js/logic.js');

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('ok - ' + name); }
  else { fail++; console.log('FAIL - ' + name + (extra ? ' :: ' + extra : '')); }
}
function eq(name, got, want) { check(name, got === want, 'got ' + JSON.stringify(got) + ', want ' + JSON.stringify(want)); }

// Node HMAC adapter (independent implementation, used as the injected hmacFn).
async function nodeHmac(algorithm, keyBytes, msgBytes) {
  const map = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };
  return new Uint8Array(crypto.createHmac(map[algorithm], Buffer.from(keyBytes)).update(Buffer.from(msgBytes)).digest());
}

(async () => {
  /* ---- Base32 ---- */
  eq('base32 decode RFC test secret -> ASCII 12345678901234567890',
    Buffer.from(L.base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')).toString('ascii'), '12345678901234567890');
  const helloBytes = Buffer.from('Hello!\xde\xad\xbe\xef', 'latin1');
  eq('base32 decode lowercase + spaces + padding accepted',
    Buffer.from(L.base32Decode('jbswy3dpehpk3pxp === ')).toString('latin1'), 'Hello!\xde\xad\xbe\xef');
  check('base32 encode/decode round-trip',
    Buffer.from(L.base32Decode(L.base32Encode(helloBytes))).equals(helloBytes));
  eq('base32 encode known value', L.base32Encode(Buffer.from('Hello!', 'ascii')), 'JBSWY3DPEE======');
  let threw = false;
  try { L.base32Decode('JBSWY3DPEHPK3PXP1'); } catch (e) { threw = e.message === 'secret_bad_chars'; }
  check('base32 rejects digit 1 (bad chars)', threw);
  threw = false;
  try { L.base32Decode('ABC'); } catch (e) { threw = true; }
  check('base32 rejects impossible length', threw);

  /* ---- RFC 6238 Appendix B vectors (8 digits) ---- */
  const sha1Secret = Buffer.from('12345678901234567890', 'ascii');
  const sha256Secret = Buffer.from('12345678901234567890123456789012', 'ascii');
  const sha512Secret = Buffer.from('1234567890123456789012345678901234567890123456789012345678901234', 'ascii');
  const vectors = [
    // [time, SHA1, SHA256, SHA512] — RFC 6238 Appendix B
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  for (const [t, s1, s256, s512] of vectors) {
    eq('RFC6238 SHA1 t=' + t, await L.totpAt(sha1Secret, t, { digits: 8, period: 30, algorithm: 'SHA1' }, nodeHmac), s1);
    eq('RFC6238 SHA256 t=' + t, await L.totpAt(sha256Secret, t, { digits: 8, period: 30, algorithm: 'SHA256' }, nodeHmac), s256);
    eq('RFC6238 SHA512 t=' + t, await L.totpAt(sha512Secret, t, { digits: 8, period: 30, algorithm: 'SHA512' }, nodeHmac), s512);
  }
  // 6-digit truncation of the famous vector: 94287082 -> 287082
  eq('6-digit TOTP t=59 SHA1', await L.totpAt(sha1Secret, 59, { digits: 6, period: 30, algorithm: 'SHA1' }, nodeHmac), '287082');
  // Leading-zero preservation: t=1111111109 SHA1 is 07081804 (starts with 0)
  eq('leading zero preserved', await L.totpAt(sha1Secret, 1111111109, { digits: 8, period: 30, algorithm: 'SHA1' }, nodeHmac), '07081804');
  // Period boundary: t=59 and t=60 are different counters for period 30
  const c59 = await L.totpAt(sha1Secret, 59, { digits: 8, period: 30, algorithm: 'SHA1' }, nodeHmac);
  const c60 = await L.totpAt(sha1Secret, 60, { digits: 8, period: 30, algorithm: 'SHA1' }, nodeHmac);
  check('period boundary changes code (59 vs 60)', c59 !== c60, c59 + ' vs ' + c60);
  // Same counter within a period: t=60 and t=89 give the same code
  const c89 = await L.totpAt(sha1Secret, 89, { digits: 8, period: 30, algorithm: 'SHA1' }, nodeHmac);
  eq('same counter within period (60 vs 89)', c60, c89);

  /* ---- time helpers ---- */
  eq('secondsRemaining t=59 period 30', L.secondsRemaining(59, 30), 1);
  eq('secondsRemaining t=60 period 30', L.secondsRemaining(60, 30), 30);
  eq('secondsRemaining t=89 period 30', L.secondsRemaining(89, 30), 1);
  check('progressFraction t=45 period 30 = 0.5', L.progressFraction(45, 30) === 0.5);

  /* ---- formatting ---- */
  eq('groupCode 6 digits', L.groupCode('287082'), '287 082');
  eq('groupCode 8 digits', L.groupCode('94287082'), '9428 7082');
  eq('bangla digits', L.toBanglaDigits('287082'), '২৮৭০৮২');

  /* ---- otpauth URIs ---- */
  const parsed = L.parseOtpauthUri('otpauth://totp/GitHub:octocat@github.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30');
  eq('parse URI issuer', parsed.issuer, 'GitHub');
  eq('parse URI account', parsed.account, 'octocat@github.com');
  eq('parse URI secret', parsed.secret, 'JBSWY3DPEHPK3PXP');
  eq('parse URI algorithm', parsed.algorithm, 'SHA1');
  const minimal = L.parseOtpauthUri('otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP');
  eq('parse minimal URI defaults digits 6', minimal.digits, 6);
  eq('parse minimal URI defaults period 30', minimal.period, 30);
  eq('parse minimal URI defaults SHA1', minimal.algorithm, 'SHA1');
  eq('parse minimal URI account without issuer', minimal.account, 'alice@example.com');
  const sha256uri = L.parseOtpauthUri('otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme&algorithm=SHA256&digits=8&period=60');
  eq('parse SHA256/8-digit/60s URI', sha256uri.algorithm + '/' + sha256uri.digits + '/' + sha256uri.period, 'SHA256/8/60');
  const built = L.buildOtpauthUri({ issuer: 'GitHub', account: 'octocat@github.com', secret: 'jbswy3dpehpk3pxp', algorithm: 'SHA1', digits: 6, period: 30 });
  check('build URI round-trips through parser', (function () { try { const p = L.parseOtpauthUri(built); return p.issuer === 'GitHub' && p.account === 'octocat@github.com' && p.secret === 'JBSWY3DPEHPK3PXP'; } catch (e) { return false; } })(), built);
  threw = false;
  try { L.parseOtpauthUri('otpauth://hotp/Acme:alice?secret=JBSWY3DPEHPK3PXP&counter=0'); } catch (e) { threw = e.message === 'uri_not_totp'; }
  check('hotp URI rejected', threw);
  threw = false;
  try { L.parseOtpauthUri('otpauth://totp/Acme:alice?issuer=Acme'); } catch (e) { threw = true; }
  check('URI without secret rejected', threw);
  threw = false;
  try { L.parseOtpauthUri('https://example.com/?secret=JBSWY3DPEHPK3PXP'); } catch (e) { threw = true; }
  check('non-otpauth URI rejected', threw);

  /* ---- account validation ---- */
  const good = { issuer: 'GitHub', account: 'a@b.c', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 };
  check('valid account passes', L.validateAccount(good).ok);
  check('missing issuer fails', !L.validateAccount({ ...good, issuer: '' }).ok);
  check('missing account fails', !L.validateAccount({ ...good, account: '' }).ok);
  check('secret with 1 fails', !L.validateAccount({ ...good, secret: 'JBSWY3DPEHPK3PXP1' }).ok);
  check('secret too short fails', !L.validateAccount({ ...good, secret: 'JBSQ' }).ok);
  check('bad algorithm fails', !L.validateAccount({ ...good, algorithm: 'MD5' }).ok);
  check('7 digits fails', !L.validateAccount({ ...good, digits: 7 }).ok);
  check('period 5 fails', !L.validateAccount({ ...good, period: 5 }).ok);
  check('period 301 fails', !L.validateAccount({ ...good, period: 301 }).ok);
  check('lowercase secret normalized on validate path', L.normalizeAccount({ ...good, secret: 'jbswy3dpehpk3pxp' }).secret === 'JBSWY3DPEHPK3PXP');

  /* ---- import validation ---- */
  const demo = L.demoAccount();
  const okImport = L.validateImport({ app: 'totp-authenticator-bd', version: 1, accounts: [good, demo] });
  check('valid import passes with 2 accounts', okImport.ok && okImport.accounts.length === 2, JSON.stringify(okImport.errors));
  check('wrong app rejected', !L.validateImport({ app: 'other', version: 1, accounts: [] }).ok);
  check('wrong version rejected', !L.validateImport({ app: 'totp-authenticator-bd', version: 2, accounts: [] }).ok);
  check('non-array accounts rejected', !L.validateImport({ app: 'totp-authenticator-bd', version: 1, accounts: {} }).ok);
  check('import with one bad account still imports the good one', (function () {
    const r = L.validateImport({ app: 'totp-authenticator-bd', version: 1, accounts: [good, { ...good, secret: '!!!' }] });
    return r.accounts.length === 1 && r.errors.length === 1;
  })());
  check('import duplicate rejected', (function () {
    const r = L.validateImport({ app: 'totp-authenticator-bd', version: 1, accounts: [good, { ...good }] });
    return r.accounts.length === 1 && r.errors.length === 1;
  })());

  /* ---- demo account ---- */
  eq('demo secret is RFC test vector', demo.secret, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  eq('demo code at t=59 is 94287082',
    await L.totpAt(L.base32Decode(demo.secret), 59, { digits: demo.digits, period: demo.period, algorithm: demo.algorithm }, nodeHmac), '94287082');

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(2); });
