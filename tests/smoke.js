// totp-authenticator-bd — headless-Chrome smoke test via raw CDP (no puppeteer).
// Usage: node tests/smoke.js
// Exits non-zero on any failed assertion; fails on page console errors.
// Loads file://index.html?asof=59 so the demo (RFC 6238) code is deterministic:
// at t=59 the 8-digit SHA-1 code must be 94287082.
const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const crypto = require('node:crypto');

const PORT = 9352;
const FILE = 'file://' + path.resolve(__dirname, '..', 'index.html') + '?asof=59';
let failures = 0;
let count = 0;
const pageErrors = [];
const nonFileRequests = [];
function check(name, cond, extra) {
  count++;
  console.log((cond ? 'ok - ' : 'FAIL - ') + name + (cond ? '' : ' :: ' + (extra || '')));
  if (!cond) failures++;
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// Expected 6-digit code for JBSWY3DPEHPK3PXP (Hello! + deadbeef) at t=59, SHA-1.
function expectedCode6() {
  const secret = Buffer.from('JBSWY3DPEHPK3PXP', 'ascii');
  // decode base32 manually via the app's own logic is circular; use known bytes:
  const bytes = Buffer.from('Hello!\xde\xad\xbe\xef', 'latin1');
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(59 / 30)));
  const mac = crypto.createHmac('sha1', bytes).update(msg).digest();
  const o = mac[mac.length - 1] & 0x0f;
  const code = ((mac[o] & 0x7f) << 24 | (mac[o + 1] & 0xff) << 16 | (mac[o + 2] & 0xff) << 8 | (mac[o + 3] & 0xff)) % 1000000;
  return String(code).padStart(6, '0');
}

(async () => {
  const CHROME_BIN = process.env.CHROME_BIN ||
    require('os').homedir() + '/.cache/ms-playwright/chromium_headless_shell-1187/chrome-linux/headless_shell';
  const chrome = spawn(CHROME_BIN, [
    '--headless=new', '--no-sandbox', '--disable-gpu',
    '--remote-debugging-port=' + PORT, '--user-data-dir=/tmp/totp-smoke-' + process.pid,
    'about:blank',
  ], { stdio: 'ignore' });
  let targets = [];
  for (let i = 0; i < 50 && targets.length === 0; i++) {
    await wait(200);
    try {
      targets = JSON.parse(await new Promise((res, rej) => {
        http.get('http://127.0.0.1:' + PORT + '/json/list', (r) => {
          let d = ''; r.on('data', (c) => (d += c)); r.on('end', () => res(d));
        }).on('error', rej);
      }));
    } catch (e) { /* retry */ }
  }
  if (!targets.length) { console.log('FAIL - chrome did not start'); process.exit(2); }
  const wsUrl = targets[0].webSocketDebuggerUrl;
  const ws = new WebSocket(wsUrl);
  await new Promise((res) => { ws.onopen = res; });
  let seq = 0; const pending = new Map();
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
    if (msg.method === 'Runtime.exceptionThrown') {
      pageErrors.push('exception: ' + JSON.stringify(msg.params.exceptionDetails).slice(0, 300));
    }
    if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
      pageErrors.push('console.error: ' + JSON.stringify(msg.params.args).slice(0, 300));
    }
    if (msg.method === 'Network.requestWillBeSent') {
      const u = msg.params.request.url;
      if (!u.startsWith('file://') && !u.startsWith('data:') && !u.startsWith('blob:')) nonFileRequests.push(u);
    }
  };
  function send(method, params) {
    return new Promise((res) => {
      const id = ++seq;
      pending.set(id, res);
      ws.send(JSON.stringify({ id, method, params: params || {} }));
    });
  }
  await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: FILE });
  await wait(1500);
  const ev = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.result && r.result.exceptionDetails) return { error: JSON.stringify(r.result.exceptionDetails).slice(0, 300) };
    return r.result ? r.result.result.value : undefined;
  };
  const setVal = async (id, v) =>
    ev(`document.getElementById('${id}').value=${JSON.stringify(v)}; document.getElementById('${id}').dispatchEvent(new Event('input'));`);

  check('page title contains TOTP', (await ev('document.title'))?.includes('TOTP'));
  check('frozen-time badge visible with ?asof', (await ev(`document.getElementById('frozenBadge').hidden`)) === false);
  check('empty state visible initially', (await ev(`document.getElementById('emptyState').hidden`)) === false);
  check('security note renders', (await ev(`document.querySelector('.note h2').textContent`)).length > 5);
  check('no fatal WebCrypto error', (await ev(`document.getElementById('fatalError').hidden`)) === true);

  // Demo account: RFC 6238 vector — at t=59 the 8-digit code is 94287082.
  await ev(`document.getElementById('demoBtn').click();`);
  await wait(1200);
  check('demo card appears', (await ev(`document.querySelectorAll('#accountsList .card').length`)) === 1);
  check('demo code is 9428 7082 at t=59',
    (await ev(`document.querySelector('#accountsList .card .code').textContent`)) === '9428 7082');
  check('demo countdown shows 1s left at t=59',
    (await ev(`document.querySelector('#accountsList .card .secs').textContent`)) === '1');
  check('demo tag shown', (await ev(`document.querySelector('#accountsList .card .demo-tag') !== null`)) === true);
  check('empty state hidden after add', (await ev(`document.getElementById('emptyState').hidden`)) === true);

  // Validation: bad secret rejected with inline error.
  await setVal('issuerInput', 'GitHub');
  await setVal('accountInput', 'octocat@github.com');
  await setVal('secretInput', 'NOT-BASE32!!!');
  await ev(`document.getElementById('addBtn').click();`);
  await wait(300);
  check('bad secret shows inline error', (await ev(`document.getElementById('formError').hidden`)) === false);
  check('bad secret does not add a card', (await ev(`document.querySelectorAll('#accountsList .card').length`)) === 1);

  // Valid manual account: code must match node:crypto-computed value.
  await setVal('secretInput', 'JBSWY3DPEHPK3PXP');
  await ev(`document.getElementById('addBtn').click();`);
  await wait(1200);
  check('valid account adds second card', (await ev(`document.querySelectorAll('#accountsList .card').length`)) === 2);
  const want6 = expectedCode6();
  const shownCodes = await ev(`Array.from(document.querySelectorAll('#accountsList .card .code')).map(e => e.textContent)`);
  const grouped = want6.slice(0, 3) + ' ' + want6.slice(3);
  check('manual account code matches node:crypto (' + grouped + ')', shownCodes.includes(grouped), JSON.stringify(shownCodes));

  // Duplicate rejected.
  await setVal('issuerInput', 'GitHub');
  await setVal('accountInput', 'octocat@github.com');
  await setVal('secretInput', 'JBSWY3DPEHPK3PXP');
  await ev(`document.getElementById('addBtn').click();`);
  await wait(300);
  check('duplicate account rejected', (await ev(`document.querySelectorAll('#accountsList .card').length`)) === 2);

  // Search filter.
  await setVal('searchInput', 'github');
  await wait(300);
  check('search filters to 1 card', (await ev(`document.querySelectorAll('#accountsList .card').length`)) === 1);
  await setVal('searchInput', 'zzz-no-match');
  await wait(300);
  check('no-match message shows', (await ev(`document.getElementById('noMatch').hidden`)) === false);
  await setVal('searchInput', '');
  await wait(300);

  // Copy button shows a toast (clipboard may or may not succeed headless).
  await ev(`document.querySelector('#accountsList .card .copy-btn').click();`);
  await wait(400);
  check('copy shows a toast', (await ev(`document.getElementById('toast').hidden`)) === false);

  // otpauth:// parse fills the manual form.
  await ev(`document.getElementById('tabUriBtn').click();`);
  await setVal('uriInput', 'otpauth://totp/Acme:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme&algorithm=SHA256&digits=8&period=60');
  await ev(`document.getElementById('parseBtn').click();`);
  await wait(300);
  check('URI parse fills issuer', (await ev(`document.getElementById('issuerInput').value`)) === 'Acme');
  check('URI parse fills account', (await ev(`document.getElementById('accountInput').value`)) === 'alice@example.com');
  check('URI parse fills secret', (await ev(`document.getElementById('secretInput').value`)) === 'JBSWY3DPEHPK3PXP');
  check('URI parse fills algorithm', (await ev(`document.getElementById('algoSel').value`)) === 'SHA256');
  check('URI parse fills digits', (await ev(`document.getElementById('digitsSel').value`)) === '8');
  // Bad URI shows error.
  await ev(`document.getElementById('tabUriBtn').click();`);
  await setVal('uriInput', 'https://example.com/not-otpauth');
  await ev(`document.getElementById('parseBtn').click();`);
  await wait(300);
  check('bad URI shows inline error', (await ev(`document.getElementById('formError').hidden`)) === false);

  // Edit flow: open edit on first card, change account name, cancel.
  await ev(`document.querySelector('#accountsList .card .edit-btn').click();`);
  await wait(300);
  check('edit mode shows Save changes', (await ev(`document.getElementById('addBtn').textContent`)).includes('Save changes'));
  check('edit pre-fills issuer', (await ev(`document.getElementById('issuerInput').value`)).length > 0);
  await ev(`document.getElementById('cancelEditBtn').click();`);
  await wait(200);
  check('cancel edit restores Add account', (await ev(`document.getElementById('addBtn').textContent`)).includes('Add account'));

  // Bengali toggle: title + demo code in Bengali digits.
  await ev(`document.getElementById('langBn').click();`);
  await wait(800);
  check('BN title renders Bengali', (await ev(`document.getElementById('appTitle').textContent`)).includes('টিওটিপি'));
  check('BN code shows Bengali digits', (await ev(`Array.from(document.querySelectorAll('#accountsList .card')).find(c => c.querySelector('.demo-tag')).querySelector('.code').textContent`)).includes('৯৪২৮'), await ev(`document.querySelector('#accountsList .card .code').textContent`));
  await ev(`document.getElementById('langEn').click();`);
  await wait(500);

  // Export: copy-export produces valid JSON with 2 accounts.
  await ev(`document.getElementById('copyExportBtn').click();`);
  await wait(400);
  const clip = await ev(`navigator.clipboard.readText().catch(() => '')`);
  if (clip) {
    const parsed = JSON.parse(clip);
    check('export JSON has app id', parsed.app === 'totp-authenticator-bd');
    check('export JSON has 2 accounts', parsed.accounts.length === 2, 'got ' + (parsed.accounts && parsed.accounts.length));
  } else {
    check('export JSON readable via clipboard (headless clipboard unavailable — skipped)', true);
  }

  // Persistence: reload keeps both accounts.
  await send('Page.navigate', { url: FILE });
  await wait(1500);
  check('reload restores 2 accounts', (await ev(`document.querySelectorAll('#accountsList .card').length`)) === 2);

  // Import: delete all via erase flow, then import the demo account JSON.
  await ev(`document.getElementById('eraseBtn').click();`);
  await setVal('eraseInput', 'DELETE');
  await ev(`document.getElementById('eraseDoBtn').click();`);
  await wait(500);
  check('erase-all clears the list', (await ev(`document.querySelectorAll('#accountsList .card').length`)) === 0);
  const demoJson = JSON.stringify({ app: 'totp-authenticator-bd', version: 1, accounts: [{ issuer: 'RFC 6238 Demo', account: 'demo@example.com', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', algorithm: 'SHA1', digits: 8, period: 30, demo: true }] });
  await ev(`document.getElementById('importBtn').click();`);
  await setVal('importText', demoJson);
  await ev(`document.getElementById('importDoBtn').click();`);
  await wait(1200);
  check('import restores demo account', (await ev(`document.querySelectorAll('#accountsList .card').length`)) === 1);
  check('imported demo code is 9428 7082',
    (await ev(`document.querySelector('#accountsList .card .code').textContent`)) === '9428 7082');

  // Delete: two-step confirm removes the card.
  await ev(`document.querySelector('#accountsList .card .delete-btn').click();`);
  await wait(200);
  check('first delete click arms confirm', (await ev(`document.querySelector('#accountsList .card .delete-btn').textContent`)).includes('again'));
  await ev(`document.querySelector('#accountsList .card .delete-btn').click();`);
  await wait(400);
  check('second delete click removes card', (await ev(`document.querySelectorAll('#accountsList .card').length`)) === 0);

  // 390px mobile: no horizontal overflow.
  await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
  await wait(600);
  check('390px no horizontal overflow', (await ev(`document.documentElement.scrollWidth <= 391`)) === true,
    'scrollWidth=' + (await ev(`document.documentElement.scrollWidth`)));

  check('zero page console/page errors', pageErrors.length === 0, pageErrors.join(' | ').slice(0, 400));
  check('zero non-file network requests', nonFileRequests.length === 0, nonFileRequests.join(', ').slice(0, 300));

  console.log('\n' + count + ' checks, ' + failures + ' failed');
  try { chrome.kill(); } catch (e) { /* ignore */ }
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(2); });
