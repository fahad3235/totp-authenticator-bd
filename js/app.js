/* totp-authenticator-bd \u2014 UI. Offline, zero network requests.
 * Codes are computed with WebCrypto (crypto.subtle HMAC). `?asof=<epoch>`
 * freezes displayed time (test hook used by tests/smoke.js).
 */
(function () {
  'use strict';
  var L = window.TotpLogic;
  var I18N = window.I18N;
  var STORE_KEY = 'totp-authenticator-bd:v1';

  var state = { accounts: [], lang: 'en', filter: '' };
  var editingId = null;
  var shownSecrets = {};
  var codeCache = {}; /* id -> {counter, code} */
  var secretBytesCache = {};
  var frozenNow = null;
  var toastTimer = null;

  function $(id) { return document.getElementById(id); }
  function t(key) { return (I18N[state.lang] && I18N[state.lang][key]) || I18N.en[key] || key; }
  function errText(code) { return t('err_' + code) || code; }
  function dispDigits(s) { return state.lang === 'bn' ? L.toBanglaDigits(String(s)) : String(s); }

  function nowSec() {
    if (frozenNow !== null) return frozenNow;
    return Date.now() / 1000;
  }

  /* ---------------- storage ---------------- */
  function load() {
    try {
      var raw = localStorage.getItem(STORE_KEY);
      if (!raw) return;
      var data = JSON.parse(raw);
      if (data && Array.isArray(data.accounts)) {
        state.accounts = data.accounts.filter(function (a) { return L.validateAccount(a).ok; }).map(L.normalizeAccount);
      }
      if (data && (data.lang === 'en' || data.lang === 'bn')) state.lang = data.lang;
    } catch (e) { /* corrupted storage -> start empty */ }
  }
  function save() {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify({ app: L.APP_ID, version: L.STORE_VERSION, lang: state.lang, accounts: state.accounts }));
    } catch (e) { /* storage full/blocked: app still works in-memory */ }
  }

  /* ---------------- crypto ---------------- */
  var WEB_ALGO = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
  async function hmacFn(algorithm, keyBytes, msgBytes) {
    var key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: WEB_ALGO[algorithm] || 'SHA-1' }, false, ['sign']);
    var sig = await crypto.subtle.sign('HMAC', key, msgBytes);
    return new Uint8Array(sig);
  }

  function secretBytes(a) {
    if (!secretBytesCache[a.id]) secretBytesCache[a.id] = L.base32Decode(a.secret);
    return secretBytesCache[a.id];
  }

  /* ---------------- i18n ---------------- */
  function applyI18n() {
    document.querySelectorAll('[data-i18n]').forEach(function (el) { el.textContent = t(el.getAttribute('data-i18n')); });
    document.querySelectorAll('[data-i18n-ph]').forEach(function (el) { el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph'))); });
    document.documentElement.lang = state.lang === 'bn' ? 'bn' : 'en';
    $('langEn').classList.toggle('active', state.lang === 'en');
    $('langBn').classList.toggle('active', state.lang === 'bn');
    $('addBtn').textContent = editingId ? t('updateBtn') : t('addBtn');
    $('cancelEditBtn').hidden = !editingId;
  }

  /* ---------------- toast / errors ---------------- */
  function toast(msg) {
    var el = $('toast');
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.hidden = true; }, 2200);
  }
  function showFormError(msg) {
    var el = $('formError');
    el.textContent = msg;
    el.hidden = !msg;
  }

  /* ---------------- render list ---------------- */
  function visibleAccounts() {
    var q = state.filter.trim().toLowerCase();
    var list = state.accounts.slice().sort(function (a, b) {
      var x = (a.issuer + ' ' + a.account).toLowerCase();
      var y = (b.issuer + ' ' + b.account).toLowerCase();
      return x < y ? -1 : x > y ? 1 : 0;
    });
    if (!q) return list;
    return list.filter(function (a) {
      return (a.issuer + ' ' + a.account).toLowerCase().indexOf(q) >= 0;
    });
  }

  function ringSvg() {
    return '<svg class="ring" viewBox="0 0 36 36" aria-hidden="true">' +
      '<circle class="ring-bg" cx="18" cy="18" r="15.9155"></circle>' +
      '<circle class="ring-fg" cx="18" cy="18" r="15.9155"></circle></svg>';
  }

  function render() {
    var list = $('accountsList');
    list.innerHTML = '';
    var vis = visibleAccounts();
    $('emptyState').hidden = state.accounts.length !== 0;
    $('noMatch').hidden = !(state.accounts.length > 0 && vis.length === 0);
    vis.forEach(function (a) {
      var card = document.createElement('article');
      card.className = 'card';
      card.dataset.id = a.id;
      var weak = '';
      try { if (secretBytes(a).length < 16) weak = '<p class="weak">' + t('weakSecret') + '</p>'; } catch (e) { weak = ''; }
      card.innerHTML =
        '<div class="card-head"><div class="card-id">' +
          '<strong class="issuer"></strong>' +
          (a.demo ? ' <span class="demo-tag">' + t('demoTag') + '</span>' : '') +
          '<div class="acct"></div>' + weak +
        '</div>' +
        '<div class="ring-wrap">' + ringSvg() + '<span class="secs"></span></div></div>' +
        '<div class="code-row"><button class="code" type="button" title="' + t('copyBtn') + '">\u2022\u2022\u2022 \u2022\u2022\u2022</button>' +
        '<button class="btn small copy-btn" type="button">' + t('copyBtn') + '</button></div>' +
        '<div class="meta"><span class="algo">' + a.algorithm + ' \u00b7 ' + a.digits + '-digit \u00b7 ' + a.period + 's</span>' +
        '<span class="otpauth" title="otpauth:// URI"></span></div>' +
        '<div class="secret-row" hidden><code class="secret-text"></code></div>' +
        '<div class="card-actions">' +
          '<button class="btn small ghost toggle-secret" type="button">' + t('showSecret') + '</button>' +
          '<button class="btn small ghost edit-btn" type="button">' + t('editBtn') + '</button>' +
          '<button class="btn small danger delete-btn" type="button"></button>' +
        '</div>';
      card.querySelector('.issuer').textContent = a.issuer;
      card.querySelector('.acct').textContent = a.account;
      card.querySelector('.otpauth').textContent = L.buildOtpauthUri(a);
      card.querySelector('.secret-text').textContent = a.secret.match(/.{1,4}/g).join(' ');
      card.querySelector('.delete-btn').textContent = t('deleteBtn');
      list.appendChild(card);

      card.querySelector('.code').addEventListener('click', function () { copyCode(a); });
      card.querySelector('.copy-btn').addEventListener('click', function () { copyCode(a); });
      card.querySelector('.toggle-secret').addEventListener('click', function (ev) {
        var row = card.querySelector('.secret-row');
        var show = row.hidden;
        row.hidden = !show;
        ev.target.textContent = show ? t('hideSecret') : t('showSecret');
      });
      card.querySelector('.edit-btn').addEventListener('click', function () { startEdit(a); });
      card.querySelector('.delete-btn').addEventListener('click', function (ev) { requestDelete(a, ev.target); });
    });
    updateCodes(true);
  }

  function requestDelete(a, btn) {
    if (btn.dataset.armed) {
      state.accounts = state.accounts.filter(function (x) { return x.id !== a.id; });
      delete secretBytesCache[a.id];
      delete codeCache[a.id];
      if (editingId === a.id) cancelEdit();
      save();
      render();
      return;
    }
    btn.dataset.armed = '1';
    btn.textContent = t('confirmDelete');
    setTimeout(function () { delete btn.dataset.armed; btn.textContent = t('deleteBtn'); }, 3000);
  }

  /* ---------------- live codes ---------------- */
  async function computeCode(a, now) {
    var counter = Math.floor(now / a.period);
    var cached = codeCache[a.id];
    if (cached && cached.counter === counter) return cached.code;
    var code = await L.totpAt(secretBytes(a), now, { digits: a.digits, period: a.period, algorithm: a.algorithm }, hmacFn);
    codeCache[a.id] = { counter: counter, code: code };
    return code;
  }

  async function updateCodes(force) {
    var now = nowSec();
    var cards = document.querySelectorAll('#accountsList .card');
    for (var i = 0; i < cards.length; i++) {
      (function (card) {
        var id = card.dataset.id;
        var a = null;
        for (var j = 0; j < state.accounts.length; j++) if (state.accounts[j].id === id) a = state.accounts[j];
        if (!a) return;
        var remain = L.secondsRemaining(now, a.period);
        var frac = L.progressFraction(now, a.period);
        var fg = card.querySelector('.ring-fg');
        if (fg) fg.style.strokeDashoffset = String(100 * frac);
        var secs = card.querySelector('.secs');
        if (secs) secs.textContent = dispDigits(remain);
        computeCode(a, now).then(function (code) {
          var btn = card.querySelector('.code');
          if (btn) {
            btn.textContent = dispDigits(L.groupCode(code));
            btn.dataset.raw = code;
          }
        }).catch(function () {
          var btn2 = card.querySelector('.code');
          if (btn2) btn2.textContent = '\u2013\u2013\u2013 \u2013\u2013\u2013';
        });
      })(cards[i]);
    }
  }

  async function copyCode(a) {
    var code = codeCache[a.id] ? codeCache[a.id].code : null;
    if (!code) code = await computeCode(a, nowSec());
    var ok = await copyText(code);
    toast(ok ? t('copied') : t('copyFailed'));
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      try {
        var ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand('copy');
        document.body.removeChild(ta);
        return ok;
      } catch (e2) { return false; }
    }
  }

  /* ---------------- add / edit ---------------- */
  function readManualForm() {
    return {
      issuer: $('issuerInput').value.trim(),
      account: $('accountInput').value.trim(),
      secret: $('secretInput').value,
      algorithm: $('algoSel').value,
      digits: parseInt($('digitsSel').value, 10),
      period: parseInt($('periodSel').value, 10)
    };
  }

  function duplicateExists(a, ignoreId) {
    return state.accounts.some(function (x) {
      return x.id !== ignoreId &&
        x.issuer.toLowerCase() === a.issuer.toLowerCase() &&
        x.account.toLowerCase() === a.account.toLowerCase();
    });
  }

  function submitForm() {
    var a = readManualForm();
    var v = L.validateAccount(a);
    if (!v.ok) { showFormError(v.errors.map(errText).join(' ')); return; }
    if (duplicateExists(a, editingId)) { showFormError(t('err_duplicate')); return; }
    if (editingId) {
      var ex = null;
      state.accounts.forEach(function (x) { if (x.id === editingId) ex = x; });
      if (ex) {
        ex.issuer = a.issuer; ex.account = a.account; ex.secret = L.normalizeSecret(a.secret);
        ex.algorithm = a.algorithm; ex.digits = a.digits; ex.period = a.period;
        delete secretBytesCache[ex.id];
        delete codeCache[ex.id];
      }
      cancelEdit();
    } else {
      var na = L.normalizeAccount(a);
      na.id = L.newId();
      na.createdAt = Math.floor(Date.now() / 1000);
      state.accounts.push(na);
    }
    save();
    render();
    clearForm();
    showFormError('');
  }

  function clearForm() {
    ['issuerInput', 'accountInput', 'secretInput', 'uriInput'].forEach(function (id) { $(id).value = ''; });
  }

  function startEdit(a) {
    editingId = a.id;
    $('issuerInput').value = a.issuer;
    $('accountInput').value = a.account;
    $('secretInput').value = a.secret;
    $('algoSel').value = a.algorithm;
    $('digitsSel').value = String(a.digits);
    $('periodSel').value = String(a.period);
    showTab('manual');
    applyI18n();
    $('addSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
    $('issuerInput').focus();
  }

  function cancelEdit() {
    editingId = null;
    clearForm();
    applyI18n();
    showFormError('');
  }

  function showTab(which) {
    $('tabManualBtn').classList.toggle('active', which === 'manual');
    $('tabUriBtn').classList.toggle('active', which === 'uri');
    $('manualForm').hidden = which !== 'manual';
    $('uriForm').hidden = which !== 'uri';
  }

  function parseUriIntoForm() {
    var raw = $('uriInput').value;
    try {
      var a = L.parseOtpauthUri(raw);
      $('issuerInput').value = a.issuer;
      $('accountInput').value = a.account;
      $('secretInput').value = a.secret;
      $('algoSel').value = a.algorithm;
      $('digitsSel').value = String(a.digits);
      var periodSel = $('periodSel');
      var found = false;
      for (var i = 0; i < periodSel.options.length; i++) if (+periodSel.options[i].value === a.period) found = true;
      if (!found) {
        var opt = document.createElement('option');
        opt.value = String(a.period);
        opt.textContent = String(a.period);
        periodSel.appendChild(opt);
      }
      periodSel.value = String(a.period);
      showTab('manual');
      showFormError('');
      toast(t('parseBtn') + ' \u2713');
    } catch (e) {
      showFormError(errText(e.message) || e.message);
    }
  }

  /* ---------------- demo / export / import / erase ---------------- */
  function addDemo() {
    if (state.accounts.some(function (x) { return x.id === 'demo-rfc6238'; })) { toast(t('demoTag') + ' \u2713'); return; }
    state.accounts.push(L.demoAccount());
    save();
    render();
  }

  function exportPayload() {
    return { app: L.APP_ID, version: L.STORE_VERSION, exportedAt: new Date().toISOString(), accounts: state.accounts };
  }

  function exportJson() {
    var blob = new Blob([JSON.stringify(exportPayload(), null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'totp-authenticator-bd-export.json';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
    toast(t('exportDone'));
  }

  async function copyExport() {
    var ok = await copyText(JSON.stringify(exportPayload(), null, 2));
    toast(ok ? t('copied') : t('copyFailed'));
  }

  function doImport() {
    var msg = $('importMsg');
    var raw = $('importText').value.trim();
    if (!raw) { msg.textContent = t('err_import_invalid'); return; }
    var data;
    try { data = JSON.parse(raw); } catch (e) { msg.textContent = t('err_import_invalid'); return; }
    var res = L.validateImport(data);
    var added = 0, skipped = 0;
    res.accounts.forEach(function (a) {
      if (duplicateExists(a, null)) { skipped++; return; }
      state.accounts.push(a);
      added++;
    });
    if (res.errors.length) skipped += res.errors.length;
    if (added > 0) { save(); render(); }
    if (res.errors.length && added === 0) msg.textContent = res.errors.map(errText).join(' ');
    else msg.textContent = t('importOk').replace('{n}', String(added));
  }

  function doErase() {
    if ($('eraseInput').value.trim() !== 'DELETE') return;
    state.accounts = [];
    secretBytesCache = {};
    codeCache = {};
    editingId = null;
    try { localStorage.removeItem(STORE_KEY); } catch (e) { /* ignore */ }
    $('erasePanel').hidden = true;
    $('eraseInput').value = '';
    render();
    toast(t('eraseDone'));
  }

  /* ---------------- init ---------------- */
  function init() {
    var params = new URLSearchParams(location.search);
    var asof = params.get('asof');
    if (asof !== null && asof !== '' && !isNaN(+asof)) {
      frozenNow = +asof;
      $('frozenBadge').hidden = false;
    }
    if (!window.crypto || !crypto.subtle) {
      $('fatalError').hidden = false;
      $('fatalError').textContent = 'WebCrypto (crypto.subtle) is not available in this browser \u2014 codes cannot be computed.';
      return;
    }
    load();
    applyI18n();
    render();
    setInterval(function () { updateCodes(false); }, 250);

    $('langEn').addEventListener('click', function () { state.lang = 'en'; save(); applyI18n(); render(); });
    $('langBn').addEventListener('click', function () { state.lang = 'bn'; save(); applyI18n(); render(); });
    $('tabManualBtn').addEventListener('click', function () { showTab('manual'); });
    $('tabUriBtn').addEventListener('click', function () { showTab('uri'); });
    $('parseBtn').addEventListener('click', parseUriIntoForm);
    $('addBtn').addEventListener('click', submitForm);
    $('cancelEditBtn').addEventListener('click', cancelEdit);
    $('demoBtn').addEventListener('click', addDemo);
    $('searchInput').addEventListener('input', function (e) { state.filter = e.target.value; render(); });
    $('exportBtn').addEventListener('click', exportJson);
    $('copyExportBtn').addEventListener('click', copyExport);
    $('importBtn').addEventListener('click', function () {
      $('importPanel').hidden = !$('importPanel').hidden;
      $('erasePanel').hidden = true;
    });
    $('importDoBtn').addEventListener('click', doImport);
    $('eraseBtn').addEventListener('click', function () {
      $('erasePanel').hidden = !$('erasePanel').hidden;
      $('importPanel').hidden = true;
    });
    $('eraseDoBtn').addEventListener('click', doErase);
    ['issuerInput', 'accountInput', 'secretInput'].forEach(function (id) {
      $(id).addEventListener('input', function () { showFormError(''); });
    });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
