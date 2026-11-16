const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../views/base.html'), 'utf8');
const match = source.match(/<script\b(?=[^>]*\bdata-okuru-security-reporter\b)([^>]*)>([\s\S]*?)<\/script>/);
assert.ok(match, 'security reporter is present');
const [, attrs, script] = match;
const endpoint = '/.well-known/okuru-browser-security';

function createHarness({ fetchImpl, probeChanges = {}, missingRequest = false, realRequest = false } = {}) {
  const listeners = {};
  const requests = [];
  class RequestMock {
    constructor(url, opts) {
      this.url = url;
      Object.assign(this, opts, probeChanges);
    }
  }
  const context = {
    window: {
      location: { origin: 'https://share.example' },
      addEventListener(type, callback, capture) { listeners[`window:${type}`] = { callback, capture }; }
    },
    document: {
      addEventListener(type, callback, capture) { listeners[`document:${type}`] = { callback, capture }; }
    },
    fetch(url, options) {
      requests.push({ url, options });
      return fetchImpl ? fetchImpl(url, options) : Promise.resolve({ ok: true });
    },
    Request: missingRequest ? undefined : (realRequest ? Request : RequestMock),
  };
  vm.runInNewContext(script, context, { timeout: 1000 });
  return { listeners, requests };
}

async function settle() {
  for (let i = 0; i < 8; i++) await new Promise((resolve) => setImmediate(resolve));
}

function csp(h, directive, extra = {}) {
  h.listeners['document:securitypolicyviolation'].callback({ effectiveDirective: directive, ...extra });
}

function scriptError(h, src, extra = {}) {
  h.listeners['window:error'].callback({
    target: { tagName: 'SCRIPT', getAttribute: () => src },
    ...extra,
  });
}

function body(request) { return JSON.parse(request.options.body); }

test('reporter is the first script and carries the dynamic nonce', () => {
  assert.match(attrs, /\bnonce="\{\{ csp_nonce \}\}"/);
  assert.equal(source.indexOf('<script'), match.index);
  assert.ok(match.index < source.indexOf('</head>'));
});

test('CSP violations send only bounded categories with privacy-preserving request settings', async () => {
  const categories = [
    ['script-src-elem', 'script'], ['style-src-attr', 'style'], ['connect-src', 'connect'],
    ['worker-src', 'worker'], ['frame-ancestors', 'frame'], ['form-action', 'form'],
    ['base-uri', 'base'], ['object-src', 'object'], ['require-trusted-types-for', 'trusted_types'],
    ['img-src', 'img'], ['font-src', 'font'], ['media-src', 'media'], ['manifest-src', 'manifest'],
    ['secret-token-in-hostile-field', 'other'], ['__proto__', 'other'],
  ];
  for (const [directive, category] of categories) {
    const h = createHarness();
    csp(h, directive, {
      documentURI: 'https://share.example/file/private-secret?token=sensitive',
      blockedURI: 'https://attacker.example/secret',
      originalPolicy: "script-src 'nonce-supersecret'", sample: 'sensitive sample',
    });
    await settle();
    assert.equal(h.requests.length, 1);
    const req = h.requests[0];
    assert.equal(req.url, endpoint);
    assert.deepEqual(body(req), { kind: 'csp_violation', category });
    assert.equal(req.options.method, 'POST');
    assert.equal(req.options.mode, 'same-origin');
    assert.equal(req.options.credentials, 'omit');
    assert.equal(req.options.referrer, '');
    assert.equal(req.options.referrerPolicy, 'no-referrer');
    assert.equal(req.options.redirect, 'error');
    assert.equal(req.options.keepalive, true);
    assert.equal(req.options.headers['Content-Type'], 'application/json');
    assert.doesNotMatch(JSON.stringify(req), /private-secret|sensitive|supersecret|attacker\.example|hostile-field/);
  }
});

test('script load failures are captured without claiming an SRI failure or sending URLs', async () => {
  const cases = [
    ['/scripts/bootstrap.min.js', 'bootstrap'],
    ['scripts/purify.min.js', 'purify'],
    ['/scripts/clipboard.min.js', 'clipboard'],
    ['/scripts/service-worker-register.js', 'worker_registration'],
    ['https://attacker.example/scripts/purify.min.js?secret=private', 'other'],
  ];
  for (const [src, category] of cases) {
    const h = createHarness();
    assert.equal(h.listeners['window:error'].capture, true);
    scriptError(h, src, { message: 'secret error', filename: '/private-share' });
    await settle();
    assert.deepEqual(body(h.requests[0]), { kind: 'script_load_failure', category });
    assert.doesNotMatch(JSON.stringify(h.requests), /secret|private-share|attacker\.example/);
  }
  const h = createHarness();
  h.listeners['window:error'].callback({ target: { tagName: 'IMG', getAttribute: () => '/secret' } });
  h.listeners['window:error'].callback({ target: null });
  await settle();
  assert.equal(h.requests.length, 0);
});

test('serializes and limits reports even when many events fire while a request is pending', async () => {
  const releases = [];
  const h = createHarness({ fetchImpl: () => new Promise((resolve) => releases.push(resolve)) });
  for (let i = 0; i < 30; i++) csp(h, 'script-src');
  assert.equal(h.requests.length, 1);
  for (let i = 0; i < 5; i++) {
    releases[i]({ ok: true });
    await settle();
  }
  assert.equal(h.requests.length, 5);
  csp(h, 'script-src');
  await settle();
  assert.equal(h.requests.length, 5);
});

test('disables reporting and discards queued events on failure without a reporting loop', async () => {
  for (const fetchImpl of [
    () => Promise.reject(new Error('secret')),
    () => Promise.resolve({ ok: false }),
    () => { throw new Error('secret'); },
  ]) {
    const h = createHarness({ fetchImpl });
    csp(h, 'connect-src');
    csp(h, 'connect-src');
    await settle();
    csp(h, 'connect-src');
    await settle();
    assert.equal(h.requests.length, 1);
    assert.doesNotMatch(JSON.stringify(h.requests), /secret/);
  }
});

test('refuses to register telemetry when request privacy options cannot be verified', () => {
  for (const probeChanges of [
    { referrerPolicy: '' }, { referrer: 'about:client' }, { credentials: 'include' },
    { mode: 'cors' }, { redirect: 'follow' },
  ]) {
    const h = createHarness({ probeChanges });
    assert.equal(Object.keys(h.listeners).length, 0);
    assert.equal(h.requests.length, 0);
  }
  assert.equal(Object.keys(createHarness({ missingRequest: true }).listeners).length, 0);
});

test('privacy probe accepts the actual platform Request implementation', async () => {
  const h = createHarness({ realRequest: true });
  assert.ok(h.listeners['document:securitypolicyviolation']);
  csp(h, 'script-src');
  await settle();
  assert.deepEqual(body(h.requests[0]), { kind: 'csp_violation', category: 'script' });
});
