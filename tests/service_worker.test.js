// Run with: node --test tests/service_worker.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const publicDir = path.join(__dirname, '..', 'public');
const worker = fs.readFileSync(path.join(publicDir, 'service-worker.js'), 'utf8');
const registration = fs.readFileSync(path.join(publicDir, 'scripts', 'service-worker-register.js'), 'utf8');

test('registers the fixed root worker and accepts no other Trusted Types URL', () => {
  let registered;
  let policyRules;
  const navigator = { serviceWorker: { register(url, options) {
    registered = { url, ...options };
    return Promise.resolve();
  } } };
  const window = { trustedTypes: { createPolicy(name, rules) {
    assert.equal(name, 'okuru-service-worker');
    policyRules = rules;
    return rules;
  } } };
  vm.runInNewContext(registration, { navigator, window, TypeError });
  assert.equal(registered.url, '/service-worker.js');
  assert.equal(registered.scope, '/');
  assert.equal(registered.updateViaCache, 'none');
  assert.throws(() => policyRules.createScriptURL('/another-worker.js'), TypeError);
});

test('registration degrades safely without Trusted Types or service workers', () => {
  let url;
  const navigator = { serviceWorker: { register(value) { url = value; return Promise.resolve(); } } };
  vm.runInNewContext(registration, { navigator, window: {} });
  assert.equal(url, '/service-worker.js');
  assert.doesNotThrow(() => vm.runInNewContext(registration, { navigator: {}, window: {} }));
  assert.doesNotThrow(() => vm.runInNewContext(registration, {
    navigator,
    window: { trustedTypes: { createPolicy() { throw new Error('policy blocked'); } } },
  }));
});

function makeResponse({ status = 200, type = 'basic', redirected = false, contentType = 'text/css', cacheControl = '', pragma = '' } = {}) {
  const response = {
    status, type, redirected,
    headers: new Headers({ 'Content-Type': contentType, 'Cache-Control': cacheControl, 'Pragma': pragma }),
    clone() { return response; },
  };
  return response;
}

function makeRequest(overrides = {}) {
  return {
    url: 'https://share.jeanphilippe.io/css/custom.css',
    method: 'GET', mode: 'no-cors', cache: 'default', headers: new Headers(),
    ...overrides,
  };
}

function workerHarness({ response = makeResponse(), networkError, cached, cacheError } = {}) {
  const handlers = {};
  const calls = { fetched: 0, put: 0, match: 0, deleted: [], cacheDeleted: [] };
  const cache = {
    async put() { calls.put++; },
    async match() { calls.match++; return cached; },
    async delete(request) { calls.deleted.push(request.url); },
  };
  const caches = {
    async open(name) { assert.equal(name, 'okuru-static-v1'); if (cacheError) throw cacheError; return cache; },
    async keys() { return ['okuru-static-v0', 'okuru-static-v1', 'another-app-v1']; },
    async delete(name) { calls.cacheDeleted.push(name); },
  };
  const self = {
    location: { origin: 'https://share.jeanphilippe.io' },
    addEventListener(name, handler) { handlers[name] = handler; },
  };
  async function fetch() { calls.fetched++; if (networkError) throw networkError; return response; }
  vm.runInNewContext(worker, { self, caches, fetch, URL });
  function dispatch(request) {
    let handled;
    handlers.fetch({ request, respondWith(promise) { handled = promise; } });
    return handled;
  }
  return { handlers, calls, dispatch };
}

test('intercepts only exact public asset GETs without sensitive request directives', () => {
  const harness = workerHarness();
  const excluded = [
    makeRequest({ method: 'POST' }),
    makeRequest({ mode: 'navigate' }),
    ...['no-store', 'no-cache', 'reload', 'force-cache', 'only-if-cached']
      .map((cache) => makeRequest({ cache })),
    makeRequest({ headers: new Headers({ 'Cache-Control': 'no-cache' }) }),
    makeRequest({ headers: new Headers({ 'Cache-Control': 'must-revalidate' }) }),
    makeRequest({ headers: new Headers({ 'Pragma': 'no-cache' }) }),
    makeRequest({ headers: new Headers({ 'Cache-Control': 'max-age=0, no-store' }) }),
    makeRequest({ headers: new Headers({ 'Cache-Control': 'private="field"' }) }),
    makeRequest({ headers: new Headers({ Authorization: 'Bearer example' }) }),
    makeRequest({ headers: new Headers({ Range: 'bytes=0-5' }) }),
    makeRequest({ headers: new Headers({ 'If-None-Match': 'example' }) }),
    makeRequest({ url: 'https://share.jeanphilippe.io/css/custom.css?x=1' }),
    makeRequest({ url: 'https://share.jeanphilippe.io/css/custom.css?' }),
    makeRequest({ url: 'https://other.example/css/custom.css' }),
    makeRequest({ url: 'https://share.jeanphilippe.io/' }),
    makeRequest({ url: 'https://share.jeanphilippe.io/file/example' }),
    makeRequest({ url: 'https://share.jeanphilippe.io/api/v1/password' }),
    makeRequest({ url: 'https://share.jeanphilippe.io/scripts/service-worker-register.js' }),
  ];
  for (const request of excluded) assert.equal(harness.dispatch(request), undefined, request.url);
  assert.equal(harness.calls.fetched, 0);
});

test('network is first, only eligible successful static responses are stored', async () => {
  const response = makeResponse();
  const harness = workerHarness({ response });
  assert.equal(await harness.dispatch(makeRequest()), response);
  assert.deepEqual({ fetched: harness.calls.fetched, put: harness.calls.put, match: harness.calls.match }, { fetched: 1, put: 1, match: 0 });
  const js = workerHarness({ response: makeResponse({ contentType: 'text/javascript; charset=utf-8' }) });
  await js.dispatch(makeRequest({ url: 'https://share.jeanphilippe.io/scripts/purify.min.js' }));
  assert.equal(js.calls.put, 1);
});

test('never stores prohibited, invalid or uncacheable responses', async () => {
  const responses = [
    makeResponse({ cacheControl: 'no-store' }),
    makeResponse({ cacheControl: 'private="set-cookie"' }),
    makeResponse({ cacheControl: 'max-age=0, no-cache' }),
    makeResponse({ cacheControl: 'NO-CACHE="field"' }),
    makeResponse({ pragma: 'no-cache' }),
    makeResponse({ cacheControl: 'public, must-revalidate' }),
    makeResponse({ cacheControl: 'public, proxy-revalidate' }),
    makeResponse({ status: 404 }),
    makeResponse({ status: 500 }),
    makeResponse({ type: 'opaque' }),
    makeResponse({ redirected: true }),
    makeResponse({ contentType: 'text/html' }),
  ];
  for (const response of responses) {
    const harness = workerHarness({ response });
    assert.equal(await harness.dispatch(makeRequest()), response);
    assert.equal(harness.calls.put, 0);
    assert.equal(harness.calls.match, 0);
    if (/no-store|private|no-cache|must-revalidate|proxy-revalidate/i.test(response.headers.get('Cache-Control')) || response.headers.get('Pragma') === 'no-cache') assert.equal(harness.calls.deleted.length, 1);
  }
});

test('only a network failure uses a validated cached asset', async () => {
  const error = new Error('offline');
  const cached = makeResponse();
  const harness = workerHarness({ networkError: error, cached });
  assert.equal(await harness.dispatch(makeRequest()), cached);
  assert.equal(harness.calls.match, 1);
  for (const bad of [undefined, makeResponse({ status: 404 }), makeResponse({ cacheControl: 'private' }), makeResponse({ cacheControl: 'no-cache' }), makeResponse({ pragma: 'no-cache' }), makeResponse({ cacheControl: 'must-revalidate' }), makeResponse({ cacheControl: 'proxy-revalidate' }), makeResponse({ contentType: 'text/html' })]) {
    const miss = workerHarness({ networkError: error, cached: bad });
    await assert.rejects(miss.dispatch(makeRequest()), (caught) => caught === error);
  }
  const inaccessible = workerHarness({ networkError: error, cacheError: new Error('cache unavailable') });
  await assert.rejects(inaccessible.dispatch(makeRequest()), (caught) => caught === error);
});

test('cache failure does not block a network response', async () => {
  const response = makeResponse();
  const harness = workerHarness({ response, cacheError: new Error('quota') });
  assert.equal(await harness.dispatch(makeRequest()), response);
});

test('activation deletes only obsolete caches in the Okuru static namespace', async () => {
  const harness = workerHarness();
  let activation;
  harness.handlers.activate({ waitUntil(promise) { activation = promise; } });
  await activation;
  assert.deepEqual(harness.calls.cacheDeleted, ['okuru-static-v0']);
});
