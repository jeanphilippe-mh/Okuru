const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const scripts = path.join(__dirname, '../public/scripts');
const origin = 'https://share.example';
const base = '/api/v2/uploads';
const asJSON = (status, data, headers = {}) => Response.json(data, { status, headers });
const version = { 'Tus-Resumable': '1.0.0' };

function fixture(intercept = () => undefined, sizes = [0, 7], maxPatchBytes = 3) {
  const files = sizes.map((size, i) => new File([Uint8Array.from({ length: size }, (_, n) => n + 1)], 'data-' + i + '.bin'));
  const buffers = files.map(() => []);
  const calls = [], delays = [], writes = [], displays = [];
  const offsets = files.map(() => 0);
  const store = new Map();
  let now = Date.now(), id, token, receipt, prepared;
  const localStorage = {
    getItem: key => store.get(key) ?? null,
    setItem: (key, value) => { writes.push(key); store.set(key, value); },
    removeItem: key => store.delete(key),
  };
  async function fetch(url, options) {
    const parsed = new URL(url);
    const { method, headers, signal } = options;
    assert.equal(parsed.origin, origin);
    assert.equal(options.redirect, 'error');
    assert.equal(options.mode, 'same-origin');
    assert.equal(options.credentials, 'same-origin');
    assert.equal(options.referrerPolicy, 'no-referrer');
    assert.equal(options.cache, 'no-store');
    signal?.throwIfAborted();
    const pathname = parsed.pathname;
    const call = { method, pathname, options, headers };
    calls.push(call);
    if (pathname.endsWith('/bootstrap')) {
      assert.equal(headers.has('Authorization'), false);
      return asJSON(200, { modes: ['blocks'], max_patch_bytes: maxPatchBytes, max_total_bytes: 2 ** 28 }, { 'X-CSRF-Token': 'csrf' });
    }
    assert.equal(headers.get('X-CSRF-Token'), ['GET', 'HEAD'].includes(method) ? null : 'csrf');
    if (!token) token = headers.get('Authorization');
    assert.match(token, /^Bearer [A-Za-z0-9_-]{43}$/);
    assert.equal(headers.get('Authorization'), token);
    const normal = async () => {
      if (pathname === base && method === 'POST') {
        const existing = !!id;
        id ??= headers.get('Idempotency-Key');
        assert.equal(headers.get('Idempotency-Key'), id);
        assert.match(id, /^[a-f0-9-]{36}$/);
        const manifest = JSON.parse(options.body);
        assert.equal(manifest.mode, 'blocks');
        const root = base + '/' + id;
        prepared = { id, mode: 'blocks', status_url: root, result_url: root + '/result',
          files: manifest.files.map((file, index) => ({ ...file, index, upload_url: root + '/files/' + index })) };
        return asJSON(existing ? 200 : 201, prepared);
      }
      const fileIndex = /\/files\/(\d+)$/.exec(pathname)?.[1];
      if (fileIndex != null) {
        assert.equal(headers.get('Tus-Resumable'), '1.0.0');
        if (method === 'HEAD') {
          return new Response(null, { headers: { ...version, 'Upload-Offset': offsets[fileIndex], 'Upload-Length': files[fileIndex].size } });
        }
        assert.equal(method, 'PATCH');
        assert.equal(headers.get('Content-Type'), 'application/offset+octet-stream');
        assert.equal(Number(headers.get('Upload-Offset')), offsets[fileIndex]);
        const chunk = new Uint8Array(await options.body.arrayBuffer());
        buffers[fileIndex].push(...chunk);
        offsets[fileIndex] += chunk.length;
        return new Response(null, { status: 204, headers: { ...version, 'Upload-Offset': offsets[fileIndex] } });
      }
      if (method === 'DELETE') return new Response(null, { status: 204 });
      if (pathname.endsWith('/complete')) {
        assert.deepEqual(offsets, sizes);
        receipt = 'private-confirmation-receipt';
        return asJSON(201, { confirmation_receipt: receipt });
      }
      if (pathname.endsWith('/result')) {
        return receipt ? asJSON(200, { confirmation_receipt: receipt }) : asJSON(409, { code: 'not_ready' });
      }
      return asJSON(200, { state: 'receiving', bytes: offsets.reduce((a, b) => a + b, 0),
        total: sizes.reduce((a, b) => a + b, 0), measure: 'file_bytes_confirmed' });
    };
    const response = await intercept(call, normal);
    return response === undefined ? normal() : response;
  }
  const ctx = vm.createContext({
    fetch, location: { origin, protocol: 'https:' }, Headers, URL, Blob, File, navigator: {},
    crypto: webcrypto, btoa, Uint8Array, DOMException, AbortController, localStorage,
    Date: class extends Date { static now() { return now; } },
    setTimeout(fn, ms) { delays.push(ms); return setTimeout(() => { now += ms; fn(); }, 0); }, clearTimeout,
  });
  ctx.window = ctx;
  for (const file of ['tus.min.js', 'upload-blocks-transport.js', 'upload-blocks-session.js']) {
    vm.runInContext(fs.readFileSync(path.join(scripts, file), 'utf8'), ctx, { filename: file });
  }
  const signal = new AbortController().signal;
  async function create() {
    const config = await ctx.OkuruBlockSession.bootstrap(signal);
    return new ctx.OkuruBlockSession.Session(files, { ttl_seconds: 3600, views: 2, deletable: true }, config,
      (...msg) => displays.push(msg));
  }
  return { create, calls, delays, buffers, writes, displays, signal, ctx, prepared: () => prepared };
}

test('the browser uses the chunk size advertised by the server', async () => {
  for (const limit of [1_000_000, 37_000_000, 100_000_000]) {
    const session = await fixture(undefined, [7], limit).create();
    assert.equal(session.chunkSize, limit);
  }
});

test('vendored tus uses only pre-created file resources, receives confirmed chunks, and keeps its session in memory', async () => {
  const h = fixture();
  const session = await h.create();
  assert.equal(await session.run(h.signal), 'private-confirmation-receipt');
  assert.deepEqual(h.buffers, [[], [1, 2, 3, 4, 5, 6, 7]]);
  assert.deepEqual(h.calls.map(c => c.method), ['GET', 'POST', 'HEAD', 'HEAD', 'PATCH', 'PATCH', 'PATCH', 'POST']);
  assert.deepEqual(h.calls.filter(c => c.method === 'PATCH').map(c => c.options.body.size), [3, 3, 1]);
  assert.ok(h.displays.some(([, done, total]) => done === 6 && total === 7));
  assert.ok(h.writes.every(key => key === 'tusSupport'));
});

test('lost prepare, PATCH and completion replies reuse the original session, HEAD offset and result', async () => {
  const lost = new Set();
  const h = fixture(async (c, accept) => {
    const stage = c.pathname === base ? 'prepare' : c.method === 'PATCH' ? 'patch' : c.pathname.endsWith('/complete') ? 'complete' : '';
    if (stage && !lost.has(stage)) { lost.add(stage); await accept(); throw Error('connection lost'); }
  });
  const s = await h.create();
  assert.equal(await s.run(h.signal), 'private-confirmation-receipt');
  assert.deepEqual(h.buffers[1], [1, 2, 3, 4, 5, 6, 7]);
  assert.equal(h.calls.filter(c => c.pathname.endsWith('/complete')).length, 1);
  assert.equal(h.calls.at(-1).pathname, s.path + '/result');
  assert.equal(h.calls.filter(c => c.method === 'HEAD' && c.pathname.endsWith('/1')).length, 2);
});

test('canonical prepared resources are required before sending a file or bearer to a returned path', async () => {
  for (const bad of ['https://other.example/file','//other.example/files/0','/api/v2/uploads/unrelated/files/0','/x?key=1']) {
    const h = fixture(async (c, normal) => {
      if (c.pathname !== base) return;
      const data = await (await normal()).json();
      data.files[0].upload_url = bad;
      return asJSON(201, data);
    });
    await assert.rejects((await h.create()).run(h.signal), /manifest/);
    assert.equal(h.calls.length, 2);
  }
});

test('invalid HEAD length, numeric prefix or PATCH offset is terminal', async () => {
  for (const mode of ['wrong size','partial number','wrong ack','wrong version','wrong status']) {
    const h = fixture(c => {
      if (c.method === 'HEAD' && ['wrong size','partial number','wrong version','wrong status'].includes(mode)) {
        return new Response(null, { status: mode === 'wrong status' ? 204 : 200, headers: {
          'Tus-Resumable': mode === 'wrong version' ? '0.2.1' : '1.0.0',
          'Upload-Offset': mode === 'partial number' ? '0junk' : '0', 'Upload-Length': mode === 'wrong size' ? '99' : '7' } });
      }
      if (mode === 'wrong ack' && c.method === 'PATCH') return new Response(null, { status: 204, headers: { ...version, 'Upload-Offset': '0' } });
    }, [7]);
    await assert.rejects((await h.create()).run(h.signal), /position|response/);
    assert.equal(h.delays.length, 0);
  }
});

test('413 reduces binary chunks after a new HEAD and part_limit stops immediately', async () => {
  let first = true;
  const h = fixture(c => {
    if (c.method === 'PATCH' && first) { first = false; return new Response('proxy limit', { status: 413 }); }
  }, [5]);
  await (await h.create()).run(h.signal);
  assert.deepEqual(h.calls.filter(c => c.method === 'PATCH').map(c => c.options.body.size), [3,1,1,1,1,1]);
  assert.equal(h.calls.filter(c => c.method === 'HEAD').length, 2);

  const cap = fixture(c => c.method === 'PATCH' ? asJSON(409, { code: 'part_limit' }) : undefined, [3]);
  await assert.rejects((await cap.create()).run(cap.signal), /chunk limit/);
  assert.equal(cap.delays.length, 0);
});

test('retry budget honours Retry-After, then an explicit resume or cancellation is available', async () => {
  const h = fixture(c => c.method === 'PATCH' ? asJSON(429, { code: 'busy' }, { 'Retry-After': '7' }) : undefined, [5]);
  const session = await h.create();
  await assert.rejects(session.run(h.signal), /Automatic retries stopped/);
  assert.equal(h.calls.filter(c => c.method === 'PATCH').length, 4);
  assert.deepEqual(h.delays,[7000,7000,7000]);
  await session.cancel(h.signal);
  assert.equal(h.calls.at(-1).method, 'DELETE');
});

test('an incomplete finalization checks result and status before repeating the same completion', async () => {
  let lost = true;
  const h = fixture(c => {
    if (c.pathname.endsWith('/complete') && lost) { lost = false; throw Error('connection lost'); }
  }, [1]);
  assert.equal(await (await h.create()).run(h.signal), 'private-confirmation-receipt');
  assert.deepEqual(h.calls.slice(-4).map(c => [c.method, c.pathname.split('/').at(-1)]),
    [['POST','complete'],['GET','result'],['GET',h.prepared().id],['POST','complete']]);
});

function uiFixture({ enabled = true, startFails = false, cancelBusy = false } = {}) {
  class Control extends EventTarget {
    constructor() { super(); this.hidden = true; this.disabled = false; this.value = ''; }
    focus() {}
    removeAttribute(name) { delete this[name]; }
    getAttribute() { return 'false'; }
  }
  const ids = ['upload-blocks-start','upload-blocks-cancel','upload-blocks-resume','file_create','submit',
    'upload-progress','upload-meter','upload-percent','upload-status','upload-confirmation','files','password','ttl','ttlViews','deletable'];
  const el = Object.fromEntries(ids.map(id => [id, new Control()]));
  const receipt = new Control(), csrf = new Control(), confirmation = el['upload-confirmation'];
  receipt.form = csrf.form = confirmation;
  csrf.value = 'html-csrf';
  let posts = 0, cancelled = 0, attempts = 0;
  Object.assign(confirmation, { isConnected: true, method: 'post', action: origin + '/file/confirmation',
    elements: { namedItem: key => key === 'receipt' ? receipt : csrf }, submit: () => posts++ });
  el.file_create.reportValidity = () => true;
  el.files.files = [new File(['ab'], 'sample.txt')];
  el.ttl.value = '25';
  el.ttlViews.value = '2';
  class Session {
    constructor(files, options, config, display) {
      assert.equal(files[0].name, 'sample.txt');
      assert.equal(options.ttl_seconds, 172800);
      assert.equal(options.views, 2);
      this.display = display;
      this.total = 2;
      this.phase = 'send';
    }
    async run() {
      attempts++;
      if (startFails && attempts === 1) throw Object.assign(new Error('Paused'), { transient: true });
      this.phase = 'done';
      return 'receipt-for-test';
    }
    async cancel() { cancelled++; if (cancelBusy) throw Object.assign(new Error("Busy"), { status: 409 }); }
  }
  const win = Object.assign(new EventTarget(), { location: { origin, protocol: 'https:' }, AbortController,
    fetch() {}, crypto: webcrypto, tus: { Upload: class {} }, OkuruBlockSession: { Session,
      async bootstrap() { if (!enabled) throw Error('closed'); return { csrf: 'upload-csrf' }; } } });
  const ctx = { window: win, document: { getElementById: id => el[id] }, AbortController, Event,
    MutationObserver: class { observe() {} } };
  vm.runInNewContext(fs.readFileSync(path.join(scripts, 'upload-blocks.js'), 'utf8'), ctx);
  return { el, win, receipt, click: id => el[id].dispatchEvent(new Event('click')), posts: () => posts, cancelled: () => cancelled };
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test('resumable control is offered only for an open mode and the regular submit remains available', async () => {
  const ui = uiFixture({ enabled: false });
  await settle();
  assert.equal(ui.el['upload-blocks-start'].hidden, true);
  assert.equal(ui.el.submit.disabled, false);
  assert.equal(ui.el.file_create.dispatchEvent(new Event('submit', { cancelable: true })), true);
});

test('an explicit retry opens the historical confirmation once with the returned receipt', async () => {
  const ui = uiFixture({ startFails: true });
  await settle();
  assert.equal(ui.el['upload-blocks-start'].hidden, false);
  ui.click('upload-blocks-start');
  await settle();
  assert.equal(ui.el.submit.disabled, true);
  assert.equal(ui.el.file_create.dispatchEvent(new Event('submit', { cancelable: true })), false);
  assert.equal(ui.el['upload-blocks-resume'].hidden, false);
  ui.click('upload-blocks-resume');
  await settle();
  assert.equal(ui.receipt.value, 'receipt-for-test');
  assert.equal(ui.posts(), 1);
});

test('explicit cancellation unlocks both the regular form and a fresh selection', async () => {
  const ui = uiFixture({ startFails: true });
  await settle();
  ui.click('upload-blocks-start');
  await settle();
  ui.click('upload-blocks-cancel');
  await settle();
  assert.equal(ui.cancelled(), 1);
  assert.equal(ui.el.submit.disabled, false);
  assert.equal(ui.el['upload-blocks-start'].hidden, false);
  assert.equal(ui.posts(), 0);
  assert.equal(ui.receipt.value, '');
});

test('empty files can complete from open after the first completion request did not reach the server', async () => {
  let dropped = false;
  const h = fixture(c => {
    if (c.pathname.endsWith('/complete') && !dropped) { dropped = true; throw Error('request lost'); }
    if (c.method === 'GET' && c.pathname !== base + '/bootstrap' && !c.pathname.endsWith('/result')) {
      return asJSON(200, { state: 'open', measure: 'file_bytes_confirmed', bytes: 0, total: 0 });
    }
  }, [0, 0]);
  const session = await h.create();
  assert.equal(await session.run(h.signal), 'private-confirmation-receipt');
  assert.equal(h.calls.some(c => c.method === 'PATCH'), false);
  assert.deepEqual(h.calls.slice(-4).map(c => [c.method, c.pathname]),
    [['POST', session.path + '/complete'], ['GET', session.path + '/result'], ['GET', session.path], ['POST', session.path + '/complete']]);
});

test('a busy cancellation during PATCH keeps the upload resumable unless publication is confirmed', async () => {
  for (const state of ['receiving', 'finalizing', 'ready']) {
    let patchStarted;
    const started = new Promise(resolve => { patchStarted = resolve; });
    let firstPatch = true;
    const h = fixture(async c => {
      if (c.method === 'PATCH' && firstPatch) {
        firstPatch = false;
        patchStarted();
        await new Promise((_, reject) => c.options.signal.addEventListener('abort', () => reject(Error('cancelled')), { once: true }));
      }
      if (c.method === 'DELETE') return asJSON(409, { code: 'busy' });
      if (c.method === 'GET' && !c.pathname.endsWith('/bootstrap')) {
        return asJSON(200, { state, measure: 'file_bytes_confirmed', bytes: 0, total: 2 });
      }
    }, [2]);
    const current = await h.create();
    const controller = new AbortController();
    const interrupted = assert.rejects(current.run(controller.signal), { name: 'AbortError' });
    await started;
    controller.abort();
    await interrupted;
    await assert.rejects(current.cancel(h.signal), { status: 409 });
    assert.equal(current.phase, state === 'receiving' ? 'send' : 'recover');
    if (state === 'receiving') {
      assert.equal(await current.run(h.signal), 'private-confirmation-receipt');
      assert.deepEqual(h.buffers[0], [1, 2]);
    }
  }
  const ui = uiFixture({ startFails: true, cancelBusy: true });
  await settle();
  ui.click('upload-blocks-start');
  await settle();
  ui.click('upload-blocks-cancel');
  await settle();
  assert.equal(ui.el['upload-blocks-resume'].hidden, false);
  assert.equal(ui.el['upload-blocks-resume'].textContent, 'Resume upload');
  assert.equal(ui.el['upload-blocks-cancel'].hidden, false);
  ui.click('upload-blocks-resume');
  await settle();
  assert.equal(ui.posts(), 1);
});
