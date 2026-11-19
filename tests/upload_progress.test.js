const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const script = fs.readFileSync(path.join(__dirname, '../public/scripts/upload-progress.js'), 'utf8');
const endpoint = 'https://share.example/file';

function browser({ validationFails = false, formDataSupported = true, uploadSupported = true } = {}) {
  const form = new EventTarget();
  const files = { files: [] };
  form.addEventListener('submit', (event) => { if (validationFails) event.preventDefault(); });
  const receipt = { value: '' };
  const csrf = { value: 'test-csrf' };
  const confirmations = [];
  const confirmation = {
    isConnected: true, action: endpoint + '/confirmation', method: 'post',
    elements: { namedItem: (name) => ({ receipt, _csrf: csrf })[name] },
    submit() { confirmations.push(receipt.value); },
  };
  csrf.form = receipt.form = confirmation;
  const button = { form, disabled: false };
  const panel = { hidden: true };
  const meter = { removeAttribute(name) { delete this[name]; } };
  const status = { textContent: '' };
  const percent = { textContent: '' };
  const elements = {
    file_create: form, files, submit: button, 'upload-progress': panel, 'upload-meter': meter,
    'upload-status': status, 'upload-percent': percent, 'upload-confirmation': confirmation,
  };
  const requests = [];
  class Request {
    constructor() {
      this.upload = uploadSupported ? { onprogress: null } : null;
      requests.push(this);
    }
    open(method, url) { this.method = method; this.url = url; this.responseURL = url; }
    setRequestHeader(name, value) { this[name] = value; }
    send(body) { this.body = body; }
    abort() { this.onabort(); }
    respond(status, response) { this.status = status; this.response = response; this.onload(); }
  }
  const window = Object.assign(new EventTarget(), {
    location: { origin: 'https://share.example' }, XMLHttpRequest: Request,
    FormData: formDataSupported ? class { constructor(source) { this.source = source; } } : undefined,
  });
  class CustomEvent extends Event {
    constructor(type, init) { super(type, init); this.detail = init.detail; }
  }
  vm.runInNewContext(script, { window, CustomEvent, document: { getElementById: (id) => elements[id] } });
  return {
    form, files, button, panel, meter, status, percent, receipt, csrf, confirmation, confirmations, requests,
    submit: () => form.dispatchEvent(new Event('submit', { cancelable: true })),
    restore: () => window.dispatchEvent(Object.assign(new Event('pageshow'), { persisted: true })),
  };
}

test('sends the existing multipart form once and opens the confirmation only after a receipt', () => {
  const page = browser();
  assert.equal(page.submit(), false);
  const [request] = page.requests;
  assert.equal(request.method, 'POST');
  assert.equal(request.url, endpoint);
  assert.equal(request.Accept, 'application/json');
  assert.equal(request.responseType, 'json');
  assert.equal(request.body.source, page.form);
  assert.equal(page.button.disabled, true);
  assert.equal(page.panel.hidden, false);
  assert.equal(page.status.textContent, 'Uploading files…');
  assert.equal(page.meter.value, undefined);

  request.upload.onprogress({ lengthComputable: true, loaded: 239, total: 400 });
  assert.equal(page.meter.value, 59);
  assert.equal(page.percent.textContent, '59%');
  request.upload.onprogress({ lengthComputable: true, loaded: 399, total: 400 });
  assert.equal(page.percent.textContent, '99%');
  request.upload.onload({ lengthComputable: true, loaded: 402, total: 400 });
  assert.equal(page.meter.value, 100);
  assert.equal(page.percent.textContent, '100%');
  assert.equal(page.status.textContent, 'Preparing your secure link…');
  assert.deepEqual(page.confirmations, []);
  assert.equal(page.submit(), false);
  assert.equal(page.requests.length, 1);
  request.respond(201, { receipt: 'test-receipt' });
  assert.deepEqual(page.confirmations, ['test-receipt']);
  assert.equal(page.submit(), false);
  assert.equal(page.requests.length, 1);
  page.restore();
  assert.equal(page.receipt.value, '');
  assert.equal(page.button.disabled, false);
  assert.equal(page.panel.hidden, true);
});

test('uses indeterminate progress without a reliable byte count', () => {
  const page = browser();
  page.submit();
  const [request] = page.requests;
  for (const progress of [{ lengthComputable: false, loaded: 20, total: 100 },
    { lengthComputable: true, loaded: 0, total: 0 }, { lengthComputable: true, loaded: NaN, total: 10 }]) {
    request.upload.onprogress(progress);
    assert.equal(page.meter.value, undefined);
    assert.equal(page.percent.textContent, '');
  }
  request.upload.onload({ lengthComputable: false, loaded: 0, total: 0 });
  assert.equal(page.status.textContent, 'Preparing your secure link…');
  assert.deepEqual(page.confirmations, []);
});

test('preserves earlier validation and native submission when enhancement is unavailable', () => {
  const invalid = browser({ validationFails: true });
  assert.equal(invalid.submit(), false);
  assert.equal(invalid.requests.length, 0);
  const missingToken = browser();
  missingToken.csrf.value = '';
  for (const page of [browser({ uploadSupported: false }), browser({ formDataSupported: false }), missingToken]) {
    assert.equal(page.submit(), true);
    assert.equal(page.button.disabled, false);
    assert.ok(page.requests.every((request) => !request.body));
  }
});

test('shows failures as text, stops progress and lets the user explicitly resubmit', () => {
  const cases = [
    [(request) => request.respond(400, { error: '<invalid name>' }), '<invalid name>'],
    [(request) => request.respond(413, null), /HTTP 413/],
    [(request) => request.respond(200, {}), /response/],
    [(request) => request.respond(200, { receipt: '  ' }), /response/],
    [(request) => { request.responseURL += '/other'; request.respond(200, { receipt: 'unused' }); }, /response/],
    [(request) => request.onerror(), /interrupted/],
    [(request) => request.ontimeout(), /interrupted/],
    [(request) => request.abort(), /interrupted/],
    [(request, page) => {
      page.confirmation.action = 'https://other.example/';
      request.respond(200, { receipt: 'unused' });
    }, /response/],
  ];
  for (const [reject, message] of cases) {
    const page = browser();
    page.submit();
    reject(page.requests[0], page);
    if (typeof message === 'string') assert.equal(page.status.textContent, message);
    else assert.match(page.status.textContent, message);
    assert.equal(page.button.disabled, false);
    assert.equal(page.meter.hidden, true);
    assert.equal(page.panel.hidden, false);
    assert.equal(page.receipt.value, '');
    assert.deepEqual(page.confirmations, []);
    assert.equal(page.requests.length, 1);
  }
  const page = browser();
  page.submit();
  page.requests[0].respond(503, null);
  page.submit();
  assert.equal(page.requests.length, 2);
  assert.equal(page.meter.hidden, false);
  page.restore();
  page.submit();
  assert.equal(page.requests.length, 3);
  page.requests[1].respond(200, { receipt: 'stale' });
  assert.deepEqual(page.confirmations, []);
});

test('only a selection-limit response for the submitted files activates the form warning', () => {
  for (const [status, code, changed, redirected, handled] of [
    [400, 'file_selection_limit', false, false, true],
    [413, 'file_selection_limit', false, false, true],
    [413, undefined, false, false, false],
    [400, 'invalid_name', false, false, false],
    [403, 'file_selection_limit', false, false, false],
    [413, 'file_selection_limit', true, false, false],
    [413, 'file_selection_limit', false, true, false]
  ]) {
    const page = browser();
    const warnings = [];
    page.form.addEventListener('file-selection-limit', event => {
      warnings.push(event.detail);
      event.preventDefault();
    });
    page.submit();
    if (changed) page.files.files = [];
    if (redirected) page.requests[0].responseURL += '/other';
    page.requests[0].respond(status, { code, error: 'Selection rejected.' });
    assert.deepEqual(warnings, handled ? ['Selection rejected.'] : []);
    assert.equal(page.panel.hidden, handled);
    assert.equal(page.button.disabled, false);
  }
});
