const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { TextEncoder } = require('node:util');

function makeForm() {
  const handlers = {};
  const elements = {};
  const timers = new Map();
  const navigations = [];
  let nextTimer = 0;
  for (const id of ['ttl', 'ttl-value', 'ttlViews', 'ttlViews-value', 'files', 'files-label-word', 'file-selection-error', 'file_create']) {
    elements[id] = {
      value: '1', files: [], attributes: {},
      addEventListener(type, fn) { handlers[`${id}:${type}`] = fn; },
      setAttribute(name, value) { this.attributes[name] = value; },
      getAttribute(name) { return this.attributes[name]; },
      focus() { this.focused = true; }
    };
  }
  const error = elements['file-selection-error'];
  const source = fs.readFileSync(path.join(__dirname, '../views/index_file.html'), 'utf8');
  const script = source.match(/<script\b(?=[^>]*\btype="application\/javascript")[^>]*>([\s\S]*?)<\/script>/)[1]
    .replace('{{ maxFileSize }}', '1048576');
  vm.runInNewContext(script, {
    TextEncoder, DOMPurify: { sanitize: value => value },
    setTimeout(fn, ms) { timers.set(++nextTimer, { fn, ms }); return nextTimer; },
    clearTimeout(id) { timers.delete(id); },
    window: {
      location: { replace: url => navigations.push(url) },
      addEventListener(type, fn) { handlers[`window:${type}`] = fn; }
    },
    document: { getElementById: id => elements[id] }
  });
  return { elements, error, handlers, timers, navigations };
}

function runSelection(form, files) {
  form.elements.files.files = files.map(([name, size = 1]) => ({ name, size }));
  form.handlers['files:change']();
  let prevented = false;
  form.handlers['file_create:submit']({ preventDefault() { prevented = true; } });
  return { message: form.error.textContent, prevented };
}

test('the file label follows selection, page restoration and form reset', () => {
  const form = makeForm();
  const word = form.elements['files-label-word'];
  form.handlers['window:pageshow']({ persisted: false });
  assert.equal(word.textContent, 'File');
  runSelection(form, [['one'], ['two']]);
  assert.equal(word.textContent, 'Files');
  runSelection(form, [['one']]);
  assert.equal(word.textContent, 'File');
  runSelection(form, []);
  assert.equal(word.textContent, 'File');
  form.elements.files.files = [{ name: 'one' }, { name: 'two' }];
  form.handlers['window:pageshow']({ persisted: true });
  assert.equal(word.textContent, 'Files');
  form.handlers['file_create:reset']();
  form.elements.files.files = [];
  for (const timer of form.timers.values()) {
    if (timer.ms === 0) timer.fn();
  }
  assert.equal(word.textContent, 'File');
});

test('blocks invalid and duplicate names before submitting, and permits correction', () => {
  const form = makeForm();
  assert.match(runSelection(form, [['bad?.txt']]).message, /Invalid file name/);
  assert.equal(runSelection(form, [['bad?.txt']]).prevented, true);
  assert.equal(form.elements.files.attributes['aria-invalid'], 'true');
  assert.equal(form.elements.files.attributes['aria-describedby'], 'files-help file-selection-error');
  assert.match(runSelection(form, [['A.txt'], ['a.txt']]).message, /Duplicate/);
  assert.match(runSelection(form, [['é.txt'], ['e\u0301.txt']]).message, /Duplicate/);
  assert.match(runSelection(form, [['É.txt'], ['é.txt']]).message, /Duplicate/);
  assert.match(runSelection(form, [['Straße.txt'], ['STRASSE.txt']]).message, /Duplicate/);
  assert.match(runSelection(form, [['CON.txt']]).message, /Invalid/);
  assert.match(runSelection(form, [['CON .txt']]).message, /Invalid/);
  assert.match(runSelection(form, [['../bad.txt']]).message, /Invalid/);
  assert.match(runSelection(form, [['\u202ebad.txt']]).message, /Invalid/);
  assert.equal(runSelection(form, [['rapport+é & # 😀.txt']]).prevented, false);
  assert.equal(runSelection(form, [['rapport..txt']]).message, '');
  assert.equal(form.elements.files.attributes['aria-invalid'], 'false');
  assert.equal(form.elements.files.attributes['aria-describedby'], 'files-help');
});

test('only count and size limits schedule a single return to the upload page after three seconds', () => {
  const form = makeForm();
  assert.match(runSelection(form, []).message, /Select at least one/);
  assert.equal(form.timers.size, 0);
  const hundred = Array.from({ length: 100 }, (_, i) => [`${i}.txt`]);
  assert.equal(runSelection(form, hundred).prevented, false);
  assert.equal(runSelection(form, [['a.txt', 1048576]]).prevented, false);
  assert.equal(form.timers.size, 0);
  for (const [files, limit] of [
    [[...hundred, ['extra']], /100 files/],
    [[['one', 1048577]], /maximum/],
    [[['a.txt', 600000], ['b.txt', 600000]], /maximum/]
  ]) {
    const result = runSelection(form, files);
    assert.equal(result.prevented, true);
    assert.match(result.message, limit);
    assert.doesNotMatch(result.message, /Returning to the upload form/);
    assert.equal(form.timers.size, 1);
    const [timer] = form.timers.values();
    assert.equal(timer.ms, 3000);
    timer.fn();
    assert.deepEqual(form.navigations.splice(0), ['/file']);
  }
});

test('correcting the selection, resetting the form or leaving the page cancels the return', () => {
  const form = makeForm();
  const tooLarge = [['one', 1048577]];
  runSelection(form, tooLarge);
  assert.equal(runSelection(form, [['one', 1]]).prevented, false);
  assert.equal(form.timers.size, 0);
  runSelection(form, tooLarge);
  form.handlers['file_create:reset']();
  assert.equal(form.error.textContent, '');
  assert.equal([...form.timers.values()].some(timer => timer.ms === 3000), false);
  runSelection(form, tooLarge);
  form.handlers['window:pagehide']();
  assert.equal([...form.timers.values()].some(timer => timer.ms === 3000), false);
  assert.deepEqual(form.navigations, []);
});

test('a server selection limit uses the same alert and timer until the files change', () => {
  const form = makeForm();
  assert.equal(runSelection(form, [['a.txt', 1000]]).prevented, false);
  let handled = false;
  form.handlers['file_create:file-selection-limit']({
    detail: 'The upload exceeds the size limit.', preventDefault() { handled = true; }
  });
  assert.equal(handled, true);
  assert.match(form.error.textContent, /^🚫 The upload exceeds the size limit\.$/);
  assert.equal(form.elements.files.attributes['aria-invalid'], 'true');
  let prevented = false;
  form.handlers['file_create:submit']({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(form.timers.size, 1);
  form.handlers['window:pagehide']();
  assert.equal(form.timers.size, 0);
  form.handlers['window:pageshow']({ persisted: true });
  assert.equal(form.timers.size, 1);
  const [timer] = form.timers.values();
  assert.equal(timer.ms, 3000);
  timer.fn();
  assert.deepEqual(form.navigations, ['/file']);
  assert.equal(runSelection(form, [['b.txt', 100]]).prevented, false);
  assert.equal(form.timers.size, 0);
  assert.equal(form.error.textContent, '');
});

test('displays an unsafe filename as text, never markup', () => {
  const form = makeForm();
  const result = runSelection(form, [['<img src=x onerror=alert(1)>.txt']]);
  assert.equal(result.prevented, true);
  assert.match(form.error.textContent, /<img/);
  assert.equal(form.error.innerHTML, undefined);
});

test('inline server errors preserve the selected files and allow resubmission or correction', () => {
  for (const [code, fieldInvalid] of [
    ['file_name_error', 'true'],
    ['form_verification_failed', 'false'],
  ]) {
    const form = makeForm();
    assert.equal(runSelection(form, [['a.txt']]).prevented, false);
    const files = form.elements.files;
    const selection = files.files;
    const reject = () => {
      let handled = false;
      form.handlers['file_create:file-upload-error']({
        detail: { code, message: '<server rejected this upload>' }, preventDefault() { handled = true; },
      });
      assert.equal(handled, true);
      assert.equal(form.error.textContent, '🚫 <server rejected this upload>');
      assert.equal(form.error.innerHTML, undefined);
      assert.equal(files.attributes['aria-invalid'], fieldInvalid);
      assert.equal(files.files, selection);
      assert.equal(form.timers.size, 0);
      assert.deepEqual(form.navigations, []);
    };
    reject();
    let prevented = false;
    form.handlers['file_create:submit']({ preventDefault() { prevented = true; } });
    assert.equal(prevented, false);
    assert.equal(form.error.textContent, '');
    reject();
    runSelection(form, [['corrected.txt']]);
    assert.equal(form.error.textContent, '');
    assert.equal(files.attributes['aria-invalid'], 'false');
  }
});
