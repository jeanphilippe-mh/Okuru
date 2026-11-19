const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { TextEncoder } = require('node:util');

function makeForm() {
  const handlers = {};
  const elements = {};
  for (const id of ['ttl', 'ttl-value', 'ttlViews', 'ttlViews-value', 'files', 'files-label-word', 'file_create']) {
    elements[id] = {
      value: '1', files: [], attributes: {},
      addEventListener(type, fn) { handlers[`${id}:${type}`] = fn; },
      setAttribute(name, value) { this.attributes[name] = value; },
      focus() { this.focused = true; }
    };
  }
  const error = { textContent: '' };
  const source = fs.readFileSync(path.join(__dirname, '../views/index_file.html'), 'utf8');
  const script = source.match(/<script\b(?=[^>]*\btype="application\/javascript")[^>]*>([\s\S]*?)<\/script>/)[1]
    .replace('{{ maxFileSize }}', '1048576');
  vm.runInNewContext(script, {
    TextEncoder, setTimeout, DOMPurify: { sanitize: value => value },
    window: { addEventListener(type, fn) { handlers[`window:${type}`] = fn; } },
    document: { getElementById: id => elements[id], querySelector: () => error }
  });
  return { elements, error, handlers };
}

function runSelection(form, files) {
  form.elements.files.files = files.map(([name, size = 1]) => ({ name, size }));
  form.handlers['files:change']();
  let prevented = false;
  form.handlers['file_create:submit']({ preventDefault() { prevented = true; } });
  return { message: form.error.textContent, prevented };
}

test('the file label follows selection, page restoration and form reset', async () => {
  const form = makeForm();
  const word = form.elements['files-label-word'];
  form.handlers['window:pageshow']();
  assert.equal(word.textContent, 'File');
  runSelection(form, [['one'], ['two']]);
  assert.equal(word.textContent, 'Files');
  runSelection(form, [['one']]);
  assert.equal(word.textContent, 'File');
  runSelection(form, []);
  assert.equal(word.textContent, 'File');
  form.elements.files.files = [{ name: 'one' }, { name: 'two' }];
  form.handlers['window:pageshow']();
  assert.equal(word.textContent, 'Files');
  form.handlers['file_create:reset']();
  form.elements.files.files = [];
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(word.textContent, 'File');
});

test('blocks invalid and duplicate names before submitting, and permits correction', () => {
  const form = makeForm();
  assert.match(runSelection(form, [['bad?.txt']]).message, /Invalid file name/);
  assert.equal(runSelection(form, [['bad?.txt']]).prevented, true);
  assert.equal(form.elements.files.attributes['aria-invalid'], 'true');
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
});

test('blocks empty, excessive and oversized selections without reloading', () => {
  const form = makeForm();
  assert.match(runSelection(form, []).message, /Select at least one/);
  assert.match(runSelection(form, Array.from({ length: 101 }, (_, i) => [`${i}.txt`])).message, /100 files/);
  assert.match(runSelection(form, [['a.txt', 600000], ['b.txt', 600000]]).message, /maximum/);
  assert.equal(runSelection(form, [['a.txt', 1048576]]).prevented, false);
});

test('displays an unsafe filename as text, never markup', () => {
  const form = makeForm();
  const result = runSelection(form, [['<img src=x onerror=alert(1)>.txt']]);
  assert.equal(result.prevented, true);
  assert.match(form.error.textContent, /<img/);
  assert.equal(form.error.innerHTML, undefined);
});
