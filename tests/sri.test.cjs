const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const views = path.join(root, 'views');
const publicDir = path.join(root, 'public');

function templateFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const filename = path.join(dir, entry.name);
    if (entry.isDirectory()) return templateFiles(filename);
    return entry.isFile() && entry.name.endsWith('.html') ? [filename] : [];
  });
}

function attributes(tag, label) {
  const result = new Map();
  const pattern = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  for (const match of tag.matchAll(pattern)) {
    const name = match[1].toLowerCase();
    assert.ok(!result.has(name), `${label}: duplicate ${name} attribute`);
    result.set(name, match[2] ?? match[3] ?? match[4] ?? '');
  }
  return result;
}

test('every script loaded by a template has a nonce and matches its local SHA-512 integrity', () => {
  let count = 0;
  for (const file of templateFiles(views)) {
    const label = path.relative(root, file);
    const source = fs.readFileSync(file, 'utf8');
    // Quotes can contain >, so do not terminate an opening tag inside one.
    const scripts = /<script\b((?:"[^"]*"|'[^']*'|[^'">])*)>/gi;
    for (const match of source.matchAll(scripts)) {
      const attrs = attributes(match[1], label);
      if (!attrs.has('src')) continue;
      count++;
      const src = attrs.get('src');
      assert.match(src, /^\/?scripts\/[a-zA-Z0-9_.-]+\.js$/, `${label}: unexpected script source ${src}`);
      assert.equal(attrs.get('nonce'), '{{ csp_nonce }}', `${label}: missing per-response nonce for ${src}`);
      const filename = path.join(publicDir, src.replace(/^\//, ''));
      assert.ok(fs.statSync(filename).isFile(), `${label}: ${src} is not a file`);
      const digest = createHash('sha512').update(fs.readFileSync(filename)).digest('base64');
      assert.equal(attrs.get('integrity'), `sha512-${digest}`, `${label}: integrity does not match ${src}`);
    }
  }
  assert.ok(count > 0, 'no external script tags were checked');
});
