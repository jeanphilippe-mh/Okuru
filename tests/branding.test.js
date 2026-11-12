const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
const publicDir = path.join(root, 'public');
const html = fs.readFileSync(path.join(root, 'views/base.html'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(publicDir, 'manifest.webmanifest'), 'utf8'));
const getMeta = (property) => [...html.matchAll(/<meta\s+([^>]+)>/g)].map((m) => Object.fromEntries([...m[1].matchAll(/([\w:-]+)="([^"]*)"/g)].map((a) => [a[1], a[2]]))).filter((m) => m.property === property || m.name === property).map((m) => m.content);
function pngSize(file) {
  const bytes = fs.readFileSync(path.join(publicDir, file));
  assert.equal(bytes.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
  return [bytes.readUInt32BE(16), bytes.readUInt32BE(20)];
}
test('social metadata uses one shared English preview', () => {
  const og = getMeta('og:image');
  assert.deepEqual(og, ['https://share.jeanphilippe.io/images/okuru-preview-en@2x.png']);
  assert.deepEqual(getMeta('twitter:image'), og);
  assert.deepEqual(getMeta('og:image:width'), ['2400']);
  assert.deepEqual(getMeta('og:image:height'), ['1260']);
  assert.deepEqual(getMeta('description'), getMeta('og:description'));
  assert.deepEqual(getMeta('description'), getMeta('twitter:description'));
  assert.deepEqual(getMeta('og:image:type'), ['image/png']);
  assert.deepEqual(pngSize('images/okuru-preview-en@2x.png'), [2400, 1260]);
  assert.equal(fs.existsSync(path.join(publicDir, 'images/okuru-preview-en.jpg')), true);
});
test('manifest and links resolve to real assets with the declared icon dimensions', () => {
  for (const icon of manifest.icons) {
    const size = Number(icon.sizes.split('x')[0]);
    assert.deepEqual(pngSize(icon.src.slice(1)), [size, size]);
  }
  for (const [name, size] of [['images/apple-touch-icon.png', 180], ['images/apple-touch-icon@2x.png', 360], ['images/icon-192@2x.png', 384], ['images/icon-512@2x.png', 1024], ['images/logo.png', 45], ['images/logo@2x.png', 90]]) {
    assert.deepEqual(pngSize(name), [size, size]);
  }
  for (const match of html.matchAll(/(?:href|src)="(\/(?:images|css|scripts)\/[^" ]+|\/favicon\.ico|\/manifest\.webmanifest)"/g)) {
    assert.ok(fs.existsSync(path.join(publicDir, match[1])), match[1]);
  }
  const ico = fs.readFileSync(path.join(publicDir, 'favicon.ico'));
  assert.equal(ico.readUInt16LE(2), 1);
  assert.equal(ico.readUInt16LE(4), 4);
  assert.deepEqual([0, 1, 2, 3].map((i) => ico[6 + i * 16] || 256), [16, 32, 48, 256]);
});
test('robots policy retains the original disallow-all rule', () => {
  const robots = fs.readFileSync(path.join(publicDir, 'robots.txt'), 'utf8');
  assert.equal(robots.replace(/\r\n/g, '\n').trim(), 'User-agent: *\nDisallow: /');
});
