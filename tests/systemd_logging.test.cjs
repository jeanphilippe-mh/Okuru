'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');

function settings(filename, section) {
  const input = fs.readFileSync(path.join(root, filename), 'utf8');
  const values = new Map();
  let active = false;
  for (const raw of input.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    if (line.startsWith('[') && line.endsWith(']')) {
      active = line === `[${section}]`;
      continue;
    }
    if (!active) continue;
    const equals = line.indexOf('=');
    assert.notEqual(equals, -1, `invalid setting: ${line}`);
    values.set(line.slice(0, equals).trim(), line.slice(equals + 1).trim());
  }
  return values;
}

function bytes(value) {
  const match = /^(\d+)([KMG])$/.exec(value || '');
  assert.ok(match, `expected a finite byte size: ${value}`);
  return Number(match[1]) * ({ K: 1024, M: 1024 ** 2, G: 1024 ** 3 }[match[2]]);
}

test('service logs use the bounded dedicated journald namespace', () => {
  const unit = settings('okuru.service', 'Service');
  const namespace = unit.get('LogNamespace');
  assert.equal(namespace, 'okuru');
  assert.equal(unit.get('StandardOutput'), 'journal');
  assert.equal(unit.get('StandardError'), 'journal');
  assert.match(unit.get('LogRateLimitIntervalSec') || '', /^[1-9]\d*(s|min|h)$/);
  assert.match(unit.get('LogRateLimitBurst') || '', /^[1-9]\d*$/);

  const conf = settings(`deploy/systemd/journald@${namespace}.conf.d/20-retention.conf`, 'Journal');
  assert.equal(conf.get('Storage'), 'persistent');
  const diskLimit = bytes(conf.get('SystemMaxUse'));
  const runtimeLimit = bytes(conf.get('RuntimeMaxUse'));
  assert.ok(diskLimit > 0 && diskLimit <= 128 * 1024 ** 2);
  assert.ok(runtimeLimit > 0 && runtimeLimit <= 32 * 1024 ** 2);
  assert.ok(bytes(conf.get('SystemMaxFileSize')) < diskLimit);
  assert.ok(bytes(conf.get('RuntimeMaxFileSize')) < runtimeLimit);
  assert.match(conf.get('MaxRetentionSec') || '', /^[1-9]\d*(day|week|month)$/);
});
