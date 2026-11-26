'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.join(__dirname, '..');
const deployment = path.join(root, 'deploy', 'systemd');
const unit = fs.readFileSync(path.join(root, 'okuru.service'), 'utf8');
const tmpfiles = fs.readFileSync(path.join(deployment, 'okuru-log.conf'), 'utf8');
const check = unit.match(/^ExecStartPre=\/bin\/sh -c '([^']+)'$/m)?.[1];
const tmpfilesExecutable = '/usr/bin/systemd-tmpfiles';

test('the unprivileged log check has valid shell syntax', () => {
  assert.ok(check);
  const result = spawnSync('/bin/sh', ['-n', '-c', check], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('tmpfiles initialization preserves an existing file and rejects symlinks', {
  skip: process.platform !== 'linux' || !fs.existsSync(tmpfilesExecutable),
}, t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'okuru-log-init-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'okuru.log');
  const config = path.join(directory, 'okuru-log.conf');
  // Apply the deployed rule to a test-owned path with the test account.
  assert.match(file, /^\/[A-Za-z0-9/_.-]+$/);
  fs.writeFileSync(config, tmpfiles.replace('/var/log/okuru.log', file)
    .replace(':freebox :freebox', `:${process.getuid()} :${process.getgid()}`));
  const prepare = () => spawnSync(tmpfilesExecutable, ['--create', config], { encoding: 'utf8' });
  const validate = () => spawnSync('/bin/sh', ['-c', check.replaceAll('/var/log/okuru.log', file)], {
    encoding: 'utf8',
  });

  assert.notEqual(validate().status, 0);
  let result = prepare();
  assert.equal(result.status, 0, result.stderr);
  const created = fs.statSync(file);
  assert.equal(created.mode & 0o777, 0o640);
  assert.equal(validate().status, 0);

  fs.writeFileSync(file, 'existing log\n');
  fs.chmodSync(file, 0o600);
  result = prepare();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.readFileSync(file, 'utf8'), 'existing log\n');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);

  const target = path.join(directory, 'target');
  fs.writeFileSync(target, 'untouched\n');
  fs.unlinkSync(file);
  fs.symlinkSync(target, file);
  prepare(); // Refusal or safe no-op are both acceptable.
  assert.equal(fs.lstatSync(file).isSymbolicLink(), true);
  assert.equal(fs.readFileSync(target, 'utf8'), 'untouched\n');
  assert.notEqual(validate().status, 0);
});
