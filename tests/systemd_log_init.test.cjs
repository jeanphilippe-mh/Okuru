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
const initializer = fs.readFileSync(path.join(deployment, 'okuru-log-init.service'), 'utf8');
const tmpfiles = fs.readFileSync(path.join(deployment, 'okuru-log.conf'), 'utf8');
const rule = tmpfiles.split(/\r?\n/).filter(line => line.trim() && !line.trimStart().startsWith('#'));
const check = unit.match(/^ExecStartPre=\/bin\/sh -c '([^']+)'$/m)?.[1];
const tmpfilesExecutable = '/usr/bin/systemd-tmpfiles';

test('log initialization is isolated from the application environment', () => {
  assert.match(unit, /^Requires=okuru-log-init\.service$/m);
  assert.match(unit, /^After=okuru-log-init\.service$/m);
  assert.match(unit, /^User=freebox$/m);
  assert.doesNotMatch(unit, /^Exec\w+=\s*[-:@|]*[+!]/m);
  assert.doesNotMatch(unit, /systemd-tmpfiles/);

  assert.match(initializer, /^Type=oneshot$/m);
  assert.match(initializer, /^User=root$/m);
  assert.match(initializer, /^ProtectHome=true$/m);
  assert.doesNotMatch(initializer, /^(?:Environment(?:File)?|PassEnvironment|WorkingDirectory)=/m);
  assert.deepEqual(initializer.match(/^Exec\w+=.*$/gm), [
    `ExecStart=${tmpfilesExecutable} --create /etc/tmpfiles.d/okuru-log.conf`,
  ]);
  assert.deepEqual(rule, ['f /var/log/okuru.log :0640 :freebox :freebox - -']);
});

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
  assert.equal(created.uid, process.getuid());
  assert.equal(created.gid, process.getgid());
  assert.equal(validate().status, 0);

  fs.writeFileSync(file, 'existing log\n');
  fs.chmodSync(file, 0o600);
  result = prepare();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.readFileSync(file, 'utf8'), 'existing log\n');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(file).ino, created.ino);

  const target = path.join(directory, 'target');
  fs.writeFileSync(target, 'untouched\n');
  fs.unlinkSync(file);
  fs.symlinkSync(target, file);
  prepare(); // Refusal or safe no-op are both acceptable.
  assert.equal(fs.lstatSync(file).isSymbolicLink(), true);
  assert.equal(fs.readFileSync(target, 'utf8'), 'untouched\n');
  assert.notEqual(validate().status, 0);
});
