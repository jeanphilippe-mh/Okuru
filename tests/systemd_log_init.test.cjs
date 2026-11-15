'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const unit = fs.readFileSync(path.join(__dirname, '..', 'okuru.service'), 'utf8');
const startLines = unit.split(/\r?\n/).filter(line => line.startsWith('ExecStartPre='));
const prep = startLines.find(line => line.startsWith("ExecStartPre=+/bin/sh -c '"));
const check = startLines.find(line => line.startsWith("ExecStartPre=/bin/sh -c '"));

function shellArgument(line, prefix) {
  assert.ok(line?.startsWith(prefix) && line.endsWith("'"));
  return line.slice(prefix.length, -1);
}

const prepCommand = shellArgument(prep, "ExecStartPre=+/bin/sh -c '");
const checkCommand = shellArgument(check, "ExecStartPre=/bin/sh -c '");

test('log initialization commands have valid shell syntax', () => {
  for (const command of [prepCommand, checkCommand]) {
    const result = spawnSync('/bin/sh', ['-n', '-c', command], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
  }
});

test('tmpfiles initialization preserves an existing file and rejects symlinks', {
  skip: process.platform !== 'linux' || !fs.existsSync('/usr/bin/systemd-tmpfiles'),
}, t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'okuru-log-init-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'okuru.log');
  // The temporary path is controlled by this test, so the privileged unit
  // preparation can be exercised without touching /var/log or using sudo.
  assert.match(file, /^\/[A-Za-z0-9/_.-]+$/);
  const prepare = prepCommand
    .replaceAll('/var/log/okuru.log', file)
    .replace(':freebox :freebox', `:${process.getuid()} :${process.getgid()}`);
  const validate = checkCommand.replaceAll('/var/log/okuru.log', file);
  const run = command => spawnSync('/bin/sh', ['-c', command], { encoding: 'utf8' });

  let result = run(prepare);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.statSync(file).mode & 0o777, 0o640);
  assert.equal(run(validate).status, 0);

  fs.writeFileSync(file, 'existing log\n');
  fs.chmodSync(file, 0o600);
  result = run(prepare);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.readFileSync(file, 'utf8'), 'existing log\n');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);

  const target = path.join(directory, 'target');
  fs.writeFileSync(target, 'untouched\n');
  fs.unlinkSync(file);
  fs.symlinkSync(target, file);
  run(prepare); // Refusal or safe no-op are both acceptable.
  assert.equal(fs.lstatSync(file).isSymbolicLink(), true);
  assert.equal(fs.readFileSync(target, 'utf8'), 'untouched\n');
  assert.notEqual(run(validate).status, 0);
});
