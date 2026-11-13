#!/usr/bin/env python3
"""Terminal presentation tests using the same offline TLSA fixtures."""

import errno
import json
import os
import pty
import re
import select
import subprocess
import time
import unittest

import test_update_tlsa as fixtures


class TLSATerminalTests(fixtures.TLSAOfflineTests):
    def run_terminal(self, *args, mode='existing', no_color=False):
        env = self.env.copy()
        env['MOCK_MODE'] = mode
        env['TERM'] = 'xterm'
        env.pop('NO_COLOR', None)
        if no_color:
            env['NO_COLOR'] = '1'
        master, slave = pty.openpty()
        try:
            proc = subprocess.Popen(
                ['bash', '-c', 'source "$1"; shift; '
                 'CERTIFICATE_PATHS[share.jeanphilippe.io]="$TEST_CERT"; '
                 'main "$@"', 'offline-test', str(fixtures.SCRIPT), *args],
                env=env, stdout=slave, stderr=slave, close_fds=True,
            )
            os.close(slave)
            slave = -1
            data = bytearray()
            deadline = time.monotonic() + 45
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    proc.kill()
                    proc.wait()
                    self.fail('TLSA script timed out while attached to a terminal')
                ready, _, _ = select.select([master], [], [], min(remaining, 1))
                if not ready:
                    continue
                try:
                    chunk = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                data.extend(chunk)
            returncode = proc.wait(timeout=5)
        finally:
            os.close(master)
            if slave != -1:
                os.close(slave)
        output = data.decode('utf-8', errors='replace')
        log = self.log.read_text() if self.log.exists() else ''
        calls = [json.loads(x) for x in self.calls.read_text().splitlines()] if self.calls.exists() else []
        self.assertNotIn(fixtures.TOKEN, output)
        self.assertNotIn(fixtures.TOKEN, log)
        for call in calls:
            self.assertFalse(call['args_have_token'], call)
            self.assertFalse(call['env_has_token'], call)
        return returncode, output, log, calls

    def test_terminal_normal_run_is_colored_but_log_is_plain(self):
        code, output, log, calls = self.run_terminal()
        self.assertEqual(code, 0, output)
        # Match the exact original palette and the corresponding event type,
        # rather than accepting an arbitrary ANSI escape anywhere in the UI.
        self.assertIn('\x1b[1;37m**STARTING TLSA RECORD UPDATE**\x1b[0m', output)
        self.assertIn('\x1b[1;37m**ENDING TLSA RECORD UPDATE**\x1b[0m', output)
        self.assertIn('\x1b[1;33m[jeanphilippe.io] Checking certificate source:', output)
        self.assertIn('\x1b[1;92m[jeanphilippe.io] Certificate verified;', output)
        self.assertRegex(output, r'\x1b\[1;34m\[[^\r\n]+\] HTTP GET attempt 1\x1b\[0m')
        self.assertNotRegex(log, r'\x1b\[[0-9;]*m')
        self.assertIn('share.jeanphilippe.io', output)
        self.assertIn('share.jeanphilippe.io', log)
        self.assertTrue(any(c['method'] == 'POST' for c in calls))

    def test_terminal_cloudflare_error_uses_original_red(self):
        code, output, log, calls = self.run_terminal(mode='failure_flag')
        self.assertNotEqual(code, 0, output)
        self.assertIn('\x1b[1;31mERROR:', output)
        self.assertNotRegex(log, r'\x1b\[[0-9;]*m')
        self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))

    def test_terminal_help_usage_is_white_and_pipe_stays_plain(self):
        code, output, log, calls = self.run_terminal('--help')
        self.assertEqual(code, 0, output)
        self.assertRegex(output, r'\x1b\[1;37mUsage: [^\r\n]+\x1b\[0m')
        self.assertFalse(calls)
        self.assertEqual(log, '')

        code, output, _, _ = self.run_terminal('--help', no_color=True)
        self.assertEqual(code, 0, output)
        self.assertIn('Usage:', output)
        self.assertNotRegex(output, r'\x1b\[[0-9;]*m')

        env = self.env.copy()
        env['TERM'] = 'xterm'
        env.pop('NO_COLOR', None)
        proc = subprocess.run(['bash', str(fixtures.SCRIPT), '--help'],
                              env=env, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Usage:', proc.stdout)
        self.assertNotRegex(proc.stdout + proc.stderr, r'\x1b\[[0-9;]*m')

    def test_terminal_no_color_disables_ansi(self):
        code, output, log, calls = self.run_terminal('--diagnostic', mode='diagnostic_matching', no_color=True)
        self.assertEqual(code, 0, output)
        self.assertNotRegex(output, r'\x1b\[[0-9;]*m')
        self.assertNotRegex(log, r'\x1b\[[0-9;]*m')
        self.assertTrue(calls)
        self.assertFalse(any(c['method'] != 'GET' for c in calls))

    def test_terminal_diagnostic_is_colored_without_dns_mutation(self):
        code, output, log, calls = self.run_terminal('--diagnostic', mode='diagnostic_matching')
        self.assertEqual(code, 0, output)
        self.assertRegex(output, r'\x1b\[[0-9;]*m')
        self.assertTrue(calls)
        self.assertFalse(any(c['method'] != 'GET' for c in calls))

    def test_terminal_ci_pipe_has_no_color(self):
        self.env['TERM'] = 'xterm'
        self.env.pop('NO_COLOR', None)
        self.run_script('--diagnostic', mode='diagnostic_matching')
        self.assertNotRegex(self.last_console, r'\x1b\[[0-9;]*m')


def load_tests(loader, _tests, _pattern):
    # Reuse fixtures without executing the parent's complete integration suite.
    suite = unittest.TestSuite()
    for name in loader.getTestCaseNames(TLSATerminalTests):
        if name.startswith('test_terminal_'):
            suite.addTest(TLSATerminalTests(name))
    return suite


if __name__ == '__main__':
    unittest.main(verbosity=2)
