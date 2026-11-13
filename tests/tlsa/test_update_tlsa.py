#!/usr/bin/env python3
"""Offline integration checks for update_tlsa.sh using disposable fake CLI tools."""
import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / 'TLSA_jeanphilippe.io.sh'
HASH = 'a' * 64
TOKEN = 'test_only_dummy_token'

FAKE_CURL = r'''#!/usr/bin/env python3
import hashlib, json, os, sys, urllib.parse
args = sys.argv[1:]
body = sys.stdin.read()
method = args[args.index('-X') + 1] if '-X' in args else 'GET'
url = next((a for a in args if a.startswith('https://')), '')
record = {'method': method, 'args_have_token': 'test_only_dummy_token' in ' '.join(args),
          'env_has_token': 'CF_API_TOKEN' in os.environ,
          'config_has_token': 'test_only_dummy_token' in body}
with open(os.environ['MOCK_CALLS'], 'a') as f: f.write(json.dumps(record) + '\n')
if record['args_have_token'] or record['env_has_token'] or not record['config_has_token']:
    sys.exit(33)
mode = os.environ.get('MOCK_MODE', 'empty')
count = len(open(os.environ['MOCK_CALLS']).readlines())
state_path = os.environ['MOCK_STATE']
try:
    state = json.load(open(state_path))
except FileNotFoundError:
    state = {'records': {}, 'post_count': 0, 'last_deleted': None}
def persist():
    with open(state_path, 'w') as f: json.dump(state, f)
def old_records(name):
    return [{'id':hashlib.sha256(name.encode()).hexdigest()[:32], 'type':'TLSA', 'name':name, 'ttl':300,
             'data':{'usage':3,'selector':1,'matching_type':1,'certificate':'b'*64}}]
if method == 'DELETE':
    if mode == 'delete_failure':
        print('{"success":false}403', end=''); sys.exit(0)
    record_id = url.rsplit('/', 1)[-1]
    for name, records in state['records'].items():
        if any(r['id'] == record_id for r in records):
            state['deleted_name'] = name
        state['records'][name] = [r for r in records if r['id'] != record_id]
    state['last_deleted'] = record_id
    persist()
    print('{"success":true,"result":{"id":"' + '0'*32 + '"}}200', end=''); sys.exit(0)
if method == 'POST':
    state['post_count'] += 1
    data = json.loads(args[args.index('--data') + 1])
    name = data['name']
    if mode != 'post_failure':
        data['id'] = '1'*32
        state['records'][name] = [data]
        state['created_name'] = name
    persist()
    if mode == 'post_failure': print('{"success":false}503', end=''); sys.exit(0)
    if mode == 'post_ambiguous_applied': sys.exit(28)
    print(json.dumps({'success':True,'result':{'id':'1'*32}}) + '200', end=''); sys.exit(0)
if mode == 'retry' and count == 1:
    print('{"success":false}503', end=''); sys.exit(0)
if mode == 'retry_429' and count == 1:
    print('{"success":false}429', end=''); sys.exit(0)
if mode == 'malformed' or (mode == 'verify_malformed' and state['post_count']):
    print('{oops200', end=''); sys.exit(0)
if mode == 'failure_flag': print('{"success":false,"result":[],"result_info":{"total_pages":1}}200', end=''); sys.exit(0)
if mode == 'pagination': print('{"success":true,"result":[],"result_info":{"total_pages":2}}200', end=''); sys.exit(0)
if mode == 'verify_failure' and state['post_count']:
    print('{"success":false}503', end=''); sys.exit(0)
parsed = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
name = parsed.get('name', [''])[0]
state['last_name'] = name
if name not in state['records']:
    state['records'][name] = old_records(name) if mode in ('existing','delete_failure','post_failure','post_ambiguous_applied','verify_malformed','verify_failure','verify_mismatch','content_only','conflicting','missing_content','bad_second_record','delete_stale','post_stale','delete_stale_always','post_stale_always','snapshot_content','snapshot_id','snapshot_added','snapshot_removed','snapshot_ttl','diagnostic_matching') else []
    if mode == 'diagnostic_matching':
        state['records'][name][0]['data']['certificate'] = os.environ['TEST_MATCH_HASH']
records = state['records'][name]
state.setdefault('get_counts', {})
state['get_counts'][name] = state['get_counts'].get(name, 0) + 1
# A second actor changes the first domain after preflight but before its first
# DELETE.  Keep the changed data valid so that snapshot comparison, not merely
# malformed-response handling, must stop the mutation.
if name == '_443._tcp.jeanphilippe.io' and state['get_counts'][name] == 2:
    if mode == 'snapshot_content':
        records = [dict(records[0], data=dict(records[0]['data'], certificate='c'*64))]
    elif mode == 'snapshot_id':
        records = [dict(records[0], id='e'*32)]
    elif mode == 'snapshot_added':
        records = records + [dict(records[0], id='e'*32)]
    elif mode == 'snapshot_removed':
        records = []
    elif mode == 'snapshot_ttl':
        records = [dict(records[0], ttl=600)]
    state['records'][name] = records
stale_key = 'stale:' + name
if state.get('deleted_name') == name and state['post_count'] == 0 and mode in ('delete_stale', 'delete_stale_always'):
    n = state.get(stale_key, 0)
    state[stale_key] = n + 1
    if n == 0 or mode == 'delete_stale_always': records = old_records(name)
if state.get('created_name') == name and mode in ('post_stale', 'post_stale_always') and records:
    n = state.get(stale_key, 0)
    state[stale_key] = n + 1
    if n == 0 or mode == 'post_stale_always': records = []
if records and records[0].get('data', {}).get('certificate') == 'b'*64:
    if mode == 'content_only':
        records = [dict(records[0], content='3 1 1 ' + 'b'*64)]
        records[0].pop('data', None)
    if mode == 'conflicting':
        records = [dict(records[0], content='3 1 1 ' + 'c'*64)]
    if mode == 'missing_content':
        records = [dict(records[0])]
        records[0].pop('data', None)
    if mode == 'bad_second_record' and name == '_443._tcp.share.jeanphilippe.io':
        records = [dict(records[0])]
        records[0].pop('data', None)
if mode == 'verify_mismatch' and state['post_count']:
    records = old_records(name)
persist()
print(json.dumps({'success':True,'result':records,'result_info':{'total_pages':1}}) + '200', end='')
'''

FAKE_OPENSSL = r'''#!/bin/sh
if [ "${1:-}" = s_client ]; then
  # Refuse the simulated handshake unless the production command requests
  # SNI, certificate chain verification, and hostname validation together.
  connect= server= verify_host= verify_return=false show_certs=false
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -connect) connect=${2:-}; shift ;;
      -servername) server=${2:-}; shift ;;
      -verify_hostname) verify_host=${2:-}; shift ;;
      -verify_return_error) verify_return=true ;;
      -showcerts) show_certs=true ;;
    esac
    shift
  done
  [ -n "$server" ] && [ "$connect" = "$server:443" ] && [ "$verify_host" = "$server" ] && [ "$verify_return" = true ] && [ "$show_certs" = true ] || exit 70
  printf '%s\n' "$server" >> "$MOCK_TLS_CALLS"
  [ "${MOCK_TLS_REJECT_DOMAIN:-}" = "$server" ] && exit 1
  if [ "${MOCK_SERVER_FAILURE_ONCE:-}" = 1 ] && [ ! -e "$MOCK_HANDSHAKE_FILE" ]; then : > "$MOCK_HANDSHAKE_FILE"; exit 1; fi
  [ "${MOCK_SERVER_FAILURE:-}" = 1 ] && exit 1
  count_file="${MOCK_HANDSHAKE_FILE}.count"
  count=0
  [ ! -f "$count_file" ] || read -r count < "$count_file"
  count=$((count+1))
  printf '%s\n' "$count" > "$count_file"
  if [ "${MOCK_SERVER_CHANGE:-}" = before ] && [ "$count" -gt 5 ]; then
    cat "$TEST_MISMATCH_CERT"; exit 0
  fi
  if [ "${MOCK_SERVER_CHANGE:-}" = after ] && [ -f "$MOCK_STATE" ] && [ "$(jq -r '.post_count' "$MOCK_STATE")" -gt 0 ]; then
    cat "$TEST_MISMATCH_CERT"; exit 0
  fi
  if [ "$server" != share.jeanphilippe.io ] && [ -n "${TEST_OVH_SERVER_CERT:-}" ]; then
    cat "$TEST_OVH_SERVER_CERT"; exit 0
  fi
  cat "$TEST_SERVER_CERT"
  exit 0
fi
checkend=false
checkhost=false
for arg in "$@"; do
  [ "$arg" = -checkend ] && checkend=true
  [ "$arg" = -checkhost ] && checkhost=true
done
if [ "${MOCK_OPENSSL_COMBINED_BUG:-}" = 1 ] && [ "$checkhost" = true ]; then
  [ "$checkend" = true ] && exit 0
  exit 1
fi
exec "$REAL_OPENSSL" "$@"
'''


class TLSAOfflineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_dir = tempfile.TemporaryDirectory(prefix='tlsa-test-cert-')
        root = pathlib.Path(cls.cert_dir.name)
        cls.cert = root / 'cert.pem'
        cls.bad_cert = root / 'bad-cert.pem'
        cls.mismatch_cert = root / 'mismatch-cert.pem'
        cls.rotated_cert = root / 'rotated-cert.pem'
        cls.bad_cert.write_text('not a certificate')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / 'key.pem'), '-out', str(cls.cert),
                        '-days', '1', '-subj', '/CN=jeanphilippe.io', '-addext',
                        'subjectAltName=DNS:jeanphilippe.io,DNS:monportfolio.jeanphilippe.io,DNS:myportfolio.jeanphilippe.io,DNS:share.jeanphilippe.io,DNS:www.jeanphilippe.io'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        public = subprocess.run(['openssl', 'x509', '-in', str(cls.cert), '-pubkey', '-noout'],
                                check=True, stdout=subprocess.PIPE).stdout
        der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'],
                             input=public, check=True, stdout=subprocess.PIPE).stdout
        cls.match_hash = hashlib.sha256(der).hexdigest()
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / 'rotated-key.pem'), '-out', str(cls.rotated_cert),
                        '-days', '1', '-subj', '/CN=jeanphilippe.io', '-addext',
                        'subjectAltName=DNS:jeanphilippe.io,DNS:monportfolio.jeanphilippe.io,DNS:myportfolio.jeanphilippe.io,DNS:www.jeanphilippe.io'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / 'mismatch-key.pem'), '-out', str(cls.mismatch_cert),
                        '-days', '1', '-subj', '/CN=other.invalid', '-addext',
                        'subjectAltName=DNS:other.invalid'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.cert_dir.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tlsa-offline-')
        root = pathlib.Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        bindir = root / 'bin'
        bindir.mkdir()
        for name, body in [('curl', FAKE_CURL), ('openssl', FAKE_OPENSSL), ('sleep', '#!/bin/sh\nexit 0\n'), ('timeout', '#!/bin/sh\nshift\nexec "$@"\n'), ('flock', '#!/usr/bin/env python3\nimport fcntl,sys\ntry: fcntl.flock(int(sys.argv[-1]), fcntl.LOCK_EX | fcntl.LOCK_NB)\nexcept (OSError, ValueError): sys.exit(1)\n')]:
            path = bindir / name
            path.write_text(body)
            path.chmod(0o755)
        self.token = root / 'token'
        self.token.write_text(TOKEN)
        self.token.chmod(0o600)
        self.calls = root / 'calls.jsonl'
        self.log = root / 'update.log'
        self.state = root / 'state.json'
        self.handshake_file = root / 'handshake'
        self.tls_calls = root / 'tls_calls'
        self.lock_dir = root / 'lock'
        self.lock_dir.mkdir(mode=0o700)
        self.env = os.environ.copy()
        self.env.update(PATH=f'{bindir}:' + self.env.get('PATH', ''),
                        CF_API_TOKEN_FILE=str(self.token), CF_ZONE_ID='0'*32,
                        LOG_FILE=str(self.log), MOCK_CALLS=str(self.calls),
                        TIMEOUT='1', MAX_RETRIES='3', TEST_CERT=str(self.cert), REAL_OPENSSL=shutil.which('openssl'), MOCK_STATE=str(self.state), TEST_SERVER_CERT=str(self.cert), OKURU_TLSA_LOCK_DIR=str(self.lock_dir), MOCK_HANDSHAKE_FILE=str(self.handshake_file), TEST_MISMATCH_CERT=str(self.mismatch_cert), MOCK_TLS_CALLS=str(self.tls_calls), TEST_MATCH_HASH=self.match_hash)
        self.env.pop('CF_API_TOKEN', None)

    def run_script(self, *args, mode='empty', success=True, env=None):
        run_env = self.env.copy()
        run_env['MOCK_MODE'] = mode
        if env: run_env.update(env)
        proc = subprocess.run(['bash', '-c', 'source "$1"; shift; CERTIFICATE_PATHS[share.jeanphilippe.io]="$TEST_CERT"; if [ -n "${TEST_BAD_DOMAIN:-}" ]; then CERTIFICATE_PATHS[$TEST_BAD_DOMAIN]="$TEST_BAD_CERT"; fi; if [ -n "${TEST_BAD_SOURCE:-}" ]; then CERTIFICATE_SOURCES[jeanphilippe.io]="$TEST_BAD_SOURCE"; fi; main "$@"', 'offline-test', str(SCRIPT), *args], env=run_env,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=25)
        self.last_output = proc.stdout + (self.log.read_text() if self.log.exists() else '')
        calls = [json.loads(x) for x in self.calls.read_text().splitlines()] if self.calls.exists() else []
        self.assertEqual(proc.returncode == 0, success, msg=f'exit={proc.returncode}\n{proc.stdout}')
        self.assertNotIn(TOKEN, proc.stdout)
        self.assertNotIn(TOKEN, self.last_output)
        for call in calls:
            self.assertFalse(call['args_have_token'], call)
            self.assertFalse(call['env_has_token'], call)
            self.assertTrue(call['config_has_token'], call)
        return calls

    def test_success_replaces_after_validation(self):
        calls = self.run_script(mode='existing')
        methods = [c['method'] for c in calls]
        self.assertTrue('GET' in methods and 'DELETE' in methods and 'POST' in methods)
        self.assertLess(methods.index('GET'), methods.index('DELETE'))
        self.assertLess(methods.index('DELETE'), methods.index('POST'))

    def test_concurrent_cloudflare_changes_prevent_all_mutation(self):
        for mode in ('snapshot_content', 'snapshot_id', 'snapshot_added',
                     'snapshot_removed', 'snapshot_ttl'):
            with self.subTest(mode=mode):
                self.calls.unlink(missing_ok=True)
                self.state.unlink(missing_ok=True)
                self.log.unlink(missing_ok=True)
                calls = self.run_script(mode=mode, success=False)
                self.assertGreaterEqual(sum(c['method'] == 'GET' for c in calls), 6)
                self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))
                self.assertRegex(self.last_output.lower(), r'(changed|concurren|modif|snapshot)')

    def test_ovh_domains_use_authenticated_public_tls_without_local_files(self):
        calls = self.run_script('--dry-run', mode='existing')
        self.assertTrue(calls)
        self.assertEqual(set(self.tls_calls.read_text().splitlines()), {
            'jeanphilippe.io', 'monportfolio.jeanphilippe.io',
            'myportfolio.jeanphilippe.io', 'share.jeanphilippe.io',
            'www.jeanphilippe.io',
        })
        self.assertFalse(any(c['method'] != 'GET' for c in calls))

    def test_rejected_ovh_certificate_never_mutates_dns(self):
        calls = self.run_script(mode='existing', success=False,
                                env={'MOCK_TLS_REJECT_DOMAIN': 'monportfolio.jeanphilippe.io'})
        self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))

    def test_authenticated_ovh_rotation_updates_without_changing_local_share_source(self):
        calls = self.run_script(mode='existing', env={'TEST_OVH_SERVER_CERT': str(self.rotated_cert)})
        self.assertEqual(sum(c['method'] == 'POST' for c in calls), 5)

        def fingerprint(cert):
            public = subprocess.run(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'],
                                    check=True, stdout=subprocess.PIPE).stdout
            der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'],
                                 input=public, check=True, stdout=subprocess.PIPE).stdout
            return hashlib.sha256(der).hexdigest()

        state = json.loads(self.state.read_text())['records']
        ovh_hash, share_hash = fingerprint(self.rotated_cert), fingerprint(self.cert)
        self.assertNotEqual(ovh_hash, share_hash)
        for domain in ('jeanphilippe.io', 'monportfolio.jeanphilippe.io',
                       'myportfolio.jeanphilippe.io', 'www.jeanphilippe.io'):
            self.assertEqual(state['_443._tcp.' + domain][0]['data']['certificate'], ovh_hash)
        self.assertEqual(state['_443._tcp.share.jeanphilippe.io'][0]['data']['certificate'], share_hash)

    def test_unknown_certificate_source_never_mutates_dns(self):
        calls = self.run_script(mode='existing', success=False, env={'TEST_BAD_SOURCE': 'unknown'})
        self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))

    def test_dry_run_does_not_modify_dns(self):
        calls = self.run_script('--dry-run', mode='existing')
        self.assertTrue(calls)
        self.assertFalse(any(c['method'] != 'GET' for c in calls))

    def test_diagnostic_reports_every_domain_without_mutation_or_secret(self):
        calls = self.run_script('--diagnostic', mode='diagnostic_matching')
        self.assertTrue(calls)
        self.assertFalse(any(c['method'] != 'GET' for c in calls))
        for domain in ('jeanphilippe.io', 'monportfolio.jeanphilippe.io',
                       'myportfolio.jeanphilippe.io', 'share.jeanphilippe.io',
                       'www.jeanphilippe.io'):
            self.assertIn(domain, self.last_output)
        self.assertIn('Cloudflare', self.last_output)
        self.assertRegex(self.last_output.lower(), r'(source|local|public)')
        self.assertRegex(self.last_output.lower(), r'(match|differ|missing|empty)')
        self.assertNotIn(TOKEN, self.last_output)

    def test_diagnostic_reports_different_cloudflare_record_as_unsuccessful(self):
        calls = self.run_script('--diagnostic', mode='existing', success=False)
        self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))
        self.assertRegex(self.last_output.lower(), r'(differ|mismatch)')

    def test_diagnostic_rejects_untrusted_endpoint_without_dns_mutation(self):
        calls = self.run_script('--diagnostic', mode='existing', success=False,
                                env={'MOCK_TLS_REJECT_DOMAIN': 'monportfolio.jeanphilippe.io'})
        self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))
        self.assertRegex(self.last_output.lower(), r'(error|failed|cannot|unable)')
        self.assertNotIn(TOKEN, self.last_output)

    def test_failed_listing_never_publishes(self):
        for mode in ['malformed', 'failure_flag', 'pagination']:
            with self.subTest(mode=mode):
                self.calls.unlink(missing_ok=True)
                calls = self.run_script(mode=mode, success=False)
                self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))

    def test_invalid_certificate_never_publishes(self):
        calls = self.run_script(mode='existing', success=False, env={'TEST_CERT': str(self.bad_cert)})
        self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))

    def test_hostname_mismatch_never_mutates_dns(self):
        calls = self.run_script(mode='existing', success=False, env={'TEST_CERT': str(self.mismatch_cert)})
        self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))

    def test_openssl_combined_check_cannot_skip_hostname(self):
        calls = self.run_script(mode='existing', success=False, env={'TEST_CERT': str(self.mismatch_cert), 'MOCK_OPENSSL_COMBINED_BUG': '1'})
        self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))

    def test_content_only_record_is_validated(self):
        calls = self.run_script(mode='content_only')
        self.assertTrue(any(c['method'] == 'DELETE' for c in calls))

    def test_inconsistent_or_missing_records_never_mutate(self):
        for mode in ('conflicting', 'missing_content', 'bad_second_record'):
            with self.subTest(mode=mode):
                self.calls.unlink(missing_ok=True)
                self.state.unlink(missing_ok=True)
                self.log.unlink(missing_ok=True)
                calls = self.run_script(mode=mode, success=False)
                self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))

    def test_live_certificate_mismatch_does_not_mutate(self):
        calls = self.run_script(mode='existing', success=False, env={'TEST_SERVER_CERT': str(self.mismatch_cert)})
        self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))

    def test_live_endpoint_failure_does_not_mutate(self):
        calls = self.run_script(mode='existing', success=False, env={'MOCK_SERVER_FAILURE': '1'})
        self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))

    def test_global_preflight_checks_all_certificates(self):
        calls = self.run_script(mode='existing', success=False, env={'TEST_BAD_DOMAIN': 'share.jeanphilippe.io', 'TEST_BAD_CERT': str(self.bad_cert)})
        self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))

    def test_post_write_verification_requires_exact_record(self):
        for mode in ('verify_failure', 'verify_malformed', 'verify_mismatch'):
            with self.subTest(mode=mode):
                self.calls.unlink(missing_ok=True)
                self.state.unlink(missing_ok=True)
                self.log.unlink(missing_ok=True)
                calls = self.run_script(mode=mode, success=False)
                self.assertEqual(sum(c['method'] == 'POST' for c in calls), 1, msg=self.last_output)
                first_post = next(i for i,c in enumerate(calls) if c['method'] == 'POST')
                self.assertTrue(any(c['method'] == 'GET' for c in calls[first_post+1:]))

    def test_ambiguous_post_reconciles_without_reposting(self):
        calls = self.run_script(mode='post_ambiguous_applied')
        methods = [c['method'] for c in calls]
        self.assertTrue('POST' in methods)
        self.assertTrue(any(m == 'GET' for m in methods[methods.index('POST')+1:]))
        self.assertEqual(sum(m == 'POST' for m in methods), 5)

    def test_endpoint_change_after_preflight_prevents_mutation(self):
        calls = self.run_script(mode='existing', success=False, env={'MOCK_SERVER_CHANGE': 'before'})
        self.assertFalse(any(c['method'] in ('DELETE', 'POST') for c in calls))

    def test_endpoint_change_after_publication_reports_failure(self):
        calls = self.run_script(mode='existing', success=False, env={'MOCK_SERVER_CHANGE': 'after'})
        self.assertEqual(sum(c['method'] == 'POST' for c in calls), 1)
        self.assertRegex(self.last_output.lower(), r'(error|failed|échec|unable)')

    def test_transient_cloudflare_rate_limit_retries(self):
        calls = self.run_script(mode='retry_429')
        self.assertGreaterEqual(sum(c['method'] == 'GET' for c in calls), 2)

    def test_transient_handshake_failure_retries_without_early_mutation(self):
        calls = self.run_script(mode='existing', env={'MOCK_SERVER_FAILURE_ONCE': '1'})
        self.assertTrue(self.handshake_file.exists())
        self.assertTrue(any(c['method'] == 'POST' for c in calls))

    def test_transient_cloudflare_stale_after_delete_or_create_recovers(self):
        for mode in ('delete_stale', 'post_stale'):
            with self.subTest(mode=mode):
                self.calls.unlink(missing_ok=True)
                self.state.unlink(missing_ok=True)
                self.log.unlink(missing_ok=True)
                calls = self.run_script(mode=mode)
                self.assertEqual(sum(c['method'] == 'POST' for c in calls), 5)

    def test_persistent_stale_stops_without_repeating_mutations(self):
        for mode in ('delete_stale_always', 'post_stale_always'):
            with self.subTest(mode=mode):
                self.calls.unlink(missing_ok=True)
                self.state.unlink(missing_ok=True)
                self.log.unlink(missing_ok=True)
                calls = self.run_script(mode=mode, success=False)
                posts = sum(c['method'] == 'POST' for c in calls)
                self.assertLessEqual(posts, 1)
                if mode == 'delete_stale_always': self.assertEqual(posts, 0)

    def test_retry_get_only(self):
        calls = self.run_script(mode='retry')
        self.assertGreaterEqual(sum(c['method'] == 'GET' for c in calls), 2)

    def test_post_failure_is_not_retried(self):
        calls = self.run_script(mode='post_failure', success=False)
        self.assertEqual(sum(c['method'] == 'POST' for c in calls), 1)
        self.assertTrue(any(c['method'] == 'DELETE' for c in calls))
        self.assertRegex(self.last_output.lower(), r'(error|failed|échec|unable)')

    def test_failed_delete_prevents_post(self):
        calls = self.run_script(mode='delete_failure', success=False)
        self.assertTrue(any(c['method'] == 'DELETE' for c in calls))
        self.assertFalse(any(c['method'] == 'POST' for c in calls))

    def test_concurrent_run_is_rejected_before_dns_calls(self):
        with open(self.lock_dir / 'lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            calls = self.run_script(mode='existing', success=False)
            self.assertFalse(calls)
            self.assertRegex(self.last_output.lower(), r'(another|running|lock|occup)')

    def test_unwritable_log_stops_before_dns_mutation(self):
        # A directory cannot be opened for append even when tests run as root.
        calls = self.run_script(mode='existing', success=False,
                                env={'LOG_FILE': self.temp.name})
        self.assertFalse(calls)

    def test_token_file_permissions(self):
        self.token.chmod(0o644)
        calls = self.run_script(success=False)
        self.assertFalse(calls)

    def test_token_sources_are_mutually_exclusive(self):
        calls = self.run_script(success=False, env={'CF_API_TOKEN':TOKEN})
        self.assertFalse(calls)

    def test_symlink_token_rejected(self):
        link = self.token.with_name('link')
        link.symlink_to(self.token)
        self.env['CF_API_TOKEN_FILE'] = str(link)
        calls = self.run_script(success=False)
        self.assertFalse(calls)

    def test_invalid_token_fails_closed(self):
        self.token.write_text('bad"injection')
        calls = self.run_script(success=False)
        self.assertFalse(calls)

    def test_help_is_non_mutating(self):
        self.run_script('--help')
        self.assertFalse(self.calls.exists())

if __name__ == '__main__':
    unittest.main(verbosity=2)
