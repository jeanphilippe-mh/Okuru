# Subresource Integrity for local scripts

Okuru uses two complementary browser checks for JavaScript. Its Content
Security Policy (CSP) uses a fresh nonce on each rendered page to authorize
the script elements in that page. Each local file loaded by a `<script src>`
element also carries a SHA-512 Subresource Integrity (SRI) attribute. Before
executing a fetched script, a supporting browser compares the file's bytes with
the SRI value and blocks the script if they differ. The nonce is in the CSP;
the SRI hash is an HTML attribute and does not add a hash source to the CSP.

This check covers the local Bootstrap, DOMPurify, ClipboardJS and service-worker
registration scripts referenced by the templates. It does not cover inline
scripts: those are authorized by the per-response nonce. It also does not check
`public/service-worker.js` itself, which is loaded separately through
`navigator.serviceWorker.register()` rather than a `<script src>` element.
TLS, output escaping, secure handling of inputs and the other existing controls
remain necessary. SRI cannot protect against an attacker who can modify both a
script and the page that specifies its expected hash.

## Updating a script

When a referenced JavaScript file changes, compute a new SHA-512 digest from
the exact file that will be served. For example, run this from the repository
root with Bash and OpenSSL:

```bash
(
  set -o pipefail
  script_file=public/scripts/purify.min.js
  test -r "$script_file" || exit 1
  digest=$(openssl dgst -sha512 -binary "$script_file" | openssl base64 -A) || exit 1
  printf 'sha512-%s\n' "$digest"
)
```

Replace `integrity` with the complete printed value in **every** template that
loads the changed file. Preserve the `nonce` attribute. Verify all script tags
and the hashes against the checked-in files with:

```sh
node --test tests/sri.test.cjs
```

The test checks the template references and file bytes; it is not a substitute
for exercising the application in a browser. A browser test should confirm the
normal page works and that a deliberately altered test asset is blocked. Never
alter production assets to conduct that negative test.

## Deployment and caching

Deploy the executable, `views/` and `public/` from the same tested revision.
Update a script and all its references together: a stale or modified response
whose bytes do not match will be rejected, and the dependent feature can stop
working. This includes a response supplied by a service worker or another cache.
The browser checks the decoded resource, so ordinary HTTP compression is
compatible; an intermediary must not rewrite or minify the JavaScript after the
hash is computed.

The CSP and Apache change must also be coordinated; see
[CSP nonces and Apache](csp-nonces.md) for the staging checks, fallback policy,
maintenance window and rollback sequence. The service worker's own script is
outside the SRI coverage described here and its registration and cache behavior
must be verified independently.
