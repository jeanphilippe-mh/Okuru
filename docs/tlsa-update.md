# TLSA update candidate

This script is based on the supplied production script. The reported setup has a local Let's Encrypt certificate for `share.jeanphilippe.io` and OVH-managed certificates for the other four configured names. Verify this arrangement and the local path on the server before use.

## Configuration

The script needs a Cloudflare API token with DNS edit access restricted to the intended zone. By default it reads the raw token from `/etc/letsencrypt/renewal-hooks/deploy/cloudflare-tlsa.token`. The file must be owned by the account running the script, must not be a symbolic link, and must not be accessible to the group or other users. A root-run Certbot hook therefore needs a root-owned file with mode `0600`. Do not put the token itself in the script or command-line arguments.

Set the non-secret `CF_ZONE_ID` in the script or provide it through a persistent hook environment. A variable set only in an interactive shell is not automatically available to Certbot's scheduled process. `CF_API_TOKEN_FILE` can select another private token file; alternatively `CF_API_TOKEN` may supply a token in the environment, but do not set both. The script sends API requests directly and ignores HTTP proxy environment settings.

The script requires Bash, OpenSSL, curl, jq, awk, GNU timeout and flock. It uses a private lock under `/run/lock/okuru-tlsa` and logs to `/var/log/letsencrypt/update_tlsa.log`. The user must be allowed to access its certificate files, lock directory and log. The production environment and these permissions have not been checked.

## Review and validation

1. Use `sudo certbot certificates` on the server to identify the certificate lineage and names for `share.jeanphilippe.io`; set its local certificate path accordingly. Confirm that OVH is the intended public TLS endpoint for each of the other four names. A proxy or CDN can present a different certificate from the origin.
2. Provide `CF_ZONE_ID` and the private token file. Run `bash TLSA_jeanphilippe.io.sh --diagnostic` to inspect each domain's certificate source and Cloudflare status. Run `bash TLSA_jeanphilippe.io.sh --dry-run` to preview proposed changes. Both modes contact Cloudflare and public HTTPS endpoints and acquire a local lock, but send no DNS mutation requests. Diagnostic exits nonzero if any domain differs, is missing, or cannot be checked.
3. Review the output and compare the public certificate, DNSSEC status, authoritative answers and the existing TLSA records for every domain. The Cloudflare API response alone does not prove DNS propagation, cache expiry or DNSSEC validity.
4. Plan an independent way to monitor errors and retry failed runs. A nonzero hook status does not necessarily make `certbot renew` itself return a nonzero status. A successful certificate renewal does not prove that Apache reloaded or that the TLSA update succeeded.

For `share.jeanphilippe.io`, the script validates the local Let's Encrypt certificate and compares its public key with one authenticated public endpoint. For each OVH-managed domain, it automatically accepts the key of the public endpoint after the system's Web PKI and hostname checks, as requested. It does not independently pin the OVH key: a fraudulent certificate trusted by the system's authorities combined with network redirection could cause publication of an attacker's key, which weakens DANE's independent protection. It repeats the endpoint check before and after a domain update. Each check samples only one resolved endpoint: it does not prove that every IPv4/IPv6 address, load balancer or CDN edge presents the same key. The script does not reload Apache or repair Certbot.

An OVH certificate can be renewed independently of the local Let's Encrypt certificate. A local Certbot deploy hook alone will not run when OVH renews a certificate, so monitoring and a separate scheduled reconciliation are necessary if TLSA records must follow those independent changes. No scheduler or alerting has been installed or validated.

For each changed domain, the requested behavior is to delete the previous TLSA records and then create the new one. Cloudflare is queried after each phase, with bounded retries for temporary failures and delayed state; ambiguous writes are not blindly repeated. If the final record already matches, the script skips the change. A failed delete or create can still leave no record or a partial set, and a failed final check requires operator investigation. There is no cross-domain transaction.

This is not a prepublished DANE key rollover: a Certbot deploy hook runs after renewal. Existing resolver caches can retain an old TLSA value after the certificate changes. Eliminating that window requires a separate key-rotation procedure with advance publication and cache-aware timing.

## Local tests

`python3 tests/tlsa/test_update_tlsa.py` runs offline tests with simulated Cloudflare and endpoint responses and temporary test certificates. It does not establish compatibility with the live account, the production Certbot/Apache configuration, the actual DNS delegation, or Linux filesystem and `flock` behavior when run on macOS.
