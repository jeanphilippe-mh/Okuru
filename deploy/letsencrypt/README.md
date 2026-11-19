# Certbot deploy hook for jeanphilippe.io

The [TLSA script](TLSA_jeanphilippe.io.sh) updates Cloudflare TLSA records for HTTPS on port 443. Each record contains the SHA-256 fingerprint of the certificate's public key (`3 1 1`). Each invocation checks all five configured hostnames. For `share.jeanphilippe.io` it compares the local Let's Encrypt certificate with the certificate served over HTTPS. For the four OVH-managed names it reads the certificate from the public endpoint.

## Prepare and preview on Debian

1. Run `sudo certbot certificates` and verify the local certificate path in the script. Review the configured names and certificate sources. Install Bash, OpenSSL, curl, jq, awk, GNU coreutils and util-linux so the hook can use `timeout` and `flock`.
2. Give the Cloudflare API token DNS edit access scoped to the zone. If Certbot's hook directory is missing, create it with `sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy`. By default, the script reads the raw token from `/etc/letsencrypt/renewal-hooks/deploy/cloudflare-tlsa.token`. Keep it in a regular file owned by root with mode `0600`. Keep the token outside the checkout.
3. From the repository root, install the reviewed script outside Certbot's active hook directory. Replace the zone ID below with the zone's 32 hexadecimal characters. Both preview commands contact the HTTPS endpoints and read records from Cloudflare. A nonzero diagnostic status can indicate a mismatch, a missing record or a failed check.

```sh
sudo install -D -o root -g root -m 0755 deploy/letsencrypt/TLSA_jeanphilippe.io.sh /usr/local/libexec/okuru/TLSA_jeanphilippe.io.sh
zone_id='YOUR_CLOUDFLARE_ZONE_ID'
sudo env CF_ZONE_ID="$zone_id" /usr/local/libexec/okuru/TLSA_jeanphilippe.io.sh --diagnostic
sudo env CF_ZONE_ID="$zone_id" /usr/local/libexec/okuru/TLSA_jeanphilippe.io.sh --dry-run
```

## Enable the renewal hook

After reviewing the preview, create a root-owned hook at `/etc/letsencrypt/renewal-hooks/deploy/okuru-tlsa` with the contents below. Set the actual zone ID here so that scheduled renewals have it too. If this server already has a hook for the script, update that hook in place to keep a single registration.

```sh
#!/bin/sh
export CF_ZONE_ID='YOUR_CLOUDFLARE_ZONE_ID'
exec /usr/local/libexec/okuru/TLSA_jeanphilippe.io.sh "$@"
```

Set the hook's mode to `0755`. Certbot runs the executable hook after a successful renewal. Running it without arguments applies any proposed DNS changes. To check the installed configuration manually, use `sudo /etc/letsencrypt/renewal-hooks/deploy/okuru-tlsa --dry-run`. Normal runs write to `/var/log/letsencrypt/update_tlsa.log`. [Certbot renewal hooks](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates)

OVH can rotate the other certificates between local renewals. Monitor those endpoints separately. The operations guide covers reconciliation, DNSSEC checks and the window during which resolvers can retain the previous key. [TLSA operations and troubleshooting](../../docs/tlsa-update.md)
