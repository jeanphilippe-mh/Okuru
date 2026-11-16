# Debian deployment of nonce CSP and SRI

Use a planned maintenance window after merging and staging with the actual
Apache HTTP/2 proxy and ModSecurity configuration. Confirm paths and service
names on the server. The versioned unit's `/home/freebox/Okuru` is only an
example, not evidence of the active installation. Use one dedicated Bash
session for the variables below. `set -e` exits that session on an unhandled
failure; if that happens, inspect state and recover the recorded paths before
continuing. Do not execute later steps after an error.

## Inspect and prepare a separate build

```sh
bash
set -e
systemctl show okuru.service -p ExecStart -p WorkingDirectory -p User -p Group
sudo apache2ctl -S
sudo grep -Rni 'Content-Security-Policy' /etc/apache2
go version

STAGE=$(mktemp -d "$HOME/okuru-csp-stage.XXXXXX")
git clone --single-branch --branch master https://github.com/jeanphilippe-mh/Okuru.git "$STAGE/source"
cd "$STAGE/source"
git log -1 --oneline
node --test tests/sri.test.cjs
go build -o "$STAGE/Okuru" .
```

Verify that this checkout includes the merged nonce and SRI change. If Node.js
is unavailable, verify SRI in a suitable staging environment and CI before
continuing. Never update the live checkout while the old application runs: it
reads templates from disk for each request.

## Prepare copies and save the active configuration

Set `APP` and `VHOST` to the verified paths. The placeholder is not a usable
Apache path. Resolve the actual vhost file rather than saving a symbolic link.
Set `SERVICE_USER` to the account reported by systemd. This generic procedure
does not support symbolic links or mount points for the three application items;
if any are found, stop and adapt it to back up their actual targets.

```sh
APP=/home/freebox/Okuru
VHOST=/etc/apache2/sites-available/REPLACE-WITH-YOUR-VHOST.conf
SERVICE_USER=freebox

VHOST=$(readlink -f "$VHOST")
: "${STAGE:?}" "${APP:?}" "${VHOST:?}" "${SERVICE_USER:?}"
test -f "$APP/Okuru"
test -d "$APP/views"
test -d "$APP/public"
sudo test -f "$VHOST"
command -v mountpoint
for item in Okuru views public; do
  if test -L "$APP/$item" || mountpoint -q "$APP/$item"; then
    printf 'Stop: %s is a symbolic link or mount point\n' "$APP/$item" >&2
    exit 1
  fi
done
NEW=$(sudo mktemp -d "$APP/.csp-new.XXXXXX")
BACKUP=$(sudo mktemp -d "$APP/.csp-rollback.XXXXXX")
: "${NEW:?}" "${BACKUP:?}"
sudo chmod 0755 "$NEW"
sudo mkdir "$BACKUP/snapshot" "$BACKUP/live"
sudo cp -a "$APP/Okuru" "$APP/views" "$APP/public" "$BACKUP/snapshot/"
sudo cp -a "$VHOST" "$BACKUP/apache-vhost.conf"
sudo install -m 0755 -o "$(stat -c %u "$APP/Okuru")" -g "$(stat -c %g "$APP/Okuru")" "$STAGE/Okuru" "$NEW/Okuru"
sudo cp -a "$STAGE/source/views" "$STAGE/source/public" "$NEW/"
sudo cp -a "$VHOST" "$NEW/apache-vhost.conf"
sudo -u "$SERVICE_USER" test -x "$NEW/Okuru"
sudo -u "$SERVICE_USER" test -r "$NEW/views/base.html"
sudo -u "$SERVICE_USER" test -r "$NEW/public/scripts/purify.min.js"
printf 'Prepared: %s\nBackup: %s\n' "$NEW" "$BACKUP"
```

Confirm that the service account can read the prepared assets. These commands
do not copy or modify `.env`, `data/`, certificates, Redis or logs. Retain the
backup until verification is complete. If Apache inherits CSP directives from
other included files, save those files too and adapt the instructions.

## Change Apache and switch the application

Edit the separate candidate and remove its old unconditional CSP directive,
without adding an Apache fallback, as described in [csp-nonces.md](csp-nonces.md).
Leave other directives unchanged. Check for other enforced CSPs for this virtual host. Do not edit the
active file before stopping the old application: another process may reload it.

```sh
sudo nano "$NEW/apache-vhost.conf"
```

During the maintenance window, stop the application, install the candidate and
validate it, then switch all three items together, restart Apache and start the
application. A syntax failure stops this sequence before the switch or restart;
restore the saved Apache file and old application according to the recovery
instructions. An Apache restart interrupts connections.

```sh
(
  set -e
  : "${APP:?}" "${NEW:?}" "${BACKUP:?}" "${VHOST:?}"
  sudo systemctl stop okuru.service
  sudo cp -a "$NEW/apache-vhost.conf" "$VHOST"
  sudo apache2ctl configtest
  sudo mv "$APP/Okuru" "$APP/views" "$APP/public" "$BACKUP/live/"
  sudo mv "$NEW/Okuru" "$NEW/views" "$NEW/public" "$APP/"
  sudo systemctl restart apache2
  sudo systemctl start okuru.service
)
```

If any command fails, stop and inspect the exact state. Do not continue a
partially completed switch as if it had succeeded. The snapshot in
`$BACKUP/snapshot/` and previous Apache file remain available.

## Verify and roll back if needed

```sh
sudo systemctl status --no-pager okuru.service apache2
sudo apache2ctl configtest
curl --http2 -sS -D - -o /dev/null https://share.jeanphilippe.io/file | grep -iE '^(content-security-policy|cache-control):'
curl --http2 -sS -D - -o /dev/null https://share.jeanphilippe.io/file | grep -iE '^(content-security-policy|cache-control):'
```

Each response must have exactly one enforced CSP, a different nonce, and
`no-store`. In a browser check the network and console, both sliders, secret and
file creation, errors and downloads, and the service worker. Exercise a
controlled Apache/ModSecurity error in staging and confirm the intended absence
of an Apache fallback CSP on responses not generated by Okuru.
Do not include private share URLs in terminal captures or logs.

For a completed or partially completed switch, first confirm the recorded
values of `APP`, `NEW`, `BACKUP`, `VHOST` and `SERVICE_USER`. This recovery
moves whichever new items exist aside, restores each old item from the snapshot,
then validates Apache and service-account access before restarting. Never run it
with paths from a different deployment. Inspect any failure before retrying.

```sh
(
  set -e
  : "${APP:?}" "${NEW:?}" "${BACKUP:?}" "${VHOST:?}" "${SERVICE_USER:?}"
  sudo test -f "$BACKUP/apache-vhost.conf"
  sudo test -f "$BACKUP/snapshot/Okuru"
  sudo test -d "$BACKUP/snapshot/views"
  sudo test -d "$BACKUP/snapshot/public"
  sudo systemctl stop okuru.service
  sudo mkdir "$NEW/failed"
  for item in Okuru views public; do
    if sudo test -e "$APP/$item"; then sudo mv "$APP/$item" "$NEW/failed/"; fi
    sudo cp -a "$BACKUP/snapshot/$item" "$APP/$item"
  done
  sudo cp -a "$BACKUP/apache-vhost.conf" "$VHOST"
  sudo apache2ctl configtest
  sudo -u "$SERVICE_USER" test -x "$APP/Okuru"
  sudo -u "$SERVICE_USER" test -r "$APP/views/base.html"
  sudo -u "$SERVICE_USER" test -r "$APP/public/scripts/purify.min.js"
  sudo systemctl restart apache2
  sudo systemctl start okuru.service
)
```

Check service status and browser behaviour again after rollback. Preserve any
additional Apache configuration files saved during preparation.
