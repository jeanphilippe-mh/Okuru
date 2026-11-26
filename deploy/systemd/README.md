# Run Okuru under systemd

Okuru runs as `freebox` and appends to `/var/log/okuru.log` and the `okuru` journal namespace. A separate systemd unit prepares the log before Okuru starts. That unit uses an administrator-owned tmpfiles rule and runs independently of `/home/freebox/Okuru/.env`. The rule creates a missing log as `freebox:freebox` with mode `0640` and preserves the contents, ownership and permissions of an existing log.

## Install or upgrade on Debian

Install the unit files and tmpfiles rule from a verified release copy in a directory controlled by the administrator. If your service account differs from `freebox`, update `User=` and `Group=` in `okuru.service` and the owner and group in `okuru-log.conf` before installing them.

```sh
sudo install -D -o root -g root -m 0644 deploy/systemd/okuru-log.conf /etc/tmpfiles.d/okuru-log.conf
sudo install -o root -g root -m 0644 deploy/systemd/okuru-log-init.service /etc/systemd/system/okuru-log-init.service
sudo install -o root -g root -m 0644 okuru.service /etc/systemd/system/okuru.service
sudo systemd-analyze verify /etc/systemd/system/okuru-log-init.service /etc/systemd/system/okuru.service
sudo systemctl daemon-reload
sudo systemctl cat okuru.service okuru-log-init.service
```

During an upgrade, check the effective units shown by `systemctl cat`. If a local drop-in contains the old privileged `ExecStartPre=+` log setup, remove that directive from the drop-in and reload systemd again. Then restart Okuru. Enabling `okuru.service` for startup also pulls in its log initializer when needed.

```sh
sudo systemctl restart okuru.service
```

## Verify the log destinations

```sh
sudo systemctl status --no-pager okuru.service
sudo stat -c '%a %U:%G %n' /var/log/okuru.log
sudo journalctl -u okuru-log-init.service -n 30 --no-pager
sudo journalctl --namespace=okuru -u okuru.service -n 30 --no-pager
```

The initializer exits after preparing the file, so it normally shows as inactive once Okuru starts. If Okuru refuses to start, check the initializer journal and verify that `/var/log/okuru.log` is a regular, writable file for the service account. Preserve any existing log data when correcting its permissions or moving it to a safe location. After correcting the issue, restart `okuru.service` to run initialization again.
