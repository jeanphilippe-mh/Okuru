"""Exercise the production supervisor and Echo worker on a hosted Ubuntu VM.

Run as a non-root user with passwordless sudo, systemd as PID 1 and the job's
loopback Redis. The transient service replaces deployment paths and identity
and shortens the watchdog to 12 s, abort/stop to 4 s and restart to 1 s.
SIGSTOP simulates a persistent process-wide stall, not a specific Go deadlock.
PID 1 may resume the worker while terminating the unit. Recovery must still
come from the watchdog, and both HTTPS endpoints must work in the new process.
"""

import configparser
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
SUDO = ["sudo", "-n"]


def output(*args):
    return subprocess.check_output(args, text=True, timeout=10)


def state(unit):
    properties = ["MainPID", "NRestarts", "StatusText"]
    lines = output("systemctl", "show", unit, "--property=" + ",".join(properties))
    return dict(line.split("=", 1) for line in lines.splitlines())


def healthy(port, cert, path, expected):
    result = subprocess.run(
        ["/usr/bin/curl", "--http2", "--tlsv1.3", "--noproxy", "*", "--cacert", cert,
         "--fail", "--silent", "--max-time", "1", "--write-out", "\\n%{http_version}",
         f"https://127.0.0.1:{port}/{path}"], capture_output=True, text=True,
    )
    if result.returncode:
        return False
    body, protocol = result.stdout.rsplit("\n", 1)
    return protocol == "2" and json.loads(body) == {"status": expected}


def wait_ready(unit, port, cert, previous_pid=None):
    deadline = time.monotonic() + 55
    while time.monotonic() < deadline:
        current = state(unit)
        pid = int(current["MainPID"])
        if (pid and pid != previous_pid and current.get("StatusText", "").startswith("Echo /ping is responding")
                and healthy(port, cert, "ping", "alive") and healthy(port, cert, "ready", "ready")):
            return pid, int(current["NRestarts"])
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for healthy HTTPS endpoints: {state(unit)}")


def worker_pid(unit, supervisor, binary):
    # Read all direct children, including forks made by other Go runtime threads.
    children = output("ps", "--ppid", str(supervisor), "-o", "pid=").split()
    for child in children:
        proc = Path("/proc") / child
        args = (proc / "cmdline").read_bytes().split(b"\0")
        groups = (proc / "cgroup").read_text().splitlines()
        if (args[1:2] == [b"--internal-worker"] and (proc / "exe").samefile(binary)
                and any(group.endswith("/" + unit) for group in groups)):
            return int(child)
    raise RuntimeError(f"Could not identify the Echo worker for {unit}")


def exercise(unit, work, port):
    binary = work / "Okuru"
    cert = work / "cert.pem"
    logs = work / "logs"
    logs.mkdir()
    (logs / "okuru.log").touch(mode=0o600)
    (work / "data").mkdir(mode=0o700)
    subprocess.run(["go", "build", "-o", binary, "."], cwd=ROOT, check=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
         "-out", cert, "-keyout", work / "key.pem"], check=True,
    )
    config = configparser.ConfigParser(strict=False, interpolation=None)
    config.read(ROOT / "okuru.service")
    service = config["Service"]
    properties = [f"{name}={service[name]}" for name in (
        "Type", "KillMode", "NotifyAccess", "WatchdogSignal", "Restart", "NoNewPrivileges",
        "PrivateTmp", "UMask", "CapabilityBoundingSet", "AmbientCapabilities",
    )]
    properties += [f"User={os.getuid()}", f"Group={os.getgid()}", f"BindPaths={logs}:/var/log",
                   "IPAddressDeny=any", "IPAddressAllow=localhost", "WatchdogSec=12s",
                   "TimeoutAbortSec=4s", "TimeoutStopSec=4s", "RestartSec=1s"]
    env = [f"OKURU_APP_PORT={port}", f"REDIS_PREFIX={unit}_", "REDIS_HOST=127.0.0.1",
           f"REDIS_PORT={os.environ.get('REDIS_PORT', '6379')}", "REDIS_DB=13",
           f"XDG_CACHE_HOME={work}/cache"]
    start = SUDO + ["systemd-run", "--quiet", "--collect", f"--unit={unit}", f"--working-directory={work}"]
    start += ["--property=" + item for item in properties] + ["--setenv=" + item for item in env]
    supervisor_flag = service["ExecStart"].split()[1:]
    subprocess.run(start + [binary, *supervisor_flag], check=True, timeout=15)
    try:
        first, restarts = wait_ready(unit, port, cert)
        worker = worker_pid(unit, first, binary)
        # Pin the PID, then recheck its identity before sending our only signal.
        fd = os.pidfd_open(worker)
        try:
            if worker_pid(unit, first, binary) != worker or state(unit)["MainPID"] != str(first):
                raise RuntimeError("Worker changed before fault injection")
            signal.pidfd_send_signal(fd, signal.SIGSTOP)
        finally:
            os.close(fd)
        if healthy(port, cert, "ping", "alive"):
            raise RuntimeError("The stopped worker still answered /ping")
        second, after = wait_ready(unit, port, cert, first)
        new_worker = worker_pid(unit, second, binary)
        journal = output(*SUDO, "journalctl", "-u", unit, "--no-pager", "-o", "cat")
        if after <= restarts or new_worker == worker or "watchdog timeout" not in journal.lower():
            raise RuntimeError("Missing evidence of a watchdog timeout and process replacement")
        print(f"Watchdog restored /ping and /ready over HTTP/2 and TLS 1.3. "
              f"Supervisor {first} → {second}, Echo {worker} → {new_worker}.")
    except Exception:
        subprocess.run(SUDO + ["journalctl", "-u", unit, "--no-pager", "-n", "45"], timeout=10)
        raise
    finally:
        subprocess.run(SUDO + ["systemctl", "stop", unit], check=True, timeout=25)


def main():
    if os.getuid() == 0 or not Path("/run/systemd/system").is_dir() or not shutil.which("systemd-run"):
        raise SystemExit("Requires a non-root account on a systemd-booted Linux host")
    unit = f"okuru-ci-{uuid.uuid4().hex}.service"
    # Keep the working directory visible to services with PrivateTmp enabled.
    with tempfile.TemporaryDirectory(prefix="okuru-watchdog-", dir=Path.home()) as work:
        with socket.socket() as available:
            available.bind(("127.0.0.1", 0))
            port = available.getsockname()[1]
        exercise(unit, Path(work), port)


if __name__ == "__main__":
    main()
