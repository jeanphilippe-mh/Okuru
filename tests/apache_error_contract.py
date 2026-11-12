#!/usr/bin/env python3
"""Exercise the Apache template locally; ModSecurity is not emulated.

macOS: python3 tests/apache_error_contract.py --apache /usr/sbin/httpd --module-dir /usr/libexec/apache2
Debian: python3 tests/apache_error_contract.py --apache /usr/sbin/apache2 --module-dir /usr/lib/apache2/modules
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(400)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":"backend sentinel"}')
    do_POST = do_GET
    def log_message(self, *args):
        pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apache", required=True)
    parser.add_argument("--module-dir", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    backend = http.server.HTTPServer(("127.0.0.1", 0), Backend)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    with tempfile.TemporaryDirectory(prefix="okuru-apache-") as temp:
        folder = Path(temp)
        errors = folder / "errors"
        shutil.copytree(root / "deploy/apache/errors", errors)
        for source in (root / "views").glob("[45][0-9][0-9].html"):
            shutil.copyfile(source, errors / source.name)
        # Reserve a free local port; Apache starts immediately afterwards.
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        modules = ["mpm_prefork", "unixd", "authz_core", "authz_host", "log_config", "mime", "alias", "proxy", "proxy_http"]
        config = [f'ServerRoot "{folder}"', f'DefaultRuntimeDir "{folder}"', f'PidFile "{folder}/httpd.pid"', f'Listen 127.0.0.1:{port}', "ServerName 127.0.0.1"]
        config += [f'LoadModule {name}_module "{args.module_dir}/mod_{name}.so"' for name in modules]
        config += [f'User "#{os.getuid()}"', f'Group "#{os.getgid()}"', f'TypesConfig "{folder}/mime.types"', f'Define APACHE_LOG_DIR "{folder}"', f'DocumentRoot "{folder}"']
        (folder / "mime.types").write_text("text/html html\napplication/json json\n")
        snippet = (root / "deploy/apache/share-errors.conf").read_text().replace("/var/www/errors", str(errors))
        config += [snippet, '<Location "/api/generated400">\nRedirect 400\n</Location>', '<Location "/browser502">\nRedirect 502\n</Location>', f'ProxyPass / http://127.0.0.1:{backend.server_port}/', f'ProxyPassReverse / http://127.0.0.1:{backend.server_port}/']
        conf = folder / "httpd.conf"
        conf.write_text("\n".join(config))
        subprocess.run([args.apache, "-t", "-f", str(conf)], check=True)
        server = subprocess.Popen([args.apache, "-X", "-f", str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        def request(path):
            try:
                response = client.open(f"http://127.0.0.1:{port}{path}", timeout=5)
            except urllib.error.HTTPError as exc:
                response = exc
            return response.code, dict(response.headers), response.read()
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    request("/ready")
                    break
                except (OSError, urllib.error.URLError):
                    if server.poll() is not None or time.monotonic() >= deadline:
                        log = folder / "error.share.jeanphilippe.io.log"
                        raise RuntimeError("Apache did not start: " + server.stderr.read().decode() + (log.read_text() if log.exists() else ""))
                    time.sleep(0.02)
            status, headers, body = request("/api/upstream")
            assert status == 400 and json.loads(body)["error"] == "backend sentinel", (status, body)
            assert "Location" not in headers
            status, headers, body = request("/api/generated400")
            assert status == 400 and "application/json" in headers.get("Content-Type", ""), (status, headers, body)
            assert json.loads(body)["error"] == "Bad Request" and "Location" not in headers
            status, headers, body = request("/browser502")
            assert status == 502 and body == (errors / "502.html").read_bytes(), (status, body[:200])
            request("/api/sensitive-audit-marker~private-key?secret=query-marker")
            access = (folder / "access.share.jeanphilippe.io.log").read_text()
            assert "sensitive-audit-marker" not in access and "private-key" not in access and "query-marker" not in access
            print("PASS: backend JSON preserved; Apache API error JSON/status preserved; local 502 HTML preserved; access log omits URL secrets.")
        finally:
            server.terminate()
            server.communicate(timeout=5)
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=5)

if __name__ == "__main__":
    main()
