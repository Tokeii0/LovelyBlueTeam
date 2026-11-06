"""Validate the shipped Nginx config against a loopback-only synthetic backend."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from urllib import error, request

ROOT = Path(__file__).resolve().parents[1]


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = json.dumps({'forwarded_for': self.headers.get('X-Forwarded-For'),
                              'path': self.path}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.do_GET()

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nginx', required=True, help='Path to nginx executable')
    args = parser.parse_args()
    executable = str(Path(shutil.which(args.nginx) or args.nginx).resolve())
    if not Path(executable).is_file():
        parser.error('Nginx executable not found')
    process = None
    backend = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    opener = request.build_opener(request.ProxyHandler({}))
    with tempfile.TemporaryDirectory(prefix='blue-team-nginx-', dir=ROOT.parent) as directory:
        temp = Path(directory)
        shutil.copytree(ROOT/'configs/nginx', temp, dirs_exist_ok=True)
        (temp/'logs').mkdir()
        (temp/'temp').mkdir()
        with socket.socket() as port_probe:
            port_probe.bind(('127.0.0.1', 0))
            port = port_probe.getsockname()[1]
        for p in (temp/'nginx.conf', temp/'servers/app.conf'):
            text = p.read_text(encoding='utf-8')
            text = text.replace('127.0.0.1:18081', f'127.0.0.1:{backend.server_port}')
            text = text.replace('127.0.0.1:18080', f'127.0.0.1:{port}')
            p.write_text(text, encoding='utf-8')
        command = [executable, '-p', temp.as_posix()+'/', '-c', 'nginx.conf']
        def fetch(path, method='GET', data=None, headers=None):
            req = request.Request(f'http://127.0.0.1:{port}'+path, data=data,
                                  method=method, headers=headers or {})
            try:
                with opener.open(req, timeout=3) as response:
                    return response.status, response.read()
            except error.HTTPError as exc:
                return exc.code, exc.read()
        try:
            check = subprocess.run(command+['-t'], cwd=temp, capture_output=True, creationflags=flags)
            if check.returncode:
                raise RuntimeError('nginx -t failed: '+check.stderr.decode(errors='replace'))
            process = subprocess.Popen(command+['-g', 'daemon off;'], cwd=temp,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
            for _ in range(100):
                try:
                    if fetch('/health')[0] == 200: break
                except OSError:
                    pass
                if process.poll() is not None:
                    raise RuntimeError('Test Nginx exited before readiness')
                time.sleep(.05)
            else:
                raise RuntimeError('Test Nginx readiness timed out')
            cases = [('/health', 200), ('/assets/photo.png', 200),
                     ('/app/page;jsessionid=demo', 200),
                     ('/normal?next=/a/..;/foo', 200),
                     ('/.env', 403), ('/.git/config', 403),
                     ('/uploads/test.jsp', 403), ('/files/test.JSPX;extra', 403),
                     ('/uploads/test%2Ejsp', 403), ('/a/..;/admin', 403),
                     ('/a/%2e%2e%3b/admin', 403), ('/a/%252e%252e/admin', 403),
                     ('/actuator/env', 403)]
            for path, expected in cases:
                status, _ = fetch(path)
                if status != expected:
                    raise AssertionError(f'{path}: expected {expected}, got {status}')
            status, payload = fetch('/health', headers={'X-Forwarded-For': '198.51.100.99'})
            if status != 200 or json.loads(payload)['forwarded_for'] != '127.0.0.1':
                raise AssertionError('Client-controlled forwarding header was trusted')
            status, _ = fetch('/business/callback?token=SYNTHETIC_QUERY_MARKER', 'POST',
                              b'{"body":"SYNTHETIC_BODY_MARKER"}', {'Content-Type': 'application/json'})
            if status != 200:
                raise AssertionError('Normal JSON callback was rejected')
            log = (temp/'logs/access.log').read_text(encoding='utf-8')
            if 'SYNTHETIC_QUERY_MARKER' in log or 'SYNTHETIC_BODY_MARKER' in log:
                raise AssertionError('Default access log included body or query')
            rows = [json.loads(line) for line in log.splitlines()]
            if not rows or any('request_id' not in row for row in rows):
                raise AssertionError('Structured logging contract was not satisfied')
            print(json.dumps({'syntax': 'passed', 'http_cases': len(cases)+2,
                              'json_logging': 'passed', 'forwarded_header': 'passed',
                              'body_and_query_omitted': True}))
        finally:
            if process is not None and process.poll() is None:
                subprocess.run(command+['-s', 'quit'], cwd=temp, capture_output=True,
                               creationflags=flags, timeout=10)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=5)
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=3)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
