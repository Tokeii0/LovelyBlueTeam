"""Build public honeypots and test loopback HTTP/CLI; optionally test Nginx."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
from urllib import error, request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FLAGS = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nginx', help='Optional native Nginx executable')
    args = parser.parse_args()
    if not shutil.which('go'): parser.error('go is required')
    nginx = None
    if args.nginx:
        nginx = str(Path(shutil.which(args.nginx) or args.nginx).resolve())
        if not Path(nginx).is_file(): parser.error('Nginx executable not found')
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    processes = []
    nginx_command = nginx_process = None
    cases = 0
    with tempfile.TemporaryDirectory(prefix='blue-team-honeypots-', dir=ROOT.parent) as directory, ExitStack() as stack:
        temp = Path(directory)
        def run(command, cwd=temp, expected=0):
            result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                    encoding='utf-8', creationflags=FLAGS, timeout=120)
            if result.returncode != expected:
                raise AssertionError(f'Command failed: {command[0]} (exit {result.returncode})\n{result.stderr}')
            return result.stdout

        def fetch(port, path, method='GET', data=None, headers=None):
            nonlocal cases
            cases += 1
            req = request.Request(f'http://127.0.0.1:{port}'+path, data=data, method=method, headers=headers or {})
            try:
                with opener.open(req, timeout=3) as response:
                    return response.status, response.read(), response.headers
            except error.HTTPError as exc:
                return exc.code, exc.read(), exc.headers

        def check(port, path, status=200, method='GET', data=None, headers=None):
            got, body, hdr = fetch(port, path, method, data, headers)
            if got != status: raise AssertionError(f'{method} {path}: {got} != {status}')
            return body, hdr

        def ready(port, process):
            for _ in range(100):
                if process.poll() is not None: raise AssertionError('Service exited during startup')
                try:
                    if fetch(port, '/healthz')[0] == 200: return
                except OSError: pass
                time.sleep(.05)
            raise AssertionError('Service readiness timeout')

        binaries = {}
        for name, target in [('vpn', './vpn'), ('uds', './uds-agent/cmd/portal'), ('cli', './uds-agent')]:
            path = temp/(name+('.exe' if os.name == 'nt' else ''))
            run(['go', 'build', '-trimpath', '-o', str(path), target], ROOT/'honeypots')
            binaries[name] = str(path)
        deps = run(['go', 'list', '-deps', './uds-agent'], ROOT/'honeypots').splitlines()
        if {'net', 'net/http', 'os/exec'} & set(deps):
            raise AssertionError('Offline CLI acquired network or child-process dependencies')
        cli_dir = temp/'cli-work'; cli_dir.mkdir()
        for command in [[], ['--help'], ['--version']]: run([binaries['cli'], *command], cli_dir)
        if list(cli_dir.iterdir()): raise AssertionError('Help/version created files')
        commands = [['status'], ['test'], ['sync'], ['auth'], ['run'], ['list'],
                    ['patient','TEST-PATIENT-001'], ['lis','TEST-LAB-001','cbc'],
                    ['invoke','ChannelService.ListAll'], ['conntest','demo://192.0.2.20:8220']]
        for command in commands:
            data = json.loads(run([binaries['cli'], *command, '--json'], cli_dir))
            if data.get('synthetic') is not True or data.get('host') != 'DEMO-HOST':
                raise AssertionError('CLI lost its synthetic identity marker')
        if list(cli_dir.iterdir()): raise AssertionError('Read-only simulation created files')
        run([binaries['cli'], 'unknown', '--config', 'missing.json'], cli_dir, expected=1)
        run([binaries['cli'], 'status', '--config', 'missing.json'], cli_dir, expected=1)
        run([binaries['cli'], 'export', 'fixture.json', '--json'], cli_dir)
        original = (cli_dir/'fixture.json').read_bytes()
        result = json.loads(run([binaries['cli'], 'export', 'fixture.json', '--json'], cli_dir, expected=2))
        if result['ok'] or (cli_dir/'fixture.json').read_bytes() != original:
            raise AssertionError('Export overwrote a file or hid failure')
        result = json.loads(run([binaries['cli'], 'diagnose', '--json'], cli_dir))
        with zipfile.ZipFile(cli_dir/result['result']['diagFile']) as archive:
            if set(archive.namelist()) != {'agent.log','channels.json','env.json'}:
                raise AssertionError('Unexpected diagnostic file')
            environment = json.loads(archive.read('env.json'))
            if environment['hostname'] != 'DEMO-HOST' or not environment['synthetic']:
                raise AssertionError('Diagnostic environment is not synthetic')

        ports = {}
        try:
            for name in ['vpn','uds']:
                port = free_port(); ports[name] = port
                stderr = stack.enter_context((temp/(name+'-stderr.txt')).open('wb'))
                proc = subprocess.Popen([binaries[name], '-listen', f'127.0.0.1:{port}',
                                         '-events', str(temp/(name+'-events.jsonl'))], cwd=temp,
                                        stdout=subprocess.DEVNULL, stderr=stderr, creationflags=FLAGS)
                processes.append(proc); ready(port,proc)
            for path in ['/', '/client', '/resources']: check(ports['vpn'], path)
            headers = {'Content-Type':'application/json'}
            check(ports['vpn'], '/api/login', 200, 'POST', b'{"user":"demo","password":"demo"}', headers)
            check(ports['vpn'], '/api/login', 401, 'POST', b'{"user":"fixture-account","password":"fixture-private"}', headers)
            payload,_ = check(ports['vpn'], '/api/connect', 200, 'POST', b'{"scenario":"demo"}', headers)
            if json.loads(payload).get('tunnel') is not False: raise AssertionError('VPN misreports a real tunnel')
            check(ports['vpn'], '/api/connect', 400, 'POST', b'{"scenario":"demo","screenshot":"fixture-screen"}', headers)
            check(ports['vpn'], '/api/host', 404, 'POST', b'{"hostPack":"fixture-host"}', headers)
            check(ports['vpn'], '/api/connect', 413, 'POST', b'{"scenario":"'+b'x'*17000+b'"}', headers)
            check(ports['uds'], '/portal', 302)
            _, hdr = check(ports['uds'], '/login', 303, 'POST', b'username=demo&password=demo', {'Content-Type':'application/x-www-form-urlencoded'})
            cookie = hdr['Set-Cookie'].split(';')[0]
            check(ports['uds'], '/portal', headers={'Cookie':cookie})
            check(ports['uds'], '/docs/download', headers={'Cookie':cookie})
            check(ports['uds'], '/download/agent', 404, headers={'Cookie':cookie})
            check(ports['uds'], '/logout', 303, 'POST', b'', {'Cookie':cookie})
            check(ports['uds'], '/portal', 302, headers={'Cookie':cookie})
            for name in ports: check(ports[name], '/fixture-private-path?token=fixture-private-query', 404)

            if nginx:
                proxy_dir = temp/'nginx'; proxy_dir.mkdir()
                (proxy_dir/'logs').mkdir(); (proxy_dir/'temp').mkdir()
                config = (ROOT/'configs/nginx/honeypots/nginx.conf').read_text(encoding='utf-8')
                fronts = {}
                for name, upstream, front in [('vpn',8801,8811),('uds',8802,8812)]:
                    fronts[name]=free_port()
                    config=config.replace(f'127.0.0.1:{upstream}',f'127.0.0.1:{ports[name]}')
                    config=config.replace(f'127.0.0.1:{front}',f'127.0.0.1:{fronts[name]}')
                (proxy_dir/'nginx.conf').write_text(config,encoding='utf-8')
                nginx_command=[nginx,'-p',proxy_dir.as_posix()+'/', '-c','nginx.conf']
                run(nginx_command+['-t'],proxy_dir)
                nginx_process=subprocess.Popen(nginx_command+['-g','daemon off;'],cwd=proxy_dir,
                                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=FLAGS)
                ready(fronts['vpn'],nginx_process)
                for name in fronts: check(fronts[name],'/healthz')
                # Non-standard browser ports must survive Host forwarding.
                same_origin={**headers,'Origin':f'http://127.0.0.1:{fronts["vpn"]}'}
                check(fronts['vpn'],'/api/login',200,'POST',b'{"user":"demo","password":"demo"}',same_origin)
                check(fronts['vpn'],'/api/login',403,'POST',b'{}',{**headers,'Origin':'https://fixture.invalid'})
                check(fronts['uds'],'/fixture-private-path?token=fixture-private-query',404)
                check(fronts['uds'],'/api/auth/token',413,'POST',b'x'*17000,headers)
                log=(proxy_dir/'logs/honeypots.jsonl').read_text(encoding='utf-8')
                if any(x in log for x in ['fixture-private','password','127.0.0.1']):
                    raise AssertionError('Proxy access log contains private fields')
                if not all('route' in json.loads(line) for line in log.splitlines()):
                    raise AssertionError('Proxy log schema mismatch')
            for name in ports:
                log=(temp/(name+'-events.jsonl')).read_text(encoding='utf-8')
                if any(x in log for x in ['fixture-','password','127.0.0.1',cookie]):
                    raise AssertionError('Service event contains private fields')
                if not all('peer_tag' in json.loads(line) for line in log.splitlines()):
                    raise AssertionError('Service event schema mismatch')
            print(json.dumps({'builds':3,'cli_scenarios':len(commands),'http_requests':cases,
                              'offline_dependency_check':'passed','minimal_events':'passed',
                              'nginx':'passed' if nginx else 'not requested'}))
        finally:
            if nginx_process is not None and nginx_process.poll() is None:
                subprocess.run(nginx_command+['-s','quit'],cwd=temp/'nginx',capture_output=True,
                               creationflags=FLAGS,timeout=10)
                try: nginx_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    nginx_process.terminate();nginx_process.wait(timeout=5)
            for proc in reversed(processes):
                if proc.poll() is None: proc.terminate()
                proc.wait(timeout=10)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
