"""Push the 1Panel WAF global blacklist to a Sangfor AF firewall (AF 8.0.107 RESTful API).

API used (AF API 帮助文档):
  2.1 POST /api/v1/namespaces/{ns}/login             {"name","password"} -> data.loginResult.token
  2.2 POST /api/v1/namespaces/{ns}/logout
  8.2.1 GET  /api/v1/namespaces/{ns}/whiteblacklist?type=BLACK&_start=&_length=   (max 200 per page)
  8.2.4 POST /api/batch/v1/namespaces/{ns}/whiteblacklist?override=SKIP   [{"url","type":"BLACK","description"}]
  8.2.5 DELETE /api/v1/namespaces/{ns}/whiteblacklist/{url}
Requests carry the token as `Cookie: token=...`. Only entries whose description starts
with MARK were created here; other AF entries are never modified or removed.
"""
from datetime import datetime
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import socket
from pathlib import Path
import re
import ssl
import threading
import time
from urllib import error, parse, request

from security import SETTINGS_LOCK, SecurityError, settings as ai_settings

MARK = 'LovelyLivelog'
LOG = logging.getLogger('af')
LOG_NAME = 'af.log'


def setup_log(directory):
    """runtime/af.log: every AF request and the exact failure cause; never passwords or tokens."""
    path = Path(directory) / LOG_NAME
    if any(getattr(h, 'baseFilename', '') == str(path.resolve()) for h in LOG.handlers):
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(path, maxBytes=1024 * 1024, backupCount=3, encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)
    return path


def failure_reason(exc):
    """Readable cause of a failed request, from the innermost socket / TLS error."""
    reason = exc.reason if isinstance(exc, error.URLError) and not isinstance(exc, error.HTTPError) else exc
    if isinstance(reason, ssl.SSLCertVerificationError):
        return ('证书校验失败（' + (reason.verify_message or '证书不受信任') + '）。AF 使用自签名证书时，'
                '请取消勾选“校验 HTTPS 证书”后保存')
    if isinstance(reason, ssl.SSLError):
        return f'TLS 握手失败（{reason.reason or reason}），请确认端口是 AF 的 HTTPS 管理端口'
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return '连接或读取超时，请检查网络、AF 管理口的访问控制，或本机代理 / VPN 软件是否接管了该地址'
    if isinstance(reason, ConnectionRefusedError):
        return '连接被拒绝，该端口没有开放 HTTPS 管理服务'
    if isinstance(reason, ConnectionResetError):
        return '连接被重置，可能被 AF 的管理口访问控制拦截'
    if isinstance(reason, socket.gaierror):
        return '无法解析地址'
    return f'{type(reason).__name__}: {reason}'[:300]
FIELDS = {'enabled': 'AF_ENABLED', 'url': 'AF_URL', 'username': 'AF_USERNAME', 'password': 'AF_PASSWORD',
          'namespace': 'AF_NAMESPACE', 'verifyTls': 'AF_VERIFY_TLS', 'interval': 'AF_INTERVAL',
          'remove': 'AF_REMOVE', 'includePrivate': 'AF_INCLUDE_PRIVATE'}
BATCH = 100
MAX_REMOVALS = 200
# AF rejects these characters in a black/whitelist description (code 22).
DESCRIPTION_FORBIDDEN = re.compile('[\f\n\r\t\v`~!#$%^&*+=\\\\|;:"\',/<>?]')
ERRORS = {1: 'AF 账号或密码错误，或认证失败。', 13: 'AF 账号缺少该接口的 WEB API 权限。',
          1010: 'AF 账号密码已过期：请用该账号登录 AF 网页修改密码，再在此处填写新密码并保存。',
          1003: 'AF 登录状态已失效。', 1004: 'AF 资源不存在。', 1012: 'AF 登录状态错误。'}


def af_settings(root):
    values = {}
    path = Path(root) / '.env'
    with SETTINGS_LOCK:
        if path.exists():
            for line in path.read_text(encoding='utf-8-sig').splitlines():
                if '=' in line and not line.lstrip().startswith('#'):
                    key, value = line.split('=', 1)
                    values[key.strip()] = value.strip().strip('"\'')
    values.update({key: os.environ[key] for key in FIELDS.values() if key in os.environ})
    flag = lambda key, default: values.get(key, default).lower() == 'true'
    try:
        interval = int(values.get('AF_INTERVAL', '300'))
    except ValueError:
        interval = 300
    return {'enabled': flag('AF_ENABLED', 'false'), 'url': values.get('AF_URL', '').rstrip('/'),
            'username': values.get('AF_USERNAME', ''), 'password': values.get('AF_PASSWORD', ''),
            'namespace': values.get('AF_NAMESPACE', 'public') or 'public', 'verifyTls': flag('AF_VERIFY_TLS', 'true'),
            'interval': min(86400, max(60, interval)), 'remove': flag('AF_REMOVE', 'true'),
            'includePrivate': flag('AF_INCLUDE_PRIVATE', 'false')}


def check_url(value):
    if not value:
        raise ValueError('请先填写 AF 地址并保存，例如 https://10.30.40.2。')
    if not value.isascii():
        raise ValueError('AF 地址含有中文冒号、全角字符或空格，请改为半角输入，例如 https://10.30.40.2:443。')
    parts = parse.urlsplit(value)
    if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or
            parts.path not in ('', '/') or parts.query or parts.fragment or len(value) > 200):
        raise ValueError('AF 地址应为 https://设备IP[:端口]，不包含路径和账号。')


def save_af_settings(root, body):
    if not isinstance(body, dict):
        raise ValueError('设置格式不正确。')
    updates = {}
    for key, target in FIELDS.items():
        if key not in body or (key == 'password' and not body[key]):
            continue  # An empty password keeps the saved one.
        value = body[key]
        if key in ('enabled', 'verifyTls', 'remove', 'includePrivate'):
            if type(value) is not bool:
                raise ValueError('开关设置必须是布尔值。')
            value = str(value).lower()
        elif key == 'interval':
            if type(value) is not int or not 60 <= value <= 86400:
                raise ValueError('同步间隔应为 60–86400 秒。')
            value = str(value)
        else:
            if not isinstance(value, str) or len(value) > 512 or any(c in value for c in '\r\n\x00'):
                raise ValueError('AF 设置格式不正确。')
            value = value.strip()
            if key == 'url':
                value = value.rstrip('/')
                if value:
                    check_url(value)
            if key == 'namespace' and not re.fullmatch(r'[A-Za-z0-9_-]{1,15}', value):
                raise ValueError('命名空间一般为 public（1–15 个字母或数字）。')
            if key == 'username' and len(value) > 60:
                raise ValueError('AF 账户名最长 60 个字符。')
        updates[target] = value
    with SETTINGS_LOCK:
        path = Path(root) / '.env'
        original = path.read_text(encoding='utf-8-sig').splitlines() if path.exists() else []
        output, remaining = [], dict(updates)
        for line in original:
            name = line.split('=', 1)[0].strip() if '=' in line and not line.lstrip().startswith('#') else None
            if name in updates:
                if name in remaining:
                    output.append(f'{name}={remaining.pop(name)}')
            else:
                output.append(line)
        output.extend(f'{key}={value}' for key, value in remaining.items())
        temporary = Path(root) / '.env.tmp'
        temporary.write_text('\n'.join(output) + '\n', encoding='utf-8')
        os.replace(temporary, path)
        for key, value in updates.items():
            if key in os.environ:
                os.environ[key] = value
    return af_settings(root)


def description(text):
    return DESCRIPTION_FORBIDDEN.sub('', text)[:95]


def canonical(value):
    """Comparable form of an AF url / snapshot target: IP, CIDR network or start-end range."""
    value = str(value).strip()
    try:
        if '-' in value:
            first, last = (ipaddress.ip_address(v.strip()) for v in value.split('-', 1))
            return f'{first}-{last}'
        if '/' in value:
            network = ipaddress.ip_network(value, strict=False)
            return str(network.network_address) if network.num_addresses == 1 else str(network)
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value.lower()


def networks_of(target):
    """ip_network objects covering one target, for protection checks."""
    if '-' in target:
        first, last = (ipaddress.ip_address(v) for v in target.split('-', 1))
        return list(ipaddress.summarize_address_range(first, last))
    return [ipaddress.ip_network(target, strict=False)]


class AfClient:
    def __init__(self, config, timeout=15):
        check_url(config['url'])
        if not config['username'] or not config['password']:
            raise SecurityError('请填写 AF 的 WEB API 账号和密码。', 400)
        self.config, self.timeout, self.token = config, timeout, ''
        context = ssl.create_default_context()
        if not config['verifyTls']:
            # AF devices usually ship a self-signed certificate; the user opts in explicitly.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        # The AF is an internal device: never send its credentials through a system proxy.
        self.opener = request.build_opener(request.ProxyHandler({}), request.HTTPSHandler(context=context), NoRedirect())
        LOG.info('AF client %s namespace=%s verifyTls=%s user=%s', config['url'], config['namespace'],
                 config['verifyTls'], config['username'])

    def call(self, method, path, body=None, query=None, batch=False):
        base = '/api/batch/v1' if batch else '/api/v1'
        url = f"{self.config['url']}{base}/namespaces/{parse.quote(self.config['namespace'])}/{path}"
        if query:
            url += '?' + parse.urlencode(query)
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode('utf-8')
        headers = {'Accept': 'application/json'}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        if self.token:
            headers['Cookie'] = 'token=' + self.token
        req = request.Request(url, data=data, method=method, headers=headers)
        # Logged without the body (login carries the password) and without the token cookie.
        shown = url
        items = f' items={len(body)}' if isinstance(body, list) else ''
        began = time.monotonic()
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
                status = response.status
        except error.HTTPError as exc:
            snippet = exc.read(300).decode('utf-8', 'replace') if exc.fp else ''
            LOG.warning('%s %s%s -> HTTP %s %.2fs body=%r', method, shown, items, exc.code, time.monotonic() - began, snippet)
            raise SecurityError(f'AF 返回 HTTP {exc.code}，请检查地址、端口和 WEB API 是否开启。详见 runtime/af.log') from exc
        except (error.URLError, OSError) as exc:
            reason = failure_reason(exc)
            LOG.warning('%s %s%s -> FAILED %.2fs %s | %r', method, shown, items, time.monotonic() - began, reason,
                        getattr(exc, 'reason', exc))
            raise SecurityError(f'无法连接 AF：{reason}。') from exc
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            LOG.warning('%s %s%s -> HTTP %s not JSON body=%r', method, shown, items, status, raw[:300].decode('utf-8', 'replace'))
            raise SecurityError('AF 返回的不是 JSON，请确认地址指向 AF 的 API 端口。详见 runtime/af.log') from exc
        # Errors may be reported at the top level or nested inside data (文档 1.5).
        for level in (payload, payload.get('data') if isinstance(payload, dict) else None):
            if isinstance(level, dict) and 'code' in level and 'message' in level and level['code'] != 0:
                code = level['code']
                LOG.warning('%s %s%s -> HTTP %s AF code=%s message=%r %.2fs', method, shown, items, status, code,
                            str(level.get('message'))[:300], time.monotonic() - began)
                # Keep AF's own explanation; it names the offending field or character.
                raise SecurityError(ERRORS.get(code, f'AF 返回错误 {code}：{str(level.get("message"))[:200]}'))
        LOG.info('%s %s%s -> HTTP %s code=0 %.2fs', method, shown, items, status, time.monotonic() - began)
        data = payload.get('data')
        if isinstance(data, dict) and set(data) >= {'code', 'message', 'data'}:
            data = data['data']
        return data

    def login(self):
        data = self.call('POST', 'login', {'name': self.config['username'], 'password': self.config['password']})
        token = (data or {}).get('loginResult', {}).get('token') if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise SecurityError('AF 登录成功但没有返回 token。')
        self.token = token
        return data

    def logout(self):
        if self.token:
            try:
                self.call('POST', 'logout', {'loginResult': {'token': self.token}})
            except SecurityError:
                pass
            self.token = ''

    def blacklist(self):
        items, start = [], 0
        while True:
            page = self.call('GET', 'whiteblacklist', query={'type': 'BLACK', '_start': start, '_length': 200})
            batch = (page or {}).get('items') or []
            items.extend(batch)
            start += len(batch)
            total = (page or {}).get('totalItems', 0)
            if not batch or start >= total or start > 2000000:
                return items

    def add(self, entries):
        return self.call('POST', 'whiteblacklist', entries, query={'override': 'SKIP'}, batch=True)

    def delete(self, url):
        return self.call('DELETE', 'whiteblacklist/' + parse.quote(url, safe=''))


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class AfSync:
    """Mirror the WAF global blacklist into the AF permanent blacklist on a timer."""

    def __init__(self, root, store, blacklist, client_factory=AfClient):
        self.root, self.store, self.blacklist, self.factory = Path(root), store, blacklist, client_factory
        self.lock = threading.Lock()
        self.stop_event, self.wake_event = threading.Event(), threading.Event()
        self.sync_requested = threading.Event()
        self.thread, self.busy = None, False
        setup_log(self.root / 'runtime')
        with store.lock, store.db:
            store.db.executescript('''
                CREATE TABLE IF NOT EXISTS af_sync_status (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                INSERT OR IGNORE INTO af_sync_status VALUES(1, '{}');
                CREATE TABLE IF NOT EXISTS af_sync_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, target TEXT NOT NULL,
                    action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
            ''')

    def status(self):
        with self.store.lock:
            return json.loads(self.store.db.execute('SELECT value FROM af_sync_status WHERE id=1').fetchone()[0])

    def public(self):
        config = af_settings(self.root)
        config['passwordSet'] = bool(config.pop('password'))
        with self.store.lock:
            log = [dict(r) for r in self.store.db.execute('SELECT at,target,action,detail FROM af_sync_log ORDER BY id DESC LIMIT 100')]
        return {'settings': config, 'status': self.status(), 'busy': self.busy, 'log': log}

    def record(self, status, actions):
        with self.store.lock, self.store.db:
            self.store.db.execute('UPDATE af_sync_status SET value=? WHERE id=1', (json.dumps(status, ensure_ascii=False),))
            now = time.time()
            self.store.db.executemany('INSERT INTO af_sync_log(at,target,action,detail) VALUES(?,?,?,?)',
                                      [(now, target, action, detail) for target, action, detail in actions])
            self.store.db.execute('DELETE FROM af_sync_log WHERE id <= (SELECT COALESCE(MAX(id),0)-2000 FROM af_sync_log)')

    def protected(self, target, config):
        """Never push the panel, administrators, allowlisted or (by default) internal addresses."""
        ai = ai_settings(self.root)
        guarded = [ipaddress.ip_network(v, strict=False) for v in re.split(r'[,\s]+', ai['allowlist']) if v]
        panel = parse.urlsplit(os.environ.get('PANEL_URL', '') or self.panel_url()).hostname
        if panel:
            try:
                guarded.append(ipaddress.ip_network(panel))
            except ValueError:
                pass
        for network in networks_of(target):
            if any(network.overlaps(g) for g in guarded if g.version == network.version):
                return '命中保护名单 / 面板地址'
            address = network.network_address
            if address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local or address.is_reserved:
                return '保留或本机地址'
            if not config['includePrivate'] and (network.is_private or not network.is_global):
                return '内网地址（未开启“包含内网地址”）'
        return ''

    def panel_url(self):
        path = self.root / '.env'
        for line in path.read_text(encoding='utf-8-sig').splitlines() if path.exists() else []:
            if line.split('=', 1)[0].strip() == 'PANEL_URL':
                return line.split('=', 1)[1].strip().strip('"\'')
        return ''

    def read_log(self, lines=200):
        path = self.root / 'runtime' / LOG_NAME
        if not path.is_file():
            return ''
        with path.open(encoding='utf-8', errors='replace') as stream:
            return ''.join(stream.readlines()[-lines:])

    def test(self):
        LOG.info('connection test started')
        try:
            client = self.factory(af_settings(self.root))
        except (ValueError, SecurityError) as exc:
            LOG.warning('connection test not started: %s', exc)
            raise
        try:
            login = client.login()
            items = client.blacklist()
            ours = sum(str(i.get('description', '')).startswith(MARK) for i in items)
            LOG.info('connection test ok: role=%s blacklist=%s managed=%s', login.get('role', ''), len(items), ours)
            return {'ok': True, 'role': login.get('role', ''), 'blacklist': len(items), 'managed': ours}
        finally:
            client.logout()

    def sync(self, manual=False):
        if not self.lock.acquire(blocking=False):
            raise SecurityError('AF 同步正在进行，请稍候。', 409)
        self.busy, began, actions = True, time.time(), []
        status = {'at': began, 'ok': False, 'manual': manual}
        try:
            config = af_settings(self.root)
            snapshot = self.blacklist.snapshot()  # Raises unless the WAF list is complete.
            desired, skipped = {}, 0
            for target in snapshot['targets']:
                reason = self.protected(target, config)
                if reason:
                    skipped += 1
                    actions.append((target, 'skipped', reason))
                else:
                    desired[canonical(target)] = target
            client = self.factory(config)
            client.login()
            try:
                current = client.blacklist()
                ours, others = {}, set()
                for item in current:
                    key = canonical(item.get('url', ''))
                    if str(item.get('description', '')).startswith(MARK):
                        ours[key] = item['url']
                    else:
                        others.add(key)
                stamp = datetime.now().strftime('%Y%m%d-%H%M')
                pending = [desired[k] for k in desired if k not in ours and k not in others]
                added = 0
                for start in range(0, len(pending), BATCH):
                    chunk = pending[start:start + BATCH]
                    client.add([{'url': t, 'type': 'BLACK', 'enable': True,
                                 'description': description(f'{MARK} 1Panel WAF 黑名单同步 {stamp}')} for t in chunk])
                    added += len(chunk)
                    actions.extend((t, 'added', '已加入 AF 黑名单') for t in chunk)
                removed, stale = 0, [ours[k] for k in ours if k not in desired]
                if stale and config['remove']:
                    if not desired:
                        # An empty source list is more likely an upstream fault than an intended mass unblock.
                        actions.append(('—', 'held', f'WAF 名单为空，暂不移除 AF 中本程序添加的 {len(stale)} 条'))
                    else:
                        for url in stale[:MAX_REMOVALS]:
                            client.delete(url)
                            removed += 1
                            actions.append((url, 'removed', 'WAF 名单已无此地址，已从 AF 移除'))
                verify = {canonical(i.get('url', '')) for i in client.blacklist()}
                missing = [desired[k] for k in desired if k not in verify]
                actions.extend((t, 'missing', 'AF 查询未找到，下一轮重试') for t in missing[:50])
                status.update(ok=not missing, total=len(snapshot['targets']), desired=len(desired), skipped=skipped,
                              added=added, removed=removed, existing=sum(k in others for k in desired),
                              managed=len(ours) + added - removed, missing=len(missing),
                              afTotal=len(verify), error='' if not missing else f'{len(missing)} 个地址写入后未查询到。')
            finally:
                client.logout()
        except SecurityError as exc:
            status['error'] = str(exc)
            LOG.warning('sync failed: %s', exc)
            raise
        except Exception as exc:
            status['error'] = 'AF 同步失败：' + type(exc).__name__
            LOG.exception('sync failed unexpectedly')
            raise SecurityError(status['error'] + '，详见 runtime/af.log') from exc
        finally:
            status['duration'] = round(time.time() - began, 2)
            LOG.info('sync %s: %s', 'ok' if status['ok'] else 'incomplete',
                     {k: status[k] for k in ('desired', 'added', 'removed', 'skipped', 'missing') if k in status})
            self.record(status, actions[-500:])
            self.busy = False
            self.lock.release()
        return self.public()

    def request_sync(self):
        """A new verified WAF entry can be mirrored without waiting for the timer."""
        self.sync_requested.set()
        self.wake_event.set()

    def run(self):
        while not self.stop_event.is_set():
            config = af_settings(self.root)
            last = self.status().get('at', 0)
            if config['enabled'] and (self.sync_requested.is_set() or time.time() - last >= config['interval']):
                self.sync_requested.clear()
                try:
                    self.sync()
                except Exception:
                    pass  # Status row holds the error; retry next interval.
            self.wake_event.wait(30)
            self.wake_event.clear()

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True, name='af-sync')
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.wake_event.set()
