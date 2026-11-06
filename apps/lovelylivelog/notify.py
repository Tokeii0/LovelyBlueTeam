"""Keyword alerts: a stored log line containing a rule's keywords is pushed to QQ groups through NapCat.

NapCat exposes the OneBot 11 HTTP API: POST {url}/{action} with `Authorization: Bearer <token>`.
  get_login_info   -> data.user_id, data.nickname
  get_group_list   -> data[].group_id, group_name, member_count
  send_group_msg   {"group_id", "message": [{"type": "text", "data": {"text"}}]} -> data.message_id
Hits of one rule within its cooldown are merged into the next message, so a burst never floods a group.
"""
from datetime import datetime
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import socket
import threading
import time
from urllib import error, parse, request

from security import SETTINGS_LOCK, SecurityError, normalized_event

LOG = logging.getLogger('notify')
FIELDS = {'enabled': 'NAPCAT_ENABLED', 'url': 'NAPCAT_URL', 'token': 'NAPCAT_TOKEN'}
KINDS = ('access.log', 'error.log', 'custom.log')
PLACEHOLDERS = ('rule', 'keyword', 'source', 'kind', 'time', 'ip', 'geo', 'method', 'path', 'status', 'count', 'raw')
DEFAULT_TEMPLATE = ('【日志告警】{rule}\n来源：{source}（{kind}）\n时间：{time}\n命中关键词：{keyword}\n'
                    'IP：{ip}（{geo}）  状态：{status}\n请求：{method} {path}\n本次合并 {count} 条\n{raw}')
MAX_RULES, MAX_GROUPS, MAX_KEYWORDS, MAX_MENTIONS = 50, 20, 30, 20
MAX_MESSAGE, MAX_RAW = 3000, 600
BATCH, SENDS_PER_ROUND, MAX_ATTEMPTS = 5000, 30, 6


def setup_log(directory):
    """runtime/notify.log: every NapCat request result; never the token."""
    path = Path(directory) / 'notify.log'
    if any(getattr(h, 'baseFilename', '') == str(path.resolve()) for h in LOG.handlers):
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(path, maxBytes=1024 * 1024, backupCount=3, encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)
    return path


def notify_settings(root):
    values = {}
    path = Path(root) / '.env'
    with SETTINGS_LOCK:
        if path.exists():
            for line in path.read_text(encoding='utf-8-sig').splitlines():
                if '=' in line and not line.lstrip().startswith('#'):
                    key, value = line.split('=', 1)
                    values[key.strip()] = value.strip().strip('"\'')
    values.update({key: os.environ[key] for key in FIELDS.values() if key in os.environ})
    return {'enabled': values.get('NAPCAT_ENABLED', 'false').lower() == 'true',
            'url': values.get('NAPCAT_URL', 'http://127.0.0.1:3000').rstrip('/'),
            'token': values.get('NAPCAT_TOKEN', '')}


def check_url(value):
    if not value.isascii():
        raise ValueError('NapCat 地址含有中文或全角字符，请改为半角输入，例如 http://127.0.0.1:3000。')
    parts = parse.urlsplit(value)
    if (parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password or
            parts.query or parts.fragment or len(value) > 200):
        raise ValueError('NapCat 地址应为 http://IP:端口，例如 http://127.0.0.1:3000，不包含账号和参数。')


def save_notify_settings(root, body):
    if not isinstance(body, dict):
        raise ValueError('设置格式不正确。')
    updates = {}
    for key, target in FIELDS.items():
        if key not in body or (key == 'token' and not body[key]):
            continue  # An empty token keeps the saved one.
        value = body[key]
        if key == 'enabled':
            if type(value) is not bool:
                raise ValueError('开关设置必须是布尔值。')
            value = str(value).lower()
        else:
            if not isinstance(value, str) or len(value) > 512 or any(c in value for c in '\r\n\x00'):
                raise ValueError('NapCat 设置格式不正确。')
            value = value.strip()
            if key == 'url':
                value = value.rstrip('/')
                check_url(value)
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
    return notify_settings(root)


class NapCatClient:
    def __init__(self, config, timeout=10):
        check_url(config['url'])
        self.config, self.timeout = config, timeout

    def call(self, action, body=None):
        headers = {'Content-Type': 'application/json'}
        if self.config['token']:
            headers['Authorization'] = 'Bearer ' + self.config['token']
        req = request.Request(f"{self.config['url']}/{action}", data=json.dumps(body or {}).encode('utf-8'),
                              headers=headers, method='POST')
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read(2 * 1024 * 1024))
        except error.HTTPError as exc:
            if exc.code in (401, 403):
                raise SecurityError('NapCat token 不正确：请填写 NapCat 网络配置中 HTTP 服务的 token。', 400) from None
            if exc.code == 404:
                raise SecurityError('NapCat 地址不对：该端口没有 OneBot HTTP 接口，请确认 NapCat 已启用 HTTP 服务器。', 400) from None
            raise SecurityError(f'NapCat 返回 HTTP {exc.code}。') from None
        except (error.URLError, socket.timeout, TimeoutError, ConnectionError) as exc:
            reason = exc.reason if isinstance(exc, error.URLError) else exc
            if isinstance(reason, ConnectionRefusedError):
                raise SecurityError('无法连接 NapCat：连接被拒绝，请确认 NapCat 正在运行且 HTTP 服务端口正确。', 503) from None
            raise SecurityError(f'无法连接 NapCat：{type(reason).__name__}。', 503) from None
        except ValueError:
            raise SecurityError('NapCat 返回的不是 JSON，请确认地址是 OneBot HTTP 接口。') from None
        if not isinstance(data, dict) or data.get('status') != 'ok' or data.get('retcode') not in (0, None):
            message = str((data or {}).get('message') or (data or {}).get('wording') or '') if isinstance(data, dict) else ''
            raise SecurityError(f"NapCat 执行 {action} 失败（retcode {data.get('retcode') if isinstance(data, dict) else '?'}）"
                                + (f'：{message[:200]}' if message else '。'))
        return data.get('data')

    def login(self):
        data = self.call('get_login_info') or {}
        return {'userId': data.get('user_id'), 'nickname': str(data.get('nickname') or '')}

    def groups(self):
        return [{'id': int(g['group_id']), 'name': str(g.get('group_remark') or g.get('group_name') or g['group_id']),
                 'members': g.get('member_count')} for g in (self.call('get_group_list') or []) if 'group_id' in g]

    def members(self, group_id):
        # NapCat loads a group's member list lazily: the first request can come back empty.
        data = []
        for attempt in range(3):
            data = self.call('get_group_member_list', {'group_id': group_id}) or []
            if data:
                break
            time.sleep(1)
        members = [{'id': int(m['user_id']), 'name': str(m.get('card') or m.get('nickname') or m['user_id']),
                    'nickname': str(m.get('nickname') or ''), 'role': str(m.get('role') or 'member')}
                   for m in data if isinstance(m, dict) and 'user_id' in m and not m.get('is_robot')]
        return sorted(members, key=lambda m: (m['role'] not in ('owner', 'admin'), m['name']))

    def send(self, group_id, text, mentions=(), mention_all=False):
        """One group message: the @ segments on the first line, then the alert text."""
        segments = ([{'type': 'at', 'data': {'qq': 'all'}}] if mention_all else []) + \
                   [{'type': 'at', 'data': {'qq': str(qq)}} for qq in mentions]
        segments.append({'type': 'text', 'data': {'text': ('\n' if segments else '') + text}})
        data = self.call('send_group_msg', {'group_id': group_id, 'message': segments})
        return (data or {}).get('message_id')


def clean_text_list(value, label, limit, length):
    if isinstance(value, str):
        value = re.split(r'[\n,，]+', value)
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f'{label}最多 {limit} 个。')
    items = []
    for item in value:
        if not isinstance(item, str) or len(item.strip()) > length or any(c in item for c in '\r\x00'):
            raise ValueError(f'{label}格式不正确，每个最长 {length} 个字符。')
        if item.strip() and item.strip() not in items:
            items.append(item.strip())
    return items


def clean_mentions(value):
    """QQ numbers to @ in each alert."""
    if not isinstance(value, list) or len(value) > MAX_MENTIONS or \
            any(type(q) is not int or not 10000 <= q <= 10 ** 11 for q in value):
        raise ValueError(f'@ 成员应为 QQ 号，最多 {MAX_MENTIONS} 个。')
    return list(dict.fromkeys(value))


def render(template, values):
    """Fill {placeholders}; unknown braces are kept as typed."""
    text = re.sub(r'\{(\w+)\}', lambda m: str(values.get(m[1], m[0])), template)
    return text if len(text) <= MAX_MESSAGE else text[:MAX_MESSAGE - 1] + '…'


class KeywordNotifier:
    def __init__(self, root, store, site_names=None, factory=NapCatClient, geo=None):
        self.root, self.store, self.factory, self.geo = Path(root), store, factory, geo
        self.site_names = site_names or (lambda: {})
        self.stop_event, self.wake_event = threading.Event(), threading.Event()
        self.thread, self.last_error, self.names, self.names_at = None, '', {}, 0
        setup_log(self.root / 'runtime')
        with store.lock, store.db:
            store.db.executescript('''
                CREATE TABLE IF NOT EXISTS notify_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, keywords TEXT NOT NULL,
                    match_all INTEGER NOT NULL DEFAULT 0, kinds TEXT NOT NULL, sources TEXT NOT NULL,
                    groups TEXT NOT NULL, template TEXT NOT NULL, cooldown INTEGER NOT NULL DEFAULT 60,
                    enabled INTEGER NOT NULL DEFAULT 1, hits INTEGER NOT NULL DEFAULT 0, last_hit REAL,
                    pending INTEGER NOT NULL DEFAULT 0, pending_values TEXT NOT NULL DEFAULT '',
                    last_sent REAL NOT NULL DEFAULT 0, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS notify_cursor (source TEXT PRIMARY KEY, last_id INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS notify_outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER NOT NULL, rule_name TEXT NOT NULL,
                    group_id INTEGER NOT NULL, message TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                    retry_at REAL NOT NULL DEFAULT 0, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS notify_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, rule_name TEXT NOT NULL,
                    group_id INTEGER NOT NULL, ok INTEGER NOT NULL, detail TEXT NOT NULL, preview TEXT NOT NULL);
            ''')
            for table, columns in (('notify_rules', {'mentions': "TEXT NOT NULL DEFAULT '[]'", 'mention_all': 'INTEGER NOT NULL DEFAULT 0'}),
                                   ('notify_outbox', {'mentions': "TEXT NOT NULL DEFAULT '[]'", 'mention_all': 'INTEGER NOT NULL DEFAULT 0'})):
                existing = {r['name'] for r in store.db.execute(f'PRAGMA table_info({table})')}
                for name, definition in columns.items():
                    if name not in existing:
                        store.db.execute(f'ALTER TABLE {table} ADD COLUMN {name} {definition}')
            # Alerts start from the rows stored now; history is never pushed.
            for table in ('events', 'agent_events'):
                store.db.execute('INSERT OR IGNORE INTO notify_cursor VALUES(?,(SELECT COALESCE(MAX(id),0) FROM %s))' % table,
                                 (table,))

    # ----- rules -----
    @staticmethod
    def row_rule(row):
        item = dict(row)
        for key in ('keywords', 'kinds', 'sources', 'groups', 'mentions'):
            item[key] = json.loads(item[key])
        item['matchAll'], item['enabled'] = bool(item.pop('match_all')), bool(item['enabled'])
        item['mentionAll'] = bool(item.pop('mention_all'))
        item['lastHit'], item['lastSent'] = item.pop('last_hit'), item.pop('last_sent')
        item.pop('pending_values')
        return item

    def rules(self):
        with self.store.lock:
            return [self.row_rule(r) for r in self.store.db.execute('SELECT * FROM notify_rules ORDER BY id')]

    def validate(self, body):
        name = body.get('name')
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 60:
            raise ValueError('规则名称应为 1–60 个字符。')
        keywords = clean_text_list(body.get('keywords', []), '关键词', MAX_KEYWORDS, 200)
        if not keywords:
            raise ValueError('至少填写一个关键词。')
        kinds = body.get('kinds') or list(KINDS)
        if not isinstance(kinds, list) or any(k not in KINDS for k in kinds):
            raise ValueError('日志类型不正确。')
        sources = body.get('sources') or []
        if (not isinstance(sources, list) or len(sources) > 200 or
                any(not isinstance(s, str) or not re.fullmatch(r'site:\d{1,9}|agent:[0-9a-f-]{36}', s) for s in sources)):
            raise ValueError('日志来源不正确，请重新选择。')
        groups = body.get('groups')
        if (not isinstance(groups, list) or not 1 <= len(groups) <= MAX_GROUPS or
                any(type(g) is not int or not 10000 <= g <= 10 ** 12 for g in groups)):
            raise ValueError(f'请选择 1–{MAX_GROUPS} 个推送群聊。')
        template = body.get('template') or DEFAULT_TEMPLATE
        if not isinstance(template, str) or len(template) > 2000 or '\x00' in template:
            raise ValueError('推送内容最长 2000 个字符。')
        cooldown = body.get('cooldown', 60)
        if type(cooldown) is not int or not 0 <= cooldown <= 86400:
            raise ValueError('合并间隔应为 0–86400 秒。')
        if any(type(body.get(k, False)) is not bool for k in ('matchAll', 'enabled', 'mentionAll')):
            raise ValueError('开关设置必须是布尔值。')
        mentions = clean_mentions(body.get('mentions', []))
        return {'name': name.strip(), 'keywords': json.dumps(keywords, ensure_ascii=False),
                'match_all': int(body.get('matchAll', False)), 'kinds': json.dumps([k for k in KINDS if k in kinds]),
                'sources': json.dumps(sorted(set(sources))), 'groups': json.dumps(list(dict.fromkeys(groups))),
                'template': template.replace('\r\n', '\n'), 'cooldown': cooldown, 'enabled': int(body.get('enabled', True)),
                'mentions': json.dumps(mentions), 'mention_all': int(body.get('mentionAll', False))}

    def save(self, body):
        data = self.validate(body)
        rule_id = body.get('id')
        with self.store.lock, self.store.db:
            if rule_id is None:
                if self.store.db.execute('SELECT COUNT(*) FROM notify_rules').fetchone()[0] >= MAX_RULES:
                    raise ValueError(f'最多 {MAX_RULES} 条推送规则。')
                self.store.db.execute(f'INSERT INTO notify_rules({",".join(data)},created) VALUES({",".join("?" * len(data))},?)',
                                      (*data.values(), time.time()))
            else:
                if type(rule_id) is not int:
                    raise ValueError('规则编号不正确。')
                result = self.store.db.execute(f'UPDATE notify_rules SET {",".join(k + "=?" for k in data)} WHERE id=?',
                                               (*data.values(), rule_id))
                if not result.rowcount:
                    raise ValueError('规则不存在，请刷新页面。')
        self.wake_event.set()
        return self.public()

    def delete(self, rule_id):
        if type(rule_id) is not int:
            raise ValueError('规则编号不正确。')
        with self.store.lock, self.store.db:
            if not self.store.db.execute('DELETE FROM notify_rules WHERE id=?', (rule_id,)).rowcount:
                raise ValueError('规则不存在，请刷新页面。')
            self.store.db.execute('DELETE FROM notify_outbox WHERE rule_id=?', (rule_id,))
        return self.public()

    # ----- matching -----
    def source_name(self, record):
        if record['source_type'] == 'agent':
            return record['server_name'] or '服务器'
        if time.time() - self.names_at > 300:
            try:
                self.names, self.names_at = self.site_names(), time.time()
            except Exception:
                self.names_at = time.time() - 240  # Panel unreachable: retry in a minute.
        return self.names.get(record['website']) or f"网站 #{record['website']}"

    def values(self, rule, record, found):
        event = normalized_event(record) if record['kind'] == 'access.log' else None
        raw = record['raw'] if len(record['raw']) <= MAX_RAW else record['raw'][:MAX_RAW] + '…'
        return {'rule': rule['name'], 'keyword': '、'.join(found), 'source': self.source_name(record),
                'kind': {'access.log': '访问日志', 'error.log': '错误日志'}.get(record['kind'], '应用日志'),
                'time': datetime.fromtimestamp(record['collected']).strftime('%Y-%m-%d %H:%M:%S'),
                'ip': event['ip'] if event else '—', 'geo': (self.geo.lookup(event['ip']) if event and self.geo else '') or '未知',
                'method': event['method'] if event else '—',
                'path': event['target'][:300] if event else '—', 'status': event['status'] if event else '—', 'raw': raw}

    @staticmethod
    def matched(rule, record):
        if record['kind'] not in rule['kinds']:
            return None
        if rule['sources']:
            source = f"agent:{record['agent_id']}" if record['source_type'] == 'agent' else f"site:{record['website']}"
            if source not in rule['sources']:
                return None
        text = record['raw'].lower()
        found = [k for k in rule['keywords'] if k.lower() in text]
        if not found or (rule['matchAll'] and len(found) < len(rule['keywords'])):
            return None
        return found

    def rows(self, table, after):
        if table == 'events':
            sql = '''SELECT id,id AS row_id,website,kind,raw,received AS collected,'panel' AS source_type,'' AS agent_id,
                     '' AS server_name,'' AS source_file FROM events WHERE id>? ORDER BY id LIMIT ?'''
        else:
            sql = '''SELECT -e.id AS id,e.id AS row_id,0 AS website,e.kind,e.raw,e.collected,'agent' AS source_type,
                     e.agent_id,a.name AS server_name,e.source AS source_file FROM agent_events e JOIN agents a ON a.id=e.agent_id
                     WHERE e.id>? ORDER BY e.id LIMIT ?'''
        with self.store.lock:
            return [dict(r) for r in self.store.db.execute(sql, (after, BATCH))]

    def scan(self, enabled=True):
        """Match new rows against enabled rules; returns True while a full batch suggests a backlog."""
        # While pushing is off, rows are skipped rather than queued, so enabling it never floods a group.
        rules = [r for r in self.rules() if r['enabled']] if enabled else []
        hits, more = {}, False
        for table in ('events', 'agent_events'):
            with self.store.lock:
                after = self.store.db.execute('SELECT last_id FROM notify_cursor WHERE source=?', (table,)).fetchone()[0]
            rows = self.rows(table, after) if rules else []
            last = rows[-1]['row_id'] if rows else after
            more = more or len(rows) == BATCH
            if not rules:
                with self.store.lock:
                    last = self.store.db.execute(f'SELECT COALESCE(MAX(id),0) FROM {table}').fetchone()[0]
            for record in rows:
                for rule in rules:
                    found = self.matched(rule, record)
                    if found:
                        item = hits.setdefault(rule['id'], {'count': 0})
                        item['count'] += 1
                        item['latest'] = self.values(rule, record, found)
            with self.store.lock, self.store.db:
                for rule_id, item in hits.items():
                    self.store.db.execute('''UPDATE notify_rules SET hits=hits+?,pending=pending+?,last_hit=?,
                        pending_values=? WHERE id=?''', (item['count'], item['count'], time.time(),
                                                         json.dumps(item['latest'], ensure_ascii=False), rule_id))
                self.store.db.execute('UPDATE notify_cursor SET last_id=? WHERE source=?', (max(last, after), table))
            hits.clear()
        return more

    def flush(self):
        """Turn each rule's merged hits into one message per group once its cooldown has passed."""
        now = time.time()
        with self.store.lock, self.store.db:
            due = [dict(r) for r in self.store.db.execute(
                'SELECT * FROM notify_rules WHERE enabled=1 AND pending>0 AND last_sent+cooldown<=?', (now,))]
            for rule in due:
                values = {**json.loads(rule['pending_values'] or '{}'), 'count': rule['pending']}
                message = render(rule['template'], values)
                self.store.db.executemany('''INSERT INTO notify_outbox(rule_id,rule_name,group_id,message,created,mentions,mention_all)
                    VALUES(?,?,?,?,?,?,?)''', [(rule['id'], rule['name'], g, message, now, rule['mentions'], rule['mention_all'])
                                               for g in json.loads(rule['groups'])])
                self.store.db.execute("UPDATE notify_rules SET pending=0,pending_values='',last_sent=? WHERE id=?", (now, rule['id']))

    def record(self, rule_name, group_id, ok, detail, message):
        with self.store.lock, self.store.db:
            self.store.db.execute('INSERT INTO notify_log(at,rule_name,group_id,ok,detail,preview) VALUES(?,?,?,?,?,?)',
                                  (time.time(), rule_name, group_id, int(ok), detail[:300], message[:300]))
            self.store.db.execute('DELETE FROM notify_log WHERE id <= (SELECT COALESCE(MAX(id),0)-1000 FROM notify_log)')

    def deliver(self, config):
        with self.store.lock:
            pending = [dict(r) for r in self.store.db.execute(
                'SELECT * FROM notify_outbox WHERE retry_at<=? ORDER BY id LIMIT ?', (time.time(), SENDS_PER_ROUND))]
        if not pending:
            return
        client = self.factory(config)
        for item in pending:
            try:
                message_id = client.send(item['group_id'], item['message'], json.loads(item['mentions']), bool(item['mention_all']))
            except SecurityError as exc:
                attempts = item['attempts'] + 1
                self.last_error = str(exc)
                LOG.warning('send to group %s failed (attempt %s): %s', item['group_id'], attempts, exc)
                with self.store.lock, self.store.db:
                    if attempts >= MAX_ATTEMPTS:
                        self.store.db.execute('DELETE FROM notify_outbox WHERE id=?', (item['id'],))
                    else:
                        self.store.db.execute('UPDATE notify_outbox SET attempts=?,retry_at=? WHERE id=?',
                                              (attempts, time.time() + min(1800, 30 * 2 ** attempts), item['id']))
                self.record(item['rule_name'], item['group_id'], False,
                            str(exc) + ('（已放弃）' if attempts >= MAX_ATTEMPTS else f'（第 {attempts} 次，稍后重试）'), item['message'])
                if exc.status in (400, 503):
                    break  # NapCat unreachable or misconfigured: the other messages wait for the next round.
                continue
            self.last_error = ''
            LOG.info('sent rule %r to group %s: message_id=%s', item['rule_name'], item['group_id'], message_id)
            with self.store.lock, self.store.db:
                self.store.db.execute('DELETE FROM notify_outbox WHERE id=?', (item['id'],))
            self.record(item['rule_name'], item['group_id'], True, '已推送', item['message'])

    # ----- API helpers -----
    def public(self):
        config = notify_settings(self.root)
        config['tokenSet'] = bool(config.pop('token'))
        with self.store.lock:
            log = [dict(r) for r in self.store.db.execute(
                'SELECT at,rule_name,group_id,ok,detail,preview FROM notify_log ORDER BY id DESC LIMIT 100')]
            queued = self.store.db.execute('SELECT COUNT(*) FROM notify_outbox').fetchone()[0]
        return {'settings': config, 'rules': self.rules(), 'log': log, 'queued': queued, 'error': self.last_error,
                'defaultTemplate': DEFAULT_TEMPLATE, 'placeholders': PLACEHOLDERS}

    def client(self):
        config = notify_settings(self.root)
        return self.factory(config)

    def test(self):
        client = self.client()
        login = client.login()
        groups = client.groups()
        LOG.info('connection test ok: bot=%s groups=%s', login['userId'], len(groups))
        return {**login, 'groups': len(groups)}

    def groups(self):
        return {'groups': self.client().groups()}

    def members(self, body):
        groups = body.get('groups')
        if not isinstance(groups, list) or not 1 <= len(groups) <= MAX_GROUPS or any(type(g) is not int for g in groups):
            raise ValueError('请先选择推送群聊，再从群成员中选择要 @ 的人。')
        client, members = self.client(), {}
        bot = client.login()['userId']  # The bot cannot usefully @ itself.
        for group_id in groups:
            for member in client.members(group_id):
                if member['id'] == bot:
                    continue
                item = members.setdefault(member['id'], {**member, 'groups': []})
                item['groups'].append(group_id)
        # Someone missing from a target group is shown as plain "@QQ号" there, not as a real mention.
        return {'members': sorted(members.values(), key=lambda m: (-len(m['groups']), m['role'] not in ('owner', 'admin'), m['name']))}

    def preview(self, body):
        template = body.get('template') or DEFAULT_TEMPLATE
        if not isinstance(template, str) or len(template) > 2000:
            raise ValueError('推送内容最长 2000 个字符。')
        sample = {'rule': str(body.get('name') or '示例规则')[:60], 'keyword': 'union select', 'source': '示例采集节点',
                  'kind': '访问日志', 'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'ip': '203.0.113.7',
                  'geo': 'Netherlands South Holland', 'method': 'GET', 'path': '/api/list?id=1 union select 1,2', 'status': 200, 'count': 3,
                  'raw': '203.0.113.7 - - [17/Oct/2026:20:15:02 +0800] "GET /api/list?id=1 union select 1,2 HTTP/1.1" 200 512'}
        return {'text': render(template, sample)}

    def send_test(self, body):
        """Send the rendered sample to the chosen groups now; the page asks for confirmation first."""
        groups = body.get('groups')
        if not isinstance(groups, list) or not 1 <= len(groups) <= MAX_GROUPS or any(type(g) is not int for g in groups):
            raise ValueError('请先选择要测试的群聊。')
        text = '【测试消息】\n' + self.preview(body)['text']
        mentions, mention_all = clean_mentions(body.get('mentions', [])), body.get('mentionAll', False)
        if type(mention_all) is not bool:
            raise ValueError('开关设置必须是布尔值。')
        client = self.client()
        sent = 0
        for group_id in groups:
            try:
                client.send(group_id, text, mentions, mention_all)
                sent += 1
                self.record('测试消息', group_id, True, '已推送', text)
            except SecurityError as exc:
                self.record('测试消息', group_id, False, str(exc), text)
                raise
        return {'sent': sent}

    def read_log(self, lines=200):
        path = self.root / 'runtime' / 'notify.log'
        if not path.is_file():
            return ''
        with path.open(encoding='utf-8', errors='replace') as stream:
            return ''.join(stream.readlines()[-lines:])

    # ----- worker -----
    def run(self):
        while not self.stop_event.is_set():
            more = False
            try:
                config = notify_settings(self.root)
                more = self.scan(config['enabled'])
                if config['enabled']:
                    self.flush()
                    self.deliver(config)
            except SecurityError as exc:
                self.last_error = str(exc)
            except Exception as exc:
                self.last_error = f'告警推送出错：{type(exc).__name__}'
                LOG.exception('notify round failed')
            if not more:
                self.wake_event.wait(5)
                self.wake_event.clear()

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True, name='keyword-notify')
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.wake_event.set()
