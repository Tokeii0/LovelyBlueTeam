"""Local UDP Syslog receiver for AF security logs. No browser session is required."""
from contextlib import closing
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import socket
import sqlite3
import threading
import time
from urllib.parse import urlsplit

from af_firewall import af_settings
from security import SecurityError, protection_reason, settings as ai_settings


TYPES = {
    'waf': 'waf', 'waf防护日志': 'waf', 'web应用防护': 'waf',
    'web应用防护日志': 'waf', 'web应用防火墙日志': 'waf',
    'ips': 'ips', 'ips防护日志': 'ips', '漏洞攻击防护': 'ips', '漏洞攻击防护日志': 'ips',
}
# Match field boundaries, not arbitrary occurrences of "ips"/"waf" inside a URL.
PAIR = re.compile(r'(?:^|[,，;；]\s*|(?<!\s)\s+)([\w\u4e00-\u9fff]+)\s*[:=：]\s*')
PRI = re.compile(r'^<(\d{1,3})>')
PAYLOAD_FIELDS = {'url', 'url_dir', 'referer', 'request', '请求', '请求内容', '报文', 'package',
                  'descript', '描述', '详细信息', 'user-agent', 'http_user_agent'}


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Ambiguous duplicate field')
        result[key] = value
    return result


def parse_message(raw):
    """Keep the original datagram and decode AF's Chinese key/value or JSON messages."""
    encoding = 'utf-8'
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError:
        encoding = 'gb18030'
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            encoding = 'utf-8-replacement'
            text = raw.decode('utf-8', errors='replace')
    message = text.strip('\ufeff\r\n\x00 ')
    pri = PRI.match(message)
    priority = int(pri[1]) if pri and int(pri[1]) <= 191 else None
    if pri:
        message = message[pri.end():]
    fields = {}
    # AF fwlog messages have a syslog header before their JSON / key-value payload.
    payload = message.split('fwlog:', 1)[-1].strip()
    structured = payload.startswith('{')
    trusted = {}
    if structured:
        try:
            value = json.loads(payload, object_pairs_hook=unique_fields)
            if isinstance(value, dict):
                fields = trusted = value
        except (ValueError, RecursionError):
            pass
    if not structured:
        matches = list(PAIR.finditer(payload))
        metadata = True
        for index, match in enumerate(matches):
            value = payload[match.end():matches[index + 1].start() if index + 1 < len(matches) else len(payload)]
            fields.setdefault(match[1], value.strip().strip('"'))
            if match[1].lower() in PAYLOAD_FIELDS:
                metadata = False
            if metadata:
                # Ambiguous metadata must never select a target for an automatic action.
                trusted[match[1]] = fields[match[1]] if match[1] not in trusted else None

    def get(*keys):
        for key in keys:
            value = fields.get(key)
            if value is not None and not isinstance(value, (dict, list, bool)):
                return str(value).strip().encode('utf-8', errors='replace').decode('utf-8')
        return ''

    log_type = get('日志类型', 'log_type', 'logType').lower()
    kind = TYPES.get(log_type, 'other' if log_type else 'unknown')
    occurred = get('时间', '日志时间', 'record_time', 'timestamp', 'time')
    if not occurred:
        stamp = re.match(r'(?:1 )?(\d{4}-\d\d-\d\d[T ][\d:.]+(?:Z|[+-]\d\d:\d\d)?)', message)
        if stamp:
            occurred = stamp[1]
        else:
            stamp = re.match(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)', message)
            occurred = stamp[1] if stamp else ''

    def address(*keys):
        value = get(*keys)
        try:
            ip = ipaddress.ip_address(value)
            return str(ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip)
        except ValueError:
            return ''

    src_keys = ('源IP', '源IP地址', '源地址', 'src_ip', 'srcIp')
    type_keys = ('日志类型', 'log_type', 'logType')
    trusted_types = {str(trusted[k]).strip().lower() for k in type_keys if k in trusted}
    trusted_sources = {str(trusted[k]).strip() for k in src_keys if k in trusted}
    block_ip = ''
    if (len(trusted_sources) == 1 and all(trusted[k] is not None for k in src_keys if k in trusted) and
            len(trusted_types) == 1 and TYPES.get(next(iter(trusted_types))) in ('waf', 'ips')):
        try:
            target = ipaddress.ip_address(next(iter(trusted_sources)))
            block_ip = str(target.ipv4_mapped if isinstance(target, ipaddress.IPv6Address) and target.ipv4_mapped else target)
        except ValueError:
            pass
    return {
        'text': text, 'encoding': encoding, 'kind': kind, 'occurred': occurred[:80],
        'src_ip': block_ip or address(*src_keys), 'block_ip': block_ip,
        'dst_ip': address('目的IP', '目的IP地址', '目的地址', 'dst_ip', 'dstIp'),
        'level': get('严重等级', '严重级别', 'severity', 'level')[:30],
        'action': get('动作', '系统动作', 'net_action', 'action')[:30],
        'title': get('漏洞名称', '攻击名称', '事件名称', 'hole_name', 'attack_name', '攻击类型', '类型', 'attack_type')[:500],
        'fields': fields, 'priority': priority,
    }


class SyslogService:
    def __init__(self, root, waf=None, af_sync=None):
        self.root = Path(root)
        self.waf, self.af_sync = waf, af_sync
        self.block_error = ''
        self.block_thread = None
        self.directory = self.root / 'runtime'
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / 'af-syslog.sqlite3'
        self.config_path = self.directory / 'syslog-settings.json'
        self.lifecycle = threading.RLock()
        self.metrics_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.drain_event = threading.Event()
        self.socket = None
        self.threads = []
        self.inbox = queue.Queue(maxsize=10000)
        self.error = ''
        self.rejected = self.dropped = 0
        self.config = self.load_settings()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS syslog_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, received REAL NOT NULL, peer TEXT NOT NULL,
                    raw BLOB NOT NULL, text TEXT NOT NULL, encoding TEXT NOT NULL, kind TEXT NOT NULL,
                    occurred TEXT NOT NULL, src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,
                    level TEXT NOT NULL, action TEXT NOT NULL, title TEXT NOT NULL, fields TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS syslog_kind ON syslog_events(kind,id);
                CREATE INDEX IF NOT EXISTS syslog_received ON syslog_events(received,id);
                CREATE INDEX IF NOT EXISTS syslog_source ON syslog_events(src_ip,id);
                CREATE INDEX IF NOT EXISTS syslog_destination ON syslog_events(dst_ip,id);
                CREATE TABLE IF NOT EXISTS syslog_counts (
                    kind TEXT PRIMARY KEY, n INTEGER NOT NULL, last_received REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS syslog_block_cursor (
                    id INTEGER PRIMARY KEY CHECK(id=1), last_id INTEGER NOT NULL);
                INSERT OR IGNORE INTO syslog_block_cursor VALUES(1,0);
                CREATE TABLE IF NOT EXISTS syslog_blocks (
                    ip TEXT PRIMARY KEY, event_id INTEGER NOT NULL, kind TEXT NOT NULL, title TEXT NOT NULL,
                    hits INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'pending', detail TEXT NOT NULL DEFAULT '',
                    attempts INTEGER NOT NULL DEFAULT 0, retry_at REAL NOT NULL DEFAULT 0, updated REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS syslog_block_pending ON syslog_blocks(state,retry_at);
            ''')

    def load_settings(self):
        host = urlsplit(af_settings(self.root)['url']).hostname or ''
        try:
            host = str(ipaddress.IPv4Address(host))
        except ValueError:
            host = ''
        config = {'enabled': False, 'bind': '0.0.0.0', 'port': 5514, 'sender': host, 'autoBlock': False}
        if self.config_path.exists():
            config.update(json.loads(self.config_path.read_text(encoding='utf-8')))
        return self.validate(config)

    @staticmethod
    def validate(body):
        if not isinstance(body, dict) or type(body.get('enabled')) is not bool:
            raise ValueError('接收开关必须是布尔值。')
        if type(body.get('port')) is not int or not 1 <= body['port'] <= 65535:
            raise ValueError('Syslog 端口应为 1–65535。')
        for key in ('bind', 'sender'):
            if key == 'sender' and not body.get(key) and not body['enabled']:
                continue
            try:
                if not isinstance(body[key], str):
                    raise ValueError()
                address = ipaddress.IPv4Address(body[key])
                if key == 'sender' and (address.is_unspecified or address.is_multicast):
                    raise ValueError()
            except (ValueError, KeyError, TypeError, ipaddress.AddressValueError):
                raise ValueError('监听地址和允许发送的 AF 地址应为有效 IPv4 地址。') from None
        if type(body.get('autoBlock', False)) is not bool:
            raise ValueError('自动拉黑开关必须是布尔值。')
        return {**{key: body[key] for key in ('enabled', 'bind', 'port', 'sender')},
                'autoBlock': body.get('autoBlock', False)}

    def save_settings(self, body):
        config = self.validate({**self.config, **body})
        with self.lifecycle:
            self.stop()
            temporary = self.config_path.with_suffix('.tmp')
            try:
                temporary.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding='utf-8')
                os.replace(temporary, self.config_path)
            except OSError:
                self.start()
                raise
            self.config = config
            self.start()
            return self.public()

    def start(self):
        with self.lifecycle:
            if self.socket or not self.config['enabled']:
                return
            self.error = ''
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Never share the port with another listener.
                if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                sock.bind((self.config['bind'], self.config['port']))
                sock.settimeout(.5)
            except OSError as exc:
                sock.close()
                self.error = f'无法监听 UDP {self.config["port"]}，请检查端口占用和监听地址（错误 {exc.errno}）。'
                return
            self.socket = sock
            self.stop_event.clear()
            self.drain_event.clear()
            self.threads = [threading.Thread(target=self.receive, args=(sock, self.config['sender']), daemon=True, name='syslog-udp'),
                            threading.Thread(target=self.write, daemon=True, name='syslog-storage')]
            for thread in self.threads:
                thread.start()
            if self.waf:
                self.block_thread = threading.Thread(target=self.run_blocker, daemon=True, name='syslog-block')
                self.block_thread.start()

    def stop(self):
        with self.lifecycle:
            self.stop_event.set()
            if self.socket:
                self.socket.close()
            if self.threads:
                self.threads[0].join()
                self.drain_event.set()
                self.threads[1].join()
            if self.block_thread:
                self.block_thread.join()
                self.block_thread = None
            self.threads = []
            self.socket = None

    def receive(self, sock, allowed):
        while not self.stop_event.is_set():
            try:
                raw, (peer, _) = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if not self.stop_event.is_set():
                    self.error = 'Syslog 接收中断，请重新启用接收。'
                break
            if peer != allowed:
                with self.metrics_lock:
                    self.rejected += 1
                continue
            try:
                self.inbox.put_nowait((time.time(), peer, raw))
            except queue.Full:
                with self.metrics_lock:
                    self.dropped += 1

    def write(self):
        try:
            db = sqlite3.connect(self.path, timeout=5)
        except sqlite3.Error:
            self.error = '无法打开 Syslog 数据库，请检查文件权限和磁盘空间。'
            self.stop_event.set()
            return
        try:
            db.execute('PRAGMA synchronous=FULL')
            while not self.drain_event.is_set() or not self.inbox.empty():
                try:
                    batch = [self.inbox.get(timeout=.2)]
                except queue.Empty:
                    continue
                # Batch disk commits under sustained traffic without delaying quiet sources.
                while len(batch) < 200:
                    try:
                        batch.append(self.inbox.get_nowait())
                    except queue.Empty:
                        break
                while True:
                    try:
                        with db:
                            for received, peer, raw in batch:
                                event = parse_message(raw)
                                db.execute('''INSERT INTO syslog_events
                                    (received,peer,raw,text,encoding,kind,occurred,src_ip,dst_ip,level,action,title,fields)
                                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                                    (received, peer, raw, *(event[k] for k in
                                     ('text', 'encoding', 'kind', 'occurred', 'src_ip', 'dst_ip', 'level', 'action', 'title')),
                                     json.dumps(event['fields'])))
                                db.execute('''INSERT INTO syslog_counts VALUES(?,1,?)
                                    ON CONFLICT(kind) DO UPDATE SET n=n+1,last_received=excluded.last_received''',
                                           (event['kind'], received))
                        self.error = ''
                        break
                    except (sqlite3.Error, ValueError):
                        self.error = 'Syslog 写入失败，请检查磁盘空间；正在重试，接收队列满后会丢弃新消息。'
                        if self.stop_event.wait(1):
                            with self.metrics_lock:
                                self.dropped += len(batch)
                            break
        finally:
            db.close()

    def reader(self):
        db = sqlite3.connect(self.path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def block_protection(self, ip):
        # This feature never inherits AI_ALLOW_PRIVATE_IPS: only public source addresses.
        address = ipaddress.ip_address(ip)
        if not address.is_global or address.is_multicast or address.is_reserved:
            return '内网或保留地址，AF 日志自动拉黑始终排除'
        config = ai_settings(self.root)
        panel = urlsplit(self.waf.client.config['url']).hostname
        reason = protection_reason(ip, {**config, 'allowPrivate': False}, panel)
        if reason:
            return reason
        if ip in (self.config['sender'], urlsplit(af_settings(self.root)['url']).hostname):
            return 'AF 设备地址受保护'
        previous = self.waf.store.block(ip)
        if previous and previous['state'] == 'unblocked':
            return '已手动解封并保护，停止再次自动拉黑'
        return ''

    def blocking_allowed(self, ip):
        return (not self.stop_event.is_set() and self.config['enabled'] and self.config['autoBlock']
                and ai_settings(self.root).get('analysisMode') != 'local'
                and not self.block_protection(ip))

    def block_once(self):
        if not self.waf or self.stop_event.is_set() or not self.config['enabled'] or not self.config['autoBlock'] or \
                ai_settings(self.root).get('analysisMode') == 'local':
            return
        # Queue and checkpoint commit together. A restart never loses pending actions.
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            with db:
                after = db.execute('SELECT last_id FROM syslog_block_cursor WHERE id=1').fetchone()[0]
                events = db.execute('SELECT id,peer,raw FROM syslog_events WHERE id>? ORDER BY id LIMIT 500',
                                    (after,)).fetchall()
                for row in events:
                    if row['peer'] != self.config['sender']:
                        continue
                    event = parse_message(row['raw'])
                    ip = event['block_ip']
                    if event['kind'] not in ('waf', 'ips') or not ip:
                        continue
                    db.execute('''INSERT INTO syslog_blocks(ip,event_id,kind,title,hits,updated) VALUES(?,?,?,?,1,?)
                        ON CONFLICT(ip) DO UPDATE SET event_id=excluded.event_id,kind=excluded.kind,title=excluded.title,
                        hits=hits+1,updated=excluded.updated,
                        state=CASE WHEN state='failed' THEN state ELSE 'pending' END''',
                               (ip, row['id'], event['kind'], event['title'], time.time()))
                if events:
                    db.execute('UPDATE syslog_block_cursor SET last_id=? WHERE id=1', (events[-1]['id'],))
            pending = [dict(row) for row in db.execute('''SELECT b.* FROM syslog_blocks b
                JOIN syslog_events e ON e.id=b.event_id
                WHERE b.state IN ('pending','failed') AND b.retry_at<=? AND e.peer=?
                ORDER BY b.updated LIMIT 50''', (time.time(), self.config['sender']))]
        changed = False
        try:
            for row in pending:
                if self.stop_event.is_set() or not self.config['enabled'] or not self.config['autoBlock']:
                    break
                ip, retry_at, attempts = row['ip'], 0, row['attempts']
                try:
                    reason = self.block_protection(ip)
                    previous = self.waf.store.block(ip)
                    if reason:
                        state, detail = 'protected', reason
                    elif previous and previous['state'] in ('listed', 'existing', 'inactive'):
                        state, detail = previous['state'], '已记录在 WAF 全局黑名单，重复命中未重复创建'
                    else:
                        label = 'Web 应用防护' if row['kind'] == 'waf' else '漏洞攻击防护'
                        state, detail = self.waf.add(ip, f'AF {label}：{row["title"]}'[:200],
                                                   allowed=lambda: self.blocking_allowed(ip), origin='AFSyslog')
                        changed = True
                except Exception as exc:
                    attempts += 1
                    detail = str(exc) if isinstance(exc, SecurityError) or type(exc).__name__ == 'PanelError' else '写入黑名单失败，稍后自动重试'
                    state = 'protected' if getattr(exc, 'status', None) == 409 else 'failed'
                    retry_at = time.time() + min(3600, 30 * 2 ** min(attempts, 7))
                    if self.stop_event.is_set() or not self.config['enabled'] or not self.config['autoBlock']:
                        state, retry_at = 'pending', 0
                with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
                    db.execute('''UPDATE syslog_blocks SET state=?,detail=?,attempts=?,retry_at=?,updated=? WHERE ip=?''',
                               (state, detail[:300], attempts, retry_at, time.time(), ip))
        finally:
            if changed and self.af_sync:
                self.af_sync.request_sync()

    def run_blocker(self):
        while not self.stop_event.is_set():
            try:
                self.block_once()
                self.block_error = ''
            except Exception:
                self.block_error = 'AF 日志自动拉黑处理失败，保留队列并稍后重试。'
            self.stop_event.wait(2)

    def public(self):
        db = self.reader()
        try:
            rows = db.execute('SELECT * FROM syslog_counts').fetchall()
            blocks = dict(db.execute('SELECT state,COUNT(*) FROM syslog_blocks GROUP BY state').fetchall())
        finally:
            db.close()
        address = self.config['bind']
        if address == '0.0.0.0' and self.config['sender']:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    probe.connect((self.config['sender'], self.config['port']))
                    address = probe.getsockname()[0]
            except OSError:
                address = ''
        with self.metrics_lock:
            counters = {'rejected': self.rejected, 'dropped': self.dropped}
        listening = bool(self.socket and self.threads and all(t.is_alive() for t in self.threads))
        fault = self.error or ('Syslog 接收线程已停止，请重新启用接收。' if self.socket and not listening else '')
        return {'settings': dict(self.config), 'listening': listening,
                'address': address, 'error': fault, 'queueDepth': self.inbox.qsize(), **counters,
                'counts': {r['kind']: r['n'] for r in rows}, 'total': sum(r['n'] for r in rows),
                'blocking': {'available': self.waf is not None, 'counts': blocks, 'error': self.block_error,
                             'afSyncEnabled': af_settings(self.root)['enabled']},
                'lastReceived': max((r['last_received'] for r in rows), default=None)}

    def feed(self, body):
        kind = body.get('kind', 'security')
        page, through = body.get('page', 1), body.get('through')
        if kind not in ('security', 'waf', 'ips', 'other', 'unknown', 'all'):
            raise ValueError('日志类型不正确。')
        if type(page) is not int or not 1 <= page <= 1000000:
            raise ValueError('页码不正确。')
        if through is not None and (type(through) is not int or not 0 <= through <= 2**63 - 1):
            raise ValueError('日志快照编号不正确。')
        clauses, args = ['id<=?'], []
        if kind == 'security':
            clauses.append("kind IN ('waf','ips')")
        elif kind != 'all':
            clauses.append('kind=?'); args.append(kind)
        for key in ('src_ip', 'dst_ip'):
            if body.get(key):
                try:
                    value = str(ipaddress.ip_address(body[key]))
                except ValueError:
                    raise ValueError('请输入有效的源 / 目的 IP。') from None
                clauses.append(f'{key}=?'); args.append(value)
        bounds = {}
        for key, operator in (('start', '>='), ('end', '<=')):
            if body.get(key):
                try:
                    stamp = datetime.strptime(body[key], '%Y-%m-%dT%H:%M').timestamp()
                except (ValueError, TypeError):
                    raise ValueError('时间格式不正确。') from None
                bounds[key] = stamp
                clauses.append(f'received{operator}?'); args.append(stamp + (59.999 if key == 'end' else 0))
        if bounds.get('start', 0) > bounds.get('end', float('inf')):
            raise ValueError('开始时间不能晚于结束时间。')
        query = body.get('query', '')
        if not isinstance(query, str) or len(query) > 200:
            raise ValueError('搜索关键词最长 200 字符。')
        if query:
            clauses.append("text LIKE ? ESCAPE '\\'")
            args.append('%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
        db = self.reader()
        try:
            # Bound expensive raw searches as the local archive grows.
            deadline = time.monotonic() + 5
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
            db.execute('BEGIN')
            if through is None:
                through = db.execute('SELECT COALESCE(MAX(id),0) FROM syslog_events').fetchone()[0]
            where, params = ' AND '.join(clauses), [through, *args]
            total = db.execute(f'SELECT COUNT(*) FROM syslog_events WHERE {where}', params).fetchone()[0]
            pages = max(1, (total + 49) // 50)
            page = min(page, pages)
            rows = db.execute(f'''SELECT id,received,peer,kind,occurred,src_ip,dst_ip,level,action,title
                FROM syslog_events WHERE {where} ORDER BY id DESC LIMIT 50 OFFSET ?''',
                              (*params, (page - 1) * 50)).fetchall()
            items = [dict(r) for r in rows]
            ips = list({r['src_ip'] for r in items if r['kind'] in ('waf', 'ips') and r['src_ip']})
            blocks = {r['ip']: dict(r) for r in db.execute(
                'SELECT ip,state,detail FROM syslog_blocks WHERE ip IN (%s)' % ','.join('?' for _ in ips), ips)} if ips else {}
            for item in items:
                item['blocking'] = blocks.get(item['src_ip']) if item['kind'] in ('waf', 'ips') else None
            return {'events': items, 'page': page, 'pages': pages, 'total': total, 'through': through}
        except sqlite3.OperationalError:
            raise ValueError('日志查询未完成，请缩小时间范围后重试。') from None
        finally:
            db.close()

    def detail(self, event_id):
        if type(event_id) is not int or not 1 <= event_id <= 2**63 - 1:
            raise ValueError('日志编号不正确。')
        db = self.reader()
        try:
            row = db.execute('SELECT * FROM syslog_events WHERE id=?', (event_id,)).fetchone()
            if row is None:
                raise ValueError('日志不存在。')
            event = dict(row)
            event.pop('raw')  # Bytes are retained in SQLite; display the decoded original text.
            event['fields'] = json.loads(event['fields'])
            return event
        finally:
            db.close()
