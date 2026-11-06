"""Authenticated agent ingestion and local, searchable server log history."""
import hashlib
from datetime import datetime
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import math
from pathlib import Path
import re
import secrets
import socket
import threading
import time
from urllib.parse import urlsplit, parse_qs
import uuid
import zipfile


ROOT = Path(__file__).resolve().parent
MAX_BODY = 1024 * 1024
KINDS = ('access.log', 'error.log', 'custom.log')


def ai_state(kind, raw):
    """Daily-cleaned rows the agent marked as ordinary traffic are archived without AI."""
    if kind != 'access.log':
        return 'ignored'
    if raw.startswith('{') and '"clean_date"' in raw:
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and data.get('clean_ai') is False:
                return 'filtered'
        except ValueError:
            pass
    return 'pending'


def platform_url(value):
    if not isinstance(value, str) or any(c.isspace() for c in value):
        raise ValueError('请填写服务器能访问的代理接收地址。')
    parsed = urlsplit(value)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment or len(value) > 500):
        raise ValueError('平台地址应为 HTTP / HTTPS 地址，不包含账号、查询参数或密钥。')
    return value.rstrip('/')


class Hub:
    def __init__(self, store, blacklist=None, clean_rules=None):
        self.store = store
        self.blacklist = blacklist
        self.clean_rules = clean_rules
        self.receiver = None
        self.advertised_url = ''
        self.receiver_error = ''
        store.ensure_agent_schema()

    def register(self, body):
        name = body.get('name', '')
        if not isinstance(name, str):
            raise ValueError('服务器名称不正确。')
        name = name.strip()
        if not 1 <= len(name) <= 100:
            raise ValueError('请填写服务器名称（1–100 个字符）。')
        url = platform_url(body.get('platformUrl') or self.advertised_url)
        sources = body.get('sources')
        if not isinstance(sources, list) or not 1 <= len(sources) <= 20:
            raise ValueError('至少填写一条日志路径。')
        clean_sources = []
        for source in sources:
            if not isinstance(source, dict):
                raise ValueError('日志路径配置不正确。')
            path, kind, mode = source.get('path', ''), source.get('kind'), source.get('mode', 'tail')
            if not isinstance(path, str):
                raise ValueError('日志路径应为文本。')
            path = path.strip()
            if not path or len(path) > 1000 or any(c in path for c in '\r\n\x00') or kind not in KINDS:
                raise ValueError('日志路径或类型不正确。')
            if mode not in ('tail', 'daily'):
                raise ValueError('采集方式不正确。')
            clean = {'path': path, 'kind': kind, 'encoding': 'utf-8'}
            if mode == 'daily':
                days = source.get('daysAgo', 1)
                if kind != 'access.log' or '{date}' not in path or any(c in path for c in '*?['):
                    raise ValueError('按日期采集仅用于访问日志，路径需包含 {date}，例如 D:/nginx/logs/access_{date}.log，且不能使用 *。')
                if type(days) is not int or not 1 <= days <= 30:
                    raise ValueError('日期偏移应为 1–30 天。')
                clean.update(mode='daily', daysAgo=days, dateFormat='%Y-%m-%d', runAfter='00:30', neighbors=1)
            clean_sources.append(clean)
        initial = body.get('initialLines', 200)
        if type(initial) is not int or initial not in (0, 200, 500):
            raise ValueError('首次读取行数应为 0、200 或 500。')
        agent_id, token = str(uuid.uuid4()), secrets.token_urlsafe(32)
        with self.store.lock, self.store.db:
            self.store.db.execute('INSERT INTO agents(id,name,token_hash,created) VALUES(?,?,?,?)',
                                  (agent_id, name, hashlib.sha256(token.encode()).hexdigest(), time.time()))
        return {'agentId': agent_id, 'name': name, 'token': token, 'platformUrl': url,
                'interval': 3, 'initialLines': initial, 'maxQueueMB': 256, 'sources': clean_sources}

    def authenticate(self, agent_id, authorization):
        if (not isinstance(agent_id, str) or len(agent_id) != 36 or
                not isinstance(authorization, str) or not authorization.startswith('Bearer ')):
            return False
        token = authorization[7:]
        if not 20 <= len(token) <= 200:
            return False
        with self.store.lock:
            row = self.store.db.execute('SELECT token_hash,enabled FROM agents WHERE id=?', (agent_id,)).fetchone()
            return bool(row and row['enabled'] and hmac.compare_digest(row['token_hash'], hashlib.sha256(token.encode()).hexdigest()))

    def ingest(self, agent_id, body):
        events, metadata = body.get('events'), body.get('metadata', {})
        if not isinstance(events, list) or len(events) > 500 or not isinstance(metadata, dict):
            raise ValueError('Invalid batch')
        rows, now, reports, new_reports = [], time.time(), {}, []
        for event in events:
            if not isinstance(event, dict):
                raise ValueError('Invalid event')
            event_id = event.get('eventId')
            raw, source, kind, collected = event.get('raw'), event.get('source'), event.get('kind'), event.get('collectedAt')
            if (not isinstance(event_id, str) or not re.fullmatch(r'[a-f0-9]{32}', event_id) or
                    not isinstance(raw, str) or len(raw) > 16384 or '\x00' in raw or
                    not isinstance(source, str) or not 1 <= len(source) <= 1000 or kind not in KINDS or
                    type(collected) not in (int, float) or not math.isfinite(collected) or collected < 0):
                raise ValueError('Invalid event fields')
            rows.append((agent_id, event_id, kind, source, raw, collected, now))
            if kind == 'custom.log' and self.clean_rules and raw.startswith('{"type":"daily_clean_report"'):
                try:
                    reports[event_id] = json.loads(raw).get('ruleHits')
                except ValueError:
                    pass
        # Agent metadata is displayed as text, never executed or used for paths.
        clean = {'hostname': str(metadata.get('hostname', ''))[:100],
                 'version': str(metadata.get('version', ''))[:100],
                 'queueDepth': max(0, min(int(metadata.get('queueDepth', 0)), 100000000)),
                 'lastError': str(metadata.get('lastError', ''))[:500],
                 'sources': metadata.get('sources', [])}
        if not isinstance(clean['sources'], list) or len(clean['sources']) > 100 or len(json.dumps(clean)) > 20000:
            raise ValueError('Invalid source status')
        with self.store.lock, self.store.db:
            row = self.store.db.execute('SELECT enabled FROM agents WHERE id=?', (agent_id,)).fetchone()
            if not row or not row['enabled']:
                raise PermissionError('Agent is disabled')
            inserted = 0
            for row in rows:
                previous = self.store.db.execute('SELECT raw FROM agent_events WHERE agent_id=? AND event_id=?', (row[0], row[1])).fetchone()
                if previous and previous['raw'] != row[4]:
                    raise ValueError('Event ID content mismatch')
                priority = None
                if row[2] == 'access.log' and row[4].startswith('{') and '"decoded_body"' in row[4]:
                    try:
                        decoded = json.loads(row[4])
                        timestamp = datetime.fromisoformat(str(decoded.get('time', '')).replace('Z', '+00:00'))
                        if timestamp.tzinfo is not None and math.isfinite(timestamp.timestamp()):
                            priority = min(now, max(0, timestamp.timestamp()))
                    except (ValueError, TypeError, AttributeError, OverflowError, OSError):
                        pass
                added = self.store.db.execute('''INSERT OR IGNORE INTO agent_events
                    (agent_id,event_id,kind,source,raw,collected,received,ai_state,priority_time) VALUES(?,?,?,?,?,?,?,?,?)''', (*row, ai_state(row[2], row[4]),priority)).rowcount
                inserted += added
                if added and row[1] in reports:
                    new_reports.append(reports[row[1]])
            self.store.db.execute('UPDATE agents SET last_seen=?,metadata=? WHERE id=?',
                                  (now, json.dumps(clean, ensure_ascii=False), agent_id))
            # Every uploaded line is kept; nothing is pruned.
        # Count rule hits only for reports stored now, so a retried batch is not counted twice.
        for hits in new_reports:
            if isinstance(hits, dict):
                self.clean_rules.add_hits(hits)
        return {'accepted': len(events), 'inserted': inserted}

    def overview(self):
        with self.store.lock:
            counts = dict(self.store.db.execute(
                "SELECT source,SUM(n) FROM log_counts WHERE tbl='agent_events' GROUP BY source").fetchall())
            agents = []
            for row in self.store.db.execute('SELECT id,name,enabled,created,last_seen,metadata FROM agents ORDER BY created DESC'):
                item = dict(row)
                item['metadata'] = json.loads(item['metadata'])
                item['count'] = counts.get(item['id'], 0)
                item['ai'] = self.store.ai_summary('agent',item['id'])
                item['status'] = ('disabled' if not item['enabled'] else 'waiting' if item['last_seen'] is None
                                  else 'online' if time.time() - item['last_seen'] <= 90 else 'offline')
                agents.append(item)
            return {'agents': agents, 'total': sum(counts.values()),
                    'ai': self.store.ai_summary('agent'),
                    'online': sum(a['status'] == 'online' for a in agents),
                    'receiver': {'ready': self.receiver is not None, 'url': self.advertised_url,
                                 'error': self.receiver_error, 'packageReady': (ROOT / 'agent' / 'dist' / 'LogAgent.exe').is_file()}}

    def verdicts(self, agent_id, body):
        ids = body.get('eventIds')
        if not isinstance(ids, list) or len(ids) > 100 or any(not isinstance(i, str) or not re.fullmatch(r'[a-f0-9]{32}', i) for i in ids):
            raise ValueError('Invalid event IDs')
        results = []
        with self.store.lock:
            for event_id in dict.fromkeys(ids):
                event = self.store.db.execute('SELECT id,ai_state FROM agent_events WHERE agent_id=? AND event_id=?', (agent_id, event_id)).fetchone()
                item = {'event_id': event_id, 'ai_state': event['ai_state'] if event else 'unknown'}
                if event:
                    decision = self.store.db.execute('''SELECT d.id,d.ip,d.attack,d.confidence,d.category,d.reason,d.state,d.detail,d.provider,d.model,d.created,d.historical,d.evidence
                        FROM analysis_event_decisions m JOIN decisions d ON d.id=m.decision_id
                        WHERE m.event_id=? AND d.agent_id=? AND d.source_type='agent' ''', (-event['id'], agent_id)).fetchone()
                    if decision:
                        item['decision'] = dict(decision)
                        item['decision']['cited'] = -event['id'] in json.loads(item['decision'].pop('evidence'))
                        block = self.store.block(decision['ip'])
                        if block:
                            item['block'] = {'state': block['state'], 'updated': block['updated']}
                results.append(item)
        return {'events': results}

    def feed(self, agent_id='', kind='all', query='', page=1, through=None):
        if (kind not in ('all', *KINDS) or not isinstance(query, str) or len(query) > 200 or
                type(page) is not int or not 1 <= page <= 1000000 or
                not isinstance(agent_id, str) or len(agent_id) > 36 or
                (through is not None and (type(through) is not int or not 0 <= through <= 2**63 - 1))):
            raise ValueError('服务器日志筛选参数不正确。')
        # The archive keeps every line, so reads use their own connection and one snapshot,
        # never the shared lock that log ingestion waits on.
        db = self.store.reader()
        try:
            db.execute('BEGIN')
            if through is None:
                through = db.execute('SELECT COALESCE(MAX(id),0) FROM agent_events').fetchone()[0]
            filters, params = '', []
            if agent_id:
                filters += ' AND e.agent_id=?'; params.append(agent_id)
            if kind != 'all':
                filters += ' AND e.kind=?'; params.append(kind)
            if query:
                filters += " AND e.raw LIKE ? ESCAPE '\\'"
                params.append('%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
                total = db.execute(f'SELECT COUNT(*) FROM agent_events e WHERE e.id<=?{filters}', (through, *params)).fetchone()[0]
            else:
                # Counter total minus the few rows that arrived after this page's snapshot.
                counted = sum(n for (k, _), n in self.store.counts('agent_events', agent_id or None, db).items()
                              if kind == 'all' or k == kind)
                newer = db.execute(f'SELECT COUNT(*) FROM agent_events e WHERE e.id>?{filters}', (through, *params)).fetchone()[0]
                total = max(0, counted - newer)
            pages = max(1, (total + 99) // 100); page = min(page, pages)
            rows = db.execute(f'''SELECT e.*,a.name AS server_name FROM agent_events e
                JOIN agents a ON a.id=e.agent_id WHERE e.id<=?{filters} ORDER BY e.id DESC LIMIT 100 OFFSET ?''',
                              (through, *params, (page - 1) * 100)).fetchall()
            return {'events': [dict(r) for r in rows], 'page': page, 'pages': pages, 'total': total, 'through': through}
        finally:
            db.close()

    def set_enabled(self, agent_id, enabled):
        if type(enabled) is not bool:
            raise ValueError('服务器状态参数不正确。')
        with self.store.lock, self.store.db:
            result = self.store.db.execute('UPDATE agents SET enabled=? WHERE id=?', (int(enabled), agent_id))
            if not result.rowcount:
                raise ValueError('服务器不存在。')

    def package(self, config):
        exe = ROOT / 'agent' / 'dist' / 'LogAgent.exe'
        if not exe.is_file():
            raise ValueError('Windows 代理还未打包完成。')
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.write(exe, 'LogAgent.exe')
            for name in ('run.cmd', 'install.cmd', 'uninstall.cmd', 'README.txt'):
                archive.write(ROOT / 'agent' / name, name)
            archive.writestr('config.json', json.dumps(config, ensure_ascii=False, indent=2))
        return stream.getvalue()

    def enroll(self, body):
        if not (ROOT / 'agent' / 'dist' / 'LogAgent.exe').is_file():
            raise ValueError('Windows 代理还未打包完成，请稍后重试。')
        config = self.register(body)
        try:
            return config['agentId'], self.package(config)
        except Exception:
            with self.store.lock, self.store.db:
                self.store.db.execute('DELETE FROM agents WHERE id=? AND last_seen IS NULL', (config['agentId'],))
            raise

    def start_receiver(self, host, port, panel_url, public_url=''):
        self.receiver_error = ''
        try:
            self.receiver = IngestServer((host, port), self)
            if public_url:
                self.advertised_url = platform_url(public_url)
            else:
                address = host
                if address == '0.0.0.0':
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                        probe.connect((urlsplit(panel_url).hostname, 80))
                        address = probe.getsockname()[0]
                self.advertised_url = f'http://{address}:{self.receiver.server_port}'
            threading.Thread(target=self.receiver.serve_forever, daemon=True, name='agent-ingest').start()
        except Exception:
            if self.receiver:
                self.receiver.server_close(); self.receiver = None
            self.receiver_error = '代理接收端未启动，请检查 AGENT_BIND / AGENT_PORT / AGENT_PUBLIC_URL 和端口占用。'

    def stop_receiver(self):
        if self.receiver:
            self.receiver.shutdown(); self.receiver.server_close()
            self.receiver = None


class IngestServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, hub):
        self.hub = hub
        super().__init__(address, IngestHandler)


class IngestHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *args):
        pass

    def reply(self, code, body, content_type='application/json; charset=utf-8'):
        raw = body.encode('utf-8') if isinstance(body,str) else json.dumps(body).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        try:
            self.wfile.write(raw)
        except ConnectionError:
            pass

    def do_GET(self):
        parsed=urlsplit(self.path)
        if parsed.path=='/health': return self.reply(200,{'appId':'1panel-agent-receiver'})
        if parsed.path=='/v1/clean-rules' and self.server.hub.clean_rules:
            # Daily agents download the cleaning rules with their own upload token.
            if self.headers.get('Origin') or not self.server.hub.authenticate(self.headers.get('X-Agent-ID',''),self.headers.get('Authorization','')):
                return self.reply(401,{'error':'Invalid or disabled agent credentials'})
            return self.reply(200,self.server.hub.clean_rules.export())
        if parsed.path!='/v1/blacklist' or not self.server.hub.blacklist:
            return self.reply(404,{'error':'Not found'})
        service=self.server.hub.blacklist
        if self.headers.get('Origin'): return self.reply(403,{'error':'Device requests only','complete':False})
        if not service.authorize(self.headers.get('Authorization','')):
            return self.reply(401,{'error':'Invalid blacklist API key','complete':False})
        try:
            format=parse_qs(parsed.query).get('format',['json'])[0]
            if format not in ('json','text'): return self.reply(400,{'error':'Use format=json or text','complete':False})
            snapshot=service.snapshot()
            self.reply(200,service.text(snapshot),'text/plain; charset=utf-8') if format=='text' else self.reply(200,snapshot)
        except Exception:
            self.reply(503,{'error':'Cannot retrieve a complete blacklist; keep the previous device rules and retry.','complete':False})

    def do_POST(self):
        if self.path not in ('/v1/ingest', '/v1/verdicts'):
            return self.reply(404, {'error': 'Not found'})
        if self.headers.get('Origin') or self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            return self.reply(403, {'error': 'Agent JSON requests only'})
        agent_id = self.headers.get('X-Agent-ID', '')
        if not self.server.hub.authenticate(agent_id, self.headers.get('Authorization', '')):
            return self.reply(401, {'error': 'Invalid or disabled agent credentials'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_BODY:
                return self.reply(413, {'error': 'Batch too large'})
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError()
            self.reply(200, self.server.hub.verdicts(agent_id, body) if self.path == '/v1/verdicts' else self.server.hub.ingest(agent_id, body))
        except PermissionError:
            self.reply(401, {'error': 'Agent disabled'})
        except (ValueError, TypeError, OverflowError):
            self.reply(400, {'error': 'Invalid log batch'})
        except Exception:
            self.reply(503, {'error': 'Storage unavailable; retry this batch'})
