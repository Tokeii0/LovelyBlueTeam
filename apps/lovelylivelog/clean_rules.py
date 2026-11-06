"""User-defined log cleaning rules, shared with daily agents and applied before AI."""
import hashlib
import json
import threading
import time
from urllib.parse import urlsplit

from agent.log_cleaner import RULE_ACTIONS, Rule, clean_options, compile_rules, explain, first_rule, is_suspicious

FIELDS = ('name', 'action', 'ip', 'method', 'status', 'path', 'ua', 'includeSuspicious', 'enabled')
COLUMNS = {'includeSuspicious': 'include_suspicious'}
MAX_RULES = 200


class CleanRules:
    def __init__(self, store):
        self.store = store
        self.cache = None
        self.blocker = None  # RuleBlocker, attached by the server
        with store.lock, store.db:
            store.db.executescript('''
                CREATE TABLE IF NOT EXISTS clean_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, position INTEGER NOT NULL,
                    name TEXT NOT NULL, action TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '',
                    method TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '',
                    ua TEXT NOT NULL DEFAULT '', include_suspicious INTEGER NOT NULL DEFAULT 0,
                    enabled INTEGER NOT NULL DEFAULT 1, hits INTEGER NOT NULL DEFAULT 0, last_hit REAL,
                    created REAL NOT NULL, updated REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS clean_options (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                INSERT OR IGNORE INTO clean_options VALUES(1, '{}');
            ''')

    @staticmethod
    def public(row):
        item = dict(row)
        item['includeSuspicious'] = bool(item.pop('include_suspicious'))
        item['enabled'] = bool(item['enabled'])
        return item

    def rules(self):
        with self.store.lock:
            return [self.public(r) for r in self.store.db.execute('SELECT * FROM clean_rules ORDER BY position,id')]

    def options(self):
        with self.store.lock:
            return clean_options(json.loads(self.store.db.execute('SELECT value FROM clean_options WHERE id=1').fetchone()[0]))

    def export(self):
        """What daily agents download: enabled rules in order plus the built-in switches.

        必封 rules go first and travel as 'ai': agents (also v1.1.1) only keep and upload
        those lines; the platform does the blocking, so no other rule may drop them."""
        enabled = [{k: r[k] for k in ('id', *FIELDS)} for r in self.rules() if r['enabled']]
        rules = ([{**r, 'action': 'ai'} for r in enabled if r['action'] == 'block'] +
                 [r for r in enabled if r['action'] != 'block'])
        options = self.options()
        version = hashlib.sha256(json.dumps([rules, options], sort_keys=True).encode()).hexdigest()[:16]
        return {'version': version, 'rules': rules, 'options': options}

    def overview(self):
        data = {'rules': self.rules(), 'options': self.options(), 'version': self.export()['version']}
        if self.blocker:
            data['blocks'] = self.blocker.public()
        return data

    def block_rules(self):
        return [Rule(r) for r in self.rules() if r['enabled'] and r['action'] == 'block']

    @staticmethod
    def validate(body):
        if not isinstance(body, dict):
            raise ValueError('规则格式不正确。')
        data = {}
        for key in FIELDS:
            value = body.get(key, True if key == 'enabled' else False if key == 'includeSuspicious' else '')
            if key in ('includeSuspicious', 'enabled'):
                if type(value) is not bool:
                    raise ValueError('规则开关必须是布尔值。')
            elif not isinstance(value, str) or len(value) > 1000 or any(c in value for c in '\r\n\x00'):
                raise ValueError('规则内容格式不正确。')
            data[key] = value.strip() if isinstance(value, str) and key != 'path' else value
        if not 1 <= len(data['name']) <= 60:
            raise ValueError('请填写规则名称（1–60 个字符）。')
        if data['action'] not in RULE_ACTIONS:
            raise ValueError('规则动作应为 丢弃、仅存档、强制送 AI 或 必封。')
        Rule(data)  # Raises a readable error for bad IP / status / regex conditions.
        return data

    def save(self, body):
        data = self.validate(body)
        rule_id, now = body.get('id'), time.time()
        values = [data[k] if k not in ('includeSuspicious', 'enabled') else int(data[k]) for k in FIELDS]
        columns = [COLUMNS.get(k, k) for k in FIELDS]
        with self.store.lock, self.store.db:
            if rule_id is None:
                count, last = self.store.db.execute('SELECT COUNT(*),COALESCE(MAX(position),0) FROM clean_rules').fetchone()
                if count >= MAX_RULES:
                    raise ValueError(f'最多保存 {MAX_RULES} 条清洗规则。')
                rule_id = self.store.db.execute(
                    f'INSERT INTO clean_rules(position,{",".join(columns)},created,updated) VALUES(?,{",".join("?" * len(columns))},?,?)',
                    (last + 1, *values, now, now)).lastrowid
            else:
                if type(rule_id) is not int:
                    raise ValueError('规则编号不正确。')
                changed = self.store.db.execute(
                    f'UPDATE clean_rules SET {",".join(c + "=?" for c in columns)},updated=? WHERE id=?',
                    (*values, now, rule_id)).rowcount
                if not changed:
                    raise ValueError('规则不存在，请刷新页面。')
        self.cache = None
        return self.overview()

    def delete(self, rule_id):
        with self.store.lock, self.store.db:
            if not self.store.db.execute('DELETE FROM clean_rules WHERE id=?', (rule_id,)).rowcount:
                raise ValueError('规则不存在，请刷新页面。')
        self.cache = None
        return self.overview()

    def move(self, rule_id, direction):
        if direction not in (-1, 1):
            raise ValueError('移动方向不正确。')
        with self.store.lock, self.store.db:
            ids = [r[0] for r in self.store.db.execute('SELECT id FROM clean_rules ORDER BY position,id')]
            if rule_id not in ids:
                raise ValueError('规则不存在，请刷新页面。')
            index = ids.index(rule_id)
            other = index + direction
            if 0 <= other < len(ids):
                ids[index], ids[other] = ids[other], ids[index]
            self.store.db.executemany('UPDATE clean_rules SET position=? WHERE id=?', [(n, i) for n, i in enumerate(ids, 1)])
        self.cache = None
        return self.overview()

    def set_options(self, body):
        options = clean_options(body)
        with self.store.lock, self.store.db:
            self.store.db.execute('UPDATE clean_options SET value=? WHERE id=1', (json.dumps(options),))
        self.cache = None
        return self.overview()

    def add_hits(self, hits):
        """Rule hit counts reported by daily agents or counted before AI."""
        rows = [(count, time.time(), int(rule_id)) for rule_id, count in (hits or {}).items()
                if str(rule_id).isdigit() and type(count) is int and 0 < count < 10**9]
        if rows:
            with self.store.lock, self.store.db:
                self.store.db.executemany('UPDATE clean_rules SET hits=hits+?,last_hit=? WHERE id=?', rows)

    def compiled(self):
        if self.cache is None:
            self.cache = compile_rules(self.export()['rules'])
        return self.cache

    def ai_action(self, event):
        """Rule applied to an already-stored row before AI: archived rows skip the model."""
        target = event.get('target', '')
        rule = first_rule(self.compiled(), event['ip'], event.get('method', ''), target, event.get('status', 0),
                          event.get('userAgent', ''), is_suspicious(event.get('method', ''), target))
        return rule

    def test(self, body):
        lines = body.get('lines')
        if not isinstance(lines, str) or len(lines) > 12000:
            raise ValueError('请粘贴 1–50 行日志。')
        items = [line for line in lines.splitlines() if line.strip()][:50]
        if not items:
            raise ValueError('请粘贴 1–50 行日志。')
        # Test with the original actions so 必封 shows as such.
        block = [r for r in self.rules() if r['enabled'] and r['action'] == 'block']
        rules = compile_rules(block + [r for r in self.rules() if r['enabled'] and r['action'] != 'block'])
        return {'results': [explain(line, rules, self.options()) for line in items]}


class RuleBlocker:
    """必封: a stored access line matching a block rule puts its IP on the WAF global blacklist, without AI."""
    BATCH = 5000
    WRITES_PER_ROUND = 50

    def __init__(self, root, client, store, waf, rules):
        from security import normalized_event, protection_reason, settings
        self.normalized, self.protection, self.settings = normalized_event, protection_reason, settings
        self.root, self.client, self.store, self.waf, self.rules = root, client, store, waf, rules
        self.stop_event, self.wake_event = threading.Event(), threading.Event()
        self.thread, self.rescanning, self.last_error = None, False, ''
        with store.lock, store.db:
            store.db.executescript('''
                CREATE TABLE IF NOT EXISTS rule_block_cursor (source TEXT PRIMARY KEY, last_id INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS rule_block_ips (
                    ip TEXT PRIMARY KEY, rule_id INTEGER NOT NULL, rule_name TEXT NOT NULL, hits INTEGER NOT NULL,
                    first_seen REAL NOT NULL, last_seen REAL NOT NULL, sample TEXT NOT NULL, origin TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending', detail TEXT NOT NULL DEFAULT '',
                    attempts INTEGER NOT NULL DEFAULT 0, retry_at REAL NOT NULL DEFAULT 0, updated REAL NOT NULL);
            ''')
            # Start from the rows stored now; older rows are covered by an explicit rescan.
            for table in ('events', 'agent_events'):
                store.db.execute('INSERT OR IGNORE INTO rule_block_cursor VALUES(?,(SELECT COALESCE(MAX(id),0) FROM %s))' % table,
                                 (table,))

    def rows(self, table, after, limit):
        if table == 'events':
            sql = '''SELECT id,website,kind,raw,received AS collected,'panel' AS source_type,'' AS agent_id,
                     '' AS server_name,'' AS source_file FROM events WHERE id>? AND kind='access.log' ORDER BY id LIMIT ?'''
        else:
            sql = '''SELECT -e.id AS id,0 AS website,e.kind,e.raw,e.collected,'agent' AS source_type,e.agent_id,
                     a.name AS server_name,e.source AS source_file,e.id AS row_id FROM agent_events e
                     JOIN agents a ON a.id=e.agent_id WHERE e.id>? AND e.kind='access.log' ORDER BY e.id LIMIT ?'''
        with self.store.lock:
            return [dict(r) for r in self.store.db.execute(sql, (after, limit))]

    def match(self, rules, record, config=None):
        from source_policy import is_local_source
        config = config or self.settings(self.root)
        if config.get('analysisMode') != 'local' and is_local_source(config, record):
            return None, None
        event = self.normalized(record)
        if not event:
            return None, None
        targets = [event['target']] + ([event['lastTarget']] if event.get('lastTarget') else [])
        for rule in rules:
            if any(rule.matches(event['ip'], event['method'], t, event['status'], event.get('userAgent', '')) for t in targets):
                return rule, event
        return None, None

    def scan_table(self, table, rules, after, until=None):
        """Check rows after `after` (up to `until`); returns the last row id looked at."""
        hits = {}
        rows = self.rows(table, after, self.BATCH)
        config = self.settings(self.root)
        last = after
        for record in rows:
            row_id = record.get('row_id', record['id'])
            if until is not None and row_id > until:
                break
            last = row_id
            rule, event = self.match(rules, record, config)
            if rule:
                origin = event.get('server') or (f'网站 #{event["website"]}' if table == 'events' else '')
                sample = f"{event['method']} {event['target']}"[:300]
                item = hits.setdefault(event['ip'], [rule, 0, sample, origin])
                item[1] += 1
        now = time.time()
        with self.store.lock, self.store.db:
            for ip, (rule, count, sample, origin) in hits.items():
                self.store.db.execute('''INSERT INTO rule_block_ips(ip,rule_id,rule_name,hits,first_seen,last_seen,sample,origin,updated)
                    VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET hits=hits+excluded.hits,last_seen=excluded.last_seen,
                    rule_id=excluded.rule_id,rule_name=excluded.rule_name,sample=excluded.sample,updated=excluded.updated,
                    state=CASE WHEN state='removed' THEN 'pending' ELSE state END''',
                    (ip, rule.id, rule.name, count, now, now, sample, origin, now))
        totals = {}
        for rule, count, _, _ in hits.values():
            totals[str(rule.id)] = totals.get(str(rule.id), 0) + count
        self.rules.add_hits(totals)
        return last, len(rows) == self.BATCH

    def scan(self):
        rules = self.block_rules_safe()
        for table in ('events', 'agent_events'):
            with self.store.lock:
                after = self.store.db.execute('SELECT last_id FROM rule_block_cursor WHERE source=?', (table,)).fetchone()[0]
            if rules:
                last, _ = self.scan_table(table, rules, after)
            else:
                with self.store.lock:
                    last = self.store.db.execute(f'SELECT COALESCE(MAX(id),0) FROM {table}').fetchone()[0]
            with self.store.lock, self.store.db:
                self.store.db.execute('UPDATE rule_block_cursor SET last_id=? WHERE source=?', (max(last, after), table))

    def block_rules_safe(self):
        try:
            return self.rules.block_rules()
        except ValueError:
            return []

    def rescan(self):
        """Apply the current 必封 rules to every log row still stored on the platform."""
        if self.rescanning:
            raise ValueError('正在扫描已保存日志，请稍候。')
        rules = self.block_rules_safe()
        if not rules:
            raise ValueError('还没有启用的必封规则。')
        self.rescanning = True

        def work():
            try:
                for table in ('events', 'agent_events'):
                    with self.store.lock:
                        until = self.store.db.execute(f'SELECT COALESCE(MAX(id),0) FROM {table}').fetchone()[0]
                    after, more = 0, True
                    while more and after < until and not self.stop_event.is_set():
                        after, more = self.scan_table(table, rules, after, until)
            finally:
                self.rescanning = False
                self.wake_event.set()
        threading.Thread(target=work, daemon=True, name='rule-rescan').start()
        return self.public()

    def process(self):
        if self.settings(self.root).get('analysisMode') == 'local':
            return  # Detection remains active; local mode requires manual decisions.
        now = time.time()
        with self.store.lock:
            pending = [dict(r) for r in self.store.db.execute(
                "SELECT * FROM rule_block_ips WHERE state IN ('pending','failed') AND retry_at<=? ORDER BY first_seen LIMIT ?",
                (now, self.WRITES_PER_ROUND))]
        if not pending:
            return
        config = self.settings(self.root)
        local_agents = config.get('localAgentIds', [])
        with self.store.lock:
            local_origins = {row[0] for row in self.store.db.execute(
                'SELECT name FROM agents WHERE id IN (' + ','.join('?' for _ in local_agents) + ')', local_agents)} \
                if local_agents else set()
        panel = urlsplit(self.client.config['url']).hostname
        for row in pending:
            if row['origin'] in local_origins:
                with self.store.lock, self.store.db:
                    self.store.db.execute("UPDATE rule_block_ips SET state='review',detail=?,updated=? WHERE ip=?",
                                          ('该来源使用本地规则，仅供人工决定封禁。', time.time(), row['ip']))
                continue
            reason = self.protection(row['ip'], config, panel)
            if reason:
                state, detail = 'protected', reason + '，未加入黑名单'
            else:
                try:
                    state, detail = self.waf.add(row['ip'], f'清洗规则必封「{row["rule_name"]}」：{row["sample"]}'[:200],
                                                 origin='CleanRule')
                except Exception as exc:
                    attempts = row['attempts'] + 1
                    detail = str(exc) if type(exc).__name__ in ('SecurityError', 'PanelError') else '写入 WAF 失败，稍后重试'
                    if getattr(exc, 'status', 0) == 409:
                        state = 'protected'  # WAF whitelist or a conflicting rule: never retried automatically.
                    else:
                        state = 'failed'
                    with self.store.lock, self.store.db:
                        self.store.db.execute('UPDATE rule_block_ips SET state=?,detail=?,attempts=?,retry_at=?,updated=? WHERE ip=?',
                                              (state, detail[:300], attempts, time.time() + min(3600, 30 * 2 ** min(attempts, 7)),
                                               time.time(), row['ip']))
                    continue
            with self.store.lock, self.store.db:
                self.store.db.execute('UPDATE rule_block_ips SET state=?,detail=?,updated=? WHERE ip=?',
                                      (state, detail[:300], time.time(), row['ip']))

    def public(self):
        with self.store.lock:
            counts = dict(self.store.db.execute('SELECT state,COUNT(*) FROM rule_block_ips GROUP BY state').fetchall())
            rows = [dict(r) for r in self.store.db.execute(
                'SELECT ip,rule_name,hits,first_seen,last_seen,sample,origin,state,detail FROM rule_block_ips ORDER BY last_seen DESC LIMIT 100')]
        return {'counts': counts, 'rows': rows, 'rescanning': self.rescanning, 'error': self.last_error}

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.scan()
                self.process()
                self.last_error = ''
            except Exception as exc:
                self.last_error = str(exc)[:300] if type(exc).__name__ in ('SecurityError', 'PanelError') else '必封规则执行失败，稍后重试。'
            self.wake_event.wait(10)
            self.wake_event.clear()

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True, name='rule-block')
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.wake_event.set()
