"""Persist newly collected records, byte cursors and AI decisions locally."""
import json
from pathlib import Path
import sqlite3
import threading
import time


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS cursors (source TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, website INTEGER NOT NULL, kind TEXT NOT NULL,
                raw TEXT NOT NULL, received REAL NOT NULL, ai_state TEXT NOT NULL DEFAULT 'pending');
            CREATE INDEX IF NOT EXISTS event_feed ON events(website,kind,id);
            CREATE INDEX IF NOT EXISTS event_pending ON events(ai_state,id);
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, website INTEGER NOT NULL, ip TEXT NOT NULL,
                attack INTEGER NOT NULL, confidence REAL NOT NULL, category TEXT NOT NULL,
                reason TEXT NOT NULL, evidence TEXT NOT NULL, state TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '', created REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS decision_history ON decisions(attack,id);
            CREATE TABLE IF NOT EXISTS analysis_event_decisions (
                event_id INTEGER PRIMARY KEY, decision_id INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS blocks (
                ip TEXT PRIMARY KEY, name TEXT NOT NULL, managed INTEGER NOT NULL,
                state TEXT NOT NULL, updated REAL NOT NULL);
            -- Websites whose access logs are collected but never sent to AI (e.g. honeypots).
            CREATE TABLE IF NOT EXISTS ai_excluded_sites (
                website INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '', updated REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS ai_usage (
                day TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL, requests INTEGER NOT NULL,
                prompt INTEGER NOT NULL, cache_hit INTEGER NOT NULL, cache_miss INTEGER NOT NULL,
                completion INTEGER NOT NULL, PRIMARY KEY(day,provider,model));
            CREATE TABLE IF NOT EXISTS ai_result_cache (
                key TEXT PRIMARY KEY, value TEXT NOT NULL, expires REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS ai_result_cache_expiry ON ai_result_cache(expires);
            CREATE TABLE IF NOT EXISTS ai_result_cache_usage (
                day TEXT PRIMARY KEY, hits INTEGER NOT NULL, rows INTEGER NOT NULL);
        """)
        columns = {row['name'] for row in self.db.execute('PRAGMA table_info(decisions)')}
        for name, definition in {'provider': "TEXT NOT NULL DEFAULT 'deepseek'", 'model': "TEXT NOT NULL DEFAULT ''",
                                 'record_count': 'INTEGER NOT NULL DEFAULT 0', 'model_facts': "TEXT NOT NULL DEFAULT '{}'",
                                 'source_type': "TEXT NOT NULL DEFAULT 'panel'", 'agent_id': "TEXT NOT NULL DEFAULT ''",
                                 'source_name': "TEXT NOT NULL DEFAULT ''", 'source_file': "TEXT NOT NULL DEFAULT ''",
                                 'historical': 'INTEGER NOT NULL DEFAULT 0'}.items():
            if name not in columns:
                self.db.execute(f'ALTER TABLE decisions ADD COLUMN {name} {definition}')
        self.db.commit()
        self.ensure_agent_schema()

    def ensure_agent_schema(self):
        with self.lock, self.db:
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1, created REAL NOT NULL,
                    last_seen REAL, metadata TEXT NOT NULL DEFAULT '{}');
                CREATE TABLE IF NOT EXISTS agent_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL,
                    event_id TEXT NOT NULL, kind TEXT NOT NULL, source TEXT NOT NULL,
                    raw TEXT NOT NULL, collected REAL NOT NULL, received REAL NOT NULL,
                    ai_state TEXT NOT NULL DEFAULT 'ignored', UNIQUE(agent_id,event_id));
                CREATE INDEX IF NOT EXISTS agent_log_feed ON agent_events(agent_id,kind,id);
            ''')
            columns = {row['name'] for row in self.db.execute('PRAGMA table_info(agent_events)')}
            if 'ai_state' not in columns:
                self.db.execute("ALTER TABLE agent_events ADD COLUMN ai_state TEXT NOT NULL DEFAULT 'ignored'")
                self.db.execute("UPDATE agent_events SET ai_state='pending' WHERE kind='access.log'")
            if 'priority_time' not in columns:
                self.db.execute('ALTER TABLE agent_events ADD COLUMN priority_time REAL')
            self.db.execute('CREATE INDEX IF NOT EXISTS agent_ai_pending ON agent_events(ai_state,received,id)')
            self.db.execute('CREATE INDEX IF NOT EXISTS agent_ai_priority ON agent_events(ai_state,COALESCE(priority_time,received),id)')
            self.db.execute('CREATE INDEX IF NOT EXISTS decision_source ON decisions(source_type,agent_id,id)')
            self.db.execute('CREATE INDEX IF NOT EXISTS decision_ip ON decisions(ip,created)')
            self.ensure_counts()

    def ensure_counts(self):
        """Row counts per table / source / kind / AI state, kept current by triggers.

        Every collected log line is kept, so status pages must not count the log tables
        themselves: that would take longer as the archive grows, under the shared lock."""
        fresh = not self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='log_counts'").fetchone()
        self.db.execute('''CREATE TABLE IF NOT EXISTS log_counts (
            tbl TEXT NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL, ai_state TEXT NOT NULL,
            n INTEGER NOT NULL, PRIMARY KEY(tbl,source,kind,ai_state))''')
        for table, source in (('events', 'CAST({row}.website AS TEXT)'), ('agent_events', '{row}.agent_id')):
            new, old = source.format(row='NEW'), source.format(row='OLD')
            add = f'''INSERT INTO log_counts VALUES('{table}',{new},NEW.kind,NEW.ai_state,1)
                      ON CONFLICT(tbl,source,kind,ai_state) DO UPDATE SET n=n+1;'''
            remove = f'''UPDATE log_counts SET n=n-1 WHERE tbl='{table}' AND source={old} AND kind=OLD.kind AND ai_state=OLD.ai_state;'''
            self.db.execute(f'CREATE TRIGGER IF NOT EXISTS {table}_count_insert AFTER INSERT ON {table} BEGIN {add} END')
            self.db.execute(f'CREATE TRIGGER IF NOT EXISTS {table}_count_delete AFTER DELETE ON {table} BEGIN {remove} END')
            self.db.execute(f'''CREATE TRIGGER IF NOT EXISTS {table}_count_update AFTER UPDATE OF ai_state,kind ON {table}
                WHEN OLD.ai_state IS NOT NEW.ai_state OR OLD.kind IS NOT NEW.kind BEGIN {remove} {add} END''')
        if fresh:
            self.db.execute('''INSERT INTO log_counts SELECT 'events',CAST(website AS TEXT),kind,ai_state,COUNT(*)
                FROM events GROUP BY website,kind,ai_state''')
            self.db.execute('''INSERT INTO log_counts SELECT 'agent_events',agent_id,kind,ai_state,COUNT(*)
                FROM agent_events GROUP BY agent_id,kind,ai_state''')

    def counts(self, table, source=None, db=None):
        """{(kind, ai_state): rows} for one log table, optionally for one website / agent."""
        sql, params = 'SELECT kind,ai_state,SUM(n) FROM log_counts WHERE tbl=?', [table]
        if source is not None:
            sql += ' AND source=?'; params.append(str(source))
        return {(kind, state): n for kind, state, n in (db or self.db).execute(sql + ' GROUP BY kind,ai_state', params)}

    def reader(self):
        """A separate read-only connection: long searches over the archive run without the shared lock."""
        db = sqlite3.connect(Path(self.path).resolve().as_uri() + '?mode=ro', uri=True, timeout=30)
        db.row_factory = sqlite3.Row
        return db

    def cursor(self, source):
        with self.lock:
            row = self.db.execute("SELECT value FROM cursors WHERE source=?", (source,)).fetchone()
            return json.loads(row[0]) if row else None

    def excluded_sites(self):
        with self.lock:
            return {row[0] for row in self.db.execute('SELECT website FROM ai_excluded_sites')}

    def set_ai_excluded(self, website, excluded, name=''):
        """Stop or resume AI analysis for one website; queued records leave the queue immediately.
        Records collected while excluded stay excluded after resuming."""
        if type(website) is not int or website <= 0 or type(excluded) is not bool:
            raise ValueError('网站或开关参数不正确。')
        with self.lock, self.db:
            if excluded:
                self.db.execute('INSERT OR REPLACE INTO ai_excluded_sites VALUES(?,?,?)', (website, str(name)[:255], time.time()))
                self.db.execute("UPDATE events SET ai_state='excluded' WHERE website=? AND ai_state='pending'", (website,))
            else:
                self.db.execute('DELETE FROM ai_excluded_sites WHERE website=?', (website,))
        return excluded

    def append(self, source, cursor, website, kind, lines):
        with self.lock, self.db:
            excluded = self.db.execute('SELECT 1 FROM ai_excluded_sites WHERE website=?', (website,)).fetchone()
            access_state = 'excluded' if excluded else 'pending'
            self.db.executemany("INSERT INTO events(website,kind,raw,received,ai_state) VALUES(?,?,?,?,?)",
                                [(website, kind, line, time.time(), access_state if kind == 'access.log' else 'ignored') for line in lines])
            self.db.execute("INSERT OR REPLACE INTO cursors VALUES(?,?)", (source, json.dumps(cursor)))
            # Every collected line is kept; nothing is pruned.

    def feed(self, website, kind, after, limit):
        with self.lock:
            last = self.db.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
            earliest = self.db.execute("SELECT MIN(id) FROM events").fetchone()[0]
            if after is None:
                rows = self.db.execute("SELECT * FROM events WHERE website=? AND kind=? ORDER BY id DESC LIMIT ?",
                                       (website, kind, limit)).fetchall()[::-1]
                more = False
            else:
                rows = self.db.execute("SELECT * FROM events WHERE website=? AND kind=? AND id>? ORDER BY id LIMIT ?",
                                       (website, kind, after, limit + 1)).fetchall()
                more = len(rows) > limit
                rows = rows[:limit]
            return {"events": [dict(r) for r in rows], "after": rows[-1]['id'] if more else last,
                    "hasMore": more, "retentionGap": after is not None and earliest is not None and after < earliest - 1,
                    "total": self.stored_total(website, kind)}

    def stored_total(self, website, kind):
        """Lines of one website log kept on this machine, from the counter table."""
        with self.lock:
            return sum(n for (k, _), n in self.counts('events', website).items() if k == kind)

    def pending(self, limit, fresh_window=300, *, agent_ids=None):
        with self.lock:
            if agent_ids is not None:
                agent_ids = tuple(dict.fromkeys(agent_ids))
                if not agent_ids:
                    return []
                placeholders = ','.join('?' for _ in agent_ids)
                sql = f'''SELECT -e.id AS id,0 AS website,e.kind,e.raw,e.received,e.ai_state,
                    'agent' AS source_type,e.agent_id,a.name AS server_name,e.source AS source_file,
                    e.collected,COALESCE(e.priority_time,e.received) AS priority
                    FROM agent_events e JOIN agents a ON a.id=e.agent_id
                    WHERE e.ai_state='pending' AND a.enabled=1 AND e.agent_id IN ({placeholders})
                    AND COALESCE(e.priority_time,e.received){{0}}? ORDER BY priority,id LIMIT ?'''
                since = time.time() - fresh_window
                rows = [dict(r) for r in self.db.execute(sql.format('>='), (*agent_ids, since, limit))]
                if len(rows) < limit:
                    rows += [dict(r) for r in self.db.execute(sql.format('<'), (*agent_ids, since, limit - len(rows)))]
                return rows
            # Negative model evidence IDs identify agent rows without colliding
            # with 1Panel rows. Each original record remains stored only once.
            sql = '''
                SELECT id,website,kind,raw,received,ai_state,'panel' AS source_type,
                    '' AS agent_id,'' AS server_name,'' AS source_file,received AS collected,received AS priority,
                    EXISTS(SELECT 1 FROM analysis_event_decisions x JOIN decisions d ON d.id=x.decision_id
                           WHERE x.event_id=events.id AND d.provider='local') AS reviewed_locally FROM events
                    WHERE ai_state='pending' AND received{0}?
                UNION ALL SELECT -e.id,0,e.kind,e.raw,e.received,e.ai_state,'agent',
                    e.agent_id,a.name,e.source,e.collected,COALESCE(e.priority_time,e.received),0 FROM agent_events e JOIN agents a ON a.id=e.agent_id
                    WHERE e.ai_state='pending' AND a.enabled=1 AND COALESCE(e.priority_time,e.received){0}?
                ORDER BY priority,id LIMIT ?'''
            # Rows received in the last few minutes go first, so a backlog of older rows
            # cannot age live attacks past the automatic-blocking window.
            since = time.time() - fresh_window
            rows = [dict(r) for r in self.db.execute(sql.format('>='), (since, since, limit))]
            if len(rows) < limit:
                rows += [dict(r) for r in self.db.execute(sql.format('<'), (since, since, limit - len(rows)))]
            return rows

    def mark(self, ids, state):
        with self.lock, self.db:
            self.db.executemany("UPDATE events SET ai_state=? WHERE id=?", [(state, i) for i in ids if i > 0])
            self.db.executemany("UPDATE agent_events SET ai_state=? WHERE id=?", [(state, -i) for i in ids if i < 0])

    def add_decision(self, website, verdict, state):
        with self.lock, self.db:
            result = self.db.execute("""INSERT INTO decisions
                (website,ip,attack,confidence,category,reason,evidence,state,created) VALUES(?,?,?,?,?,?,?,?,?)""",
                (website, verdict['ip'], int(verdict['is_attack']), verdict['confidence'], verdict['attack_type'],
                 verdict['reason'], json.dumps(verdict['evidence_ids']), state, time.time()))
            return result.lastrowid

    def complete_analysis(self, events, verdicts, provider, model):
        """Commit judgments and their completed input rows together."""
        decisions = []
        with self.lock, self.db:
            for verdict in verdicts:
                records = [e for e in events if e['ip'] == verdict['ip']]
                website = next((e['website'] for e in records if e['id'] in verdict['evidence_ids']), records[0]['website'])
                source = next((e for e in records if e['id'] in verdict['evidence_ids']), records[0])
                historical = any(e.get('_historical', False) for e in records)
                daily = all(e.get('_daily', False) for e in records)
                evidence = verdict['evidence_ids']
                if not evidence and not verdict['is_attack']:
                    # The model is asked not to cite normal traffic (output tokens); keep samples for the history view.
                    evidence = [records[0]['id']] + ([records[-1]['id']] if len(records) > 1 else [])
                result = self.db.execute('''INSERT INTO decisions
                    (website,ip,attack,confidence,category,reason,evidence,state,created,provider,model,record_count,model_facts,
                     source_type,agent_id,source_name,source_file,historical,detail)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (website, verdict['ip'], int(verdict['is_attack']), verdict['confidence'], verdict['attack_type'],
                     verdict['reason'], json.dumps(evidence), 'review' if verdict['is_attack'] else 'normal',
                     time.time(), provider, model, sum(e.get('_count', 1) for e in records), json.dumps(verdict.get('modelFacts', {})),
                     source.get('_source_type','panel'),source.get('_agent_id',''),source.get('server',''),
                     source.get('_source_file',''),int(historical),
                     '' if not historical else '按日清洗的服务器日志，48 小时内的攻击判断可自动加黑。' if daily
                     else '历史或时间不完整的日志，仅供复核，未触发自动加黑。'))
                decisions.append((result.lastrowid, verdict, records))
                self.db.executemany('INSERT OR REPLACE INTO analysis_event_decisions(event_id,decision_id) VALUES(?,?)',
                                    [(record['id'], result.lastrowid) for record in records])
            self.mark([e['id'] for e in events], 'analyzed')
        return decisions

    def recent_attack_evidence(self, decision_id, since, threshold):
        """Evidence rows of the same IP and source cited by other recent, live attack judgments.

        Live logs reach the AI in small waves, so one client's requests can be split
        across several judgments that each cite a single row."""
        with self.lock:
            own = self.db.execute('SELECT ip,source_type,agent_id,website FROM decisions WHERE id=?', (decision_id,)).fetchone()
            if not own:
                return 0
            rows = self.db.execute('''SELECT evidence FROM decisions WHERE ip=? AND created>=? AND id<>? AND attack=1
                AND historical=0 AND confidence>=? AND source_type=? AND agent_id=? AND website=?''',
                (own['ip'], since, decision_id, threshold, own['source_type'], own['agent_id'], own['website']))
            return sum(len(json.loads(row[0])) for row in rows)

    def decision(self, decision_id):
        with self.lock:
            row = self.db.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
            if not row:
                raise ValueError("判断记录不存在。")
            return dict(row)

    def update_decision(self, decision_id, state, detail=''):
        with self.lock, self.db:
            self.db.execute("UPDATE decisions SET state=?,detail=? WHERE id=?", (state, detail, decision_id))

    def update_ip_decisions(self, ip, state, detail=''):
        with self.lock, self.db:
            self.db.execute("UPDATE decisions SET state=?,detail=? WHERE ip=? AND attack=1", (state, detail, ip))

    def block(self, ip):
        with self.lock:
            row = self.db.execute("SELECT * FROM blocks WHERE ip=?", (ip,)).fetchone()
            return dict(row) if row else None

    def set_block(self, ip, name, managed, state):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO blocks VALUES(?,?,?,?,?)", (ip, name, int(managed), state, time.time()))

    def add_ai_usage(self, provider, model, usage):
        """Daily token totals from the provider's own usage report, including prefix-cache hits."""
        number = lambda key: usage.get(key) if type(usage.get(key)) is int and usage.get(key) >= 0 else 0
        prompt = number('prompt_tokens')
        details = usage.get('prompt_tokens_details')
        cached = details.get('cached_tokens') if isinstance(details, dict) else None
        hit = number('prompt_cache_hit_tokens') if 'prompt_cache_hit_tokens' in usage else \
            (cached if type(cached) is int and cached >= 0 else 0)
        hit = min(hit, prompt)
        miss = number('prompt_cache_miss_tokens') if 'prompt_cache_miss_tokens' in usage else prompt - hit
        values = (prompt, hit, miss, number('completion_tokens'))
        with self.lock, self.db:
            self.db.execute('''INSERT INTO ai_usage VALUES(?,?,?,1,?,?,?,?) ON CONFLICT(day,provider,model) DO UPDATE SET
                requests=requests+1,prompt=prompt+excluded.prompt,cache_hit=cache_hit+excluded.cache_hit,
                cache_miss=cache_miss+excluded.cache_miss,completion=completion+excluded.completion''',
                            (time.strftime('%Y-%m-%d'), provider, str(model)[:100], *values))

    def ai_usage_today(self):
        with self.lock:
            row = self.db.execute('''SELECT COALESCE(SUM(requests),0),COALESCE(SUM(prompt),0),COALESCE(SUM(cache_hit),0),
                COALESCE(SUM(cache_miss),0),COALESCE(SUM(completion),0) FROM ai_usage WHERE day=?''', (time.strftime('%Y-%m-%d'),)).fetchone()
        return dict(zip(('requests', 'prompt', 'cacheHit', 'cacheMiss', 'completion'), row))

    def ai_cache_read(self, key):
        with self.lock:
            row = self.db.execute('SELECT value FROM ai_result_cache WHERE key=? AND expires>?',
                                  (key, time.time())).fetchone()
        try:
            return json.loads(row[0]) if row else None
        except (ValueError, TypeError):
            return None

    def ai_cache_write(self, key, entry):
        now = time.time()
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO ai_result_cache VALUES(?,?,?)',
                            (key, json.dumps(entry, ensure_ascii=False), entry['expires']))
            if now - getattr(self, '_cache_cleanup', 0) >= 60:
                self.db.execute('DELETE FROM ai_result_cache WHERE expires<=?', (now,))
                self.db.execute('''DELETE FROM ai_result_cache WHERE key IN
                    (SELECT key FROM ai_result_cache ORDER BY expires DESC LIMIT -1 OFFSET 10000)''')
                self._cache_cleanup = now

    def add_ai_cache_usage(self, hits, rows):
        with self.lock, self.db:
            self.db.execute('''INSERT INTO ai_result_cache_usage VALUES(?,?,?) ON CONFLICT(day) DO UPDATE SET
                hits=hits+excluded.hits,rows=rows+excluded.rows''', (time.strftime('%Y-%m-%d'), hits, rows))

    def ai_cache_usage_today(self):
        with self.lock:
            row = self.db.execute('SELECT hits,rows FROM ai_result_cache_usage WHERE day=?',
                                  (time.strftime('%Y-%m-%d'),)).fetchone()
        return dict(zip(('hits', 'rows'), row or (0, 0)))

    def ai_summary(self, source='all', agent_id=''):
        tables=[]
        if source in ('all','panel'):
            tables.append(('events',None,'events INDEXED BY event_pending','',[]))
        if source in ('all','agent'):
            tables.append(('agent_events',agent_id or None,'agent_events INDEXED BY agent_ai_pending',
                           ' AND agent_id=?' if agent_id else '',[agent_id] if agent_id else []))
        counts,skipped,oldest={},0,[]
        with self.lock:
            for table,key,indexed,where,params in tables:
                # Counters, not COUNT(*): the log tables keep every line and only grow.
                for (kind,state),count in self.counts(table,key).items():
                    counts[state]=counts.get(state,0)+count
                    if kind=='access.log' and state in ('ignored','expired','unparsed'): skipped+=count
                # Walks only the pending rows of the AI-state index.
                value=self.db.execute(f"SELECT MIN(received) FROM {indexed} WHERE ai_state='pending'{where}",params).fetchone()[0]
                if value is not None: oldest.append(value)
            where,params=self.decision_scope(source,agent_id)
            attacks=self.db.execute(f'SELECT COUNT(*) FROM decisions WHERE {where} AND attack=1',params).fetchone()[0]
            if source=='all':
                listed=self.db.execute("SELECT COUNT(*) FROM blocks WHERE state IN ('listed','inactive','existing')").fetchone()[0]
            else:
                listed=self.db.execute(f"SELECT COUNT(DISTINCT d.ip) FROM decisions d JOIN blocks b ON b.ip=d.ip WHERE {where} AND d.attack=1 AND b.state IN ('listed','inactive','existing')",params).fetchone()[0]
            return {'pending':counts.get('pending',0),'analyzed':counts.get('analyzed',0),'skipped':skipped,
                    'expired':counts.get('expired',0),'unparsed':counts.get('unparsed',0),'excluded':counts.get('excluded',0),
                    'filtered':counts.get('filtered',0),
                    'oldestPendingReceived':min(oldest) if oldest else None,'attacks':attacks,'listed':listed}

    @staticmethod
    def decision_scope(source, agent_id):
        where,params='1=1',[]
        if source!='all': where+=' AND source_type=?'; params.append(source)
        if agent_id: where+=' AND agent_id=?'; params.append(agent_id)
        return where,params

    def dashboard(self, page=1, page_size=20, verdict='all', through=None, source='all', agent_id=''):
        if (type(page) is not int or not 1 <= page <= 1000000 or
                type(page_size) is not int or page_size not in (20,50,100) or verdict not in ('all','normal','attack') or
                source not in ('all','panel','agent') or not isinstance(agent_id,str) or len(agent_id)>36 or
                (agent_id and source!='agent') or
                (through is not None and (type(through) is not int or not 0 <= through <= 2**63-1))):
            raise ValueError('分析历史参数不正确。')
        with self.lock:
            summary=self.ai_summary(source,agent_id)
            if through is None:
                through=self.db.execute('SELECT COALESCE(MAX(id),0) FROM decisions').fetchone()[0]
            scope,scope_params=self.decision_scope(source,agent_id)
            totals=dict(self.db.execute(f'SELECT attack,COUNT(*) FROM decisions WHERE id<=? AND {scope} GROUP BY attack',(through,*scope_params)).fetchall())
            all_total=sum(totals.values()); where,params='id<=? AND '+scope,[through,*scope_params]
            if verdict!='all': where+=' AND attack=?'; params.append(int(verdict=='attack'))
            total=all_total if verdict=='all' else totals.get(int(verdict=='attack'),0)
            pages=max(1,(total+page_size-1)//page_size); page=min(page,pages)
            rows=self.db.execute(f'SELECT * FROM decisions WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?',(*params,page_size,(page-1)*page_size)).fetchall()
            decisions=[]
            for row in rows:
                item=dict(row); item['modelFacts']=json.loads(item.pop('model_facts'))
                ids=json.loads(item.pop('evidence')); item['evidenceCount']=len(ids); evidence=[]
                for event_id in ids[:10]:
                    if event_id<0:
                        event=self.db.execute('SELECT -id AS id,raw,source AS source_file,agent_id FROM agent_events WHERE id=?',(-event_id,)).fetchone()
                    else:
                        event=self.db.execute('SELECT id,raw FROM events WHERE id=?',(event_id,)).fetchone()
                    if event: evidence.append(dict(event))
                item['evidence']=evidence
                block=self.db.execute('SELECT managed,state FROM blocks WHERE ip=?',(item['ip'],)).fetchone()
                item['canUnblock']=bool(item['attack'] and block and block['managed'] and block['state'] in ('listed','inactive','existing','submitting'))
                decisions.append(item)
            return {'summary':summary,'decisions':decisions,
                    'history':{'page':page,'pageSize':page_size,'total':total,'pages':pages,'through':through,
                               'verdict':verdict,'source':source,'agentId':agent_id,'allTotal':all_total,
                               'normalTotal':totals.get(0,0),'attackTotal':totals.get(1,0)}}

    def close(self):
        with self.lock:
            self.db.close()
