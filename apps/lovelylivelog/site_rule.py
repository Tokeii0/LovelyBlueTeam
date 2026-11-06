"""Minute-based, explicit access policy for one unused website; no model calls."""
import ipaddress
import json
import os
import re
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit

from security import SecurityError, protection_reason, settings

DOMAIN = 'honeypot.example.com'
INTERVAL = 60


def visitor_ip(raw):
    try:
        if raw.lstrip().startswith('{'):
            data = json.loads(raw)
            value = data.get('remote_addr') or data.get('client_ip') or data.get('ip')
        else:
            value = raw.split(None, 1)[0]
        address = ipaddress.ip_address(value)
        return str(address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address)
    except (ValueError, TypeError, AttributeError, IndexError):
        return None


class SiteVisitRule:
    def __init__(self, root, client, store, waf):
        self.root, self.client, self.store, self.waf = root, client, store, waf
        values = {}
        config_path = Path(root) / '.env'
        if config_path.exists():
            for line in config_path.read_text(encoding='utf-8-sig').splitlines():
                if '=' in line and not line.lstrip().startswith('#'):
                    key, value = line.split('=', 1)
                    values[key.strip()] = value.strip().strip("\"'")
        self.domain = os.environ.get('SITE_RULE_DOMAIN', values.get('SITE_RULE_DOMAIN', DOMAIN)).lower().rstrip('.')
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', self.domain):
            raise ValueError('SITE_RULE_DOMAIN 应为不含协议、路径或端口的主机名。')
        self.source = client.config['url'] + '|' + client.config['prefix'] + '|' + self.domain
        self.stop_event, self.wake_event = threading.Event(), threading.Event()
        self.cycle_lock = threading.Lock()
        self.busy, self.thread = False, None
        with store.lock, store.db:
            store.db.executescript('''
                CREATE TABLE IF NOT EXISTS site_visit_rule (
                    id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL DEFAULT '', website INTEGER, started REAL,
                    last_event INTEGER NOT NULL DEFAULT 0, checked REAL, next_check REAL,
                    last_rows INTEGER NOT NULL DEFAULT 0, last_ips INTEGER NOT NULL DEFAULT 0,
                    unparsed INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '');
                INSERT OR IGNORE INTO site_visit_rule(id) VALUES(1);
                CREATE TABLE IF NOT EXISTS site_visit_ips (
                    source TEXT NOT NULL, ip TEXT NOT NULL, count INTEGER NOT NULL,
                    first_seen REAL NOT NULL, last_seen REAL NOT NULL,
                    first_event INTEGER NOT NULL, last_event INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending', detail TEXT NOT NULL DEFAULT '',
                    attempts INTEGER NOT NULL DEFAULT 0, retry_at REAL NOT NULL DEFAULT 0,
                    updated REAL NOT NULL, PRIMARY KEY(source,ip));
                CREATE INDEX IF NOT EXISTS site_rule_pending ON site_visit_ips(source,state,retry_at);
            ''')

    def config(self):
        with self.store.lock:
            return dict(self.store.db.execute('SELECT * FROM site_visit_rule WHERE id=1').fetchone())

    def target(self):
        matches = [site for site in self.client.websites() if site['name'].lower().rstrip('.') == self.domain]
        if len(matches) != 1:
            raise ValueError('目标网站未找到或归属不唯一，已停止此规则的加黑。')
        site = matches[0]
        meta = self.client.metadata(site['id'])
        if not meta.get('accessLog'):
            raise ValueError('目标网站的访问日志未开启，请在 1Panel 中检查。')
        return site['id']

    def configure(self, enabled):
        if type(enabled) is not bool:
            raise ValueError('规则开关参数不正确。')
        # Also serialize a toggle with collection so it cannot advance a new baseline.
        with self.cycle_lock:
            current = self.config()
            if bool(current['enabled']) == enabled and current['source'] == self.source:
                return self.public()
            website = self.target() if enabled else current['website']
            now = time.time()
            with self.store.lock, self.store.db:
                through = self.store.db.execute('SELECT COALESCE(MAX(id),0) FROM events').fetchone()[0]
                self.store.db.execute('''UPDATE site_visit_rule SET enabled=?,source=?,website=?,started=?,
                    last_event=?,next_check=?,last_error='' WHERE id=1''',
                                      (int(enabled), self.source, website, now, through, now + INTERVAL if enabled else None))
                if not enabled:
                    self.store.db.execute("UPDATE site_visit_ips SET state='paused',detail='规则已暂停，未执行' WHERE source=? AND state IN ('pending','failed')", (self.source,))
        self.wake_event.set()
        return self.public()

    def active(self):
        config = self.config()
        return bool(config['enabled'] and config['source'] == self.source and not self.stop_event.is_set()
                    and settings(self.root).get('analysisMode') != 'local')

    def collect(self, website, now):
        with self.cycle_lock:
            config = self.config()
            if not self.active():
                return
            if config['website'] != website:
                raise ValueError('网站编号发生变化，已停止此规则；请重新开启以确认新的日志归属。')
            with self.store.lock, self.store.db:
                rows = self.store.db.execute("SELECT id,raw,received FROM events WHERE website=? AND kind='access.log' AND id>? ORDER BY id", (website, config['last_event'])).fetchall()
                through = self.store.db.execute('SELECT COALESCE(MAX(id),0) FROM events').fetchone()[0]
                groups, unparsed = {}, 0
                for event in rows:
                    ip = visitor_ip(event['raw'])
                    if ip is None:
                        unparsed += 1
                        continue
                    group = groups.setdefault(ip, {'count':0, 'first':event, 'last':event})
                    group['count'] += 1; group['last'] = event
                for ip, group in groups.items():
                    self.store.db.execute('''INSERT INTO site_visit_ips
                        (source,ip,count,first_seen,last_seen,first_event,last_event,updated)
                        VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(source,ip) DO UPDATE SET
                        count=count+excluded.count,last_seen=excluded.last_seen,last_event=excluded.last_event,
                        state='pending',updated=excluded.updated''',
                        (self.source,ip,group['count'],group['first']['received'],group['last']['received'],
                         group['first']['id'],group['last']['id'],now))
                self.store.db.execute('''UPDATE site_visit_rule SET last_event=?,checked=?,next_check=?,last_rows=?,
                    last_ips=?,unparsed=unparsed+?,last_error='' WHERE id=1''',
                    (through,now,now + INTERVAL,len(rows),len(groups),unparsed))

    def process_once(self):
        if not self.active():
            return 0
        now = time.time()
        try:
            self.collect(self.target(), now)
            with self.store.lock:
                rows = self.store.db.execute("SELECT * FROM site_visit_ips WHERE source=? AND state IN ('pending','failed') AND retry_at<=? ORDER BY updated", (self.source,now)).fetchall()
            completed = 0
            for row in rows:
                if not self.active():
                    break
                config = settings(self.root)
                # This policy applies to every visitor, including private IPs;
                # keep explicit operator protection and non-routable addresses.
                config['allowPrivate'] = True
                reason = protection_reason(row['ip'],config,urlsplit(self.client.config['url']).hostname)
                previous = self.store.block(row['ip'])
                if previous and previous['state'] == 'unblocked':
                    reason = '已手动移除并保护，停止再次自动加黑'
                try:
                    if reason:
                        state, detail = 'protected', reason
                    else:
                        def still_allowed():
                            latest = settings(self.root); latest['allowPrivate'] = True
                            block = self.store.block(row['ip'])
                            return (self.active() and not protection_reason(row['ip'],latest,urlsplit(self.client.config['url']).hostname)
                                    and not (block and block['state'] == 'unblocked'))
                        state, detail = self.waf.add(row['ip'],f'{self.domain} 无业务网站访问规则；已收集 {row["count"]} 次访问',still_allowed,origin='SiteVisit')
                    attempts, retry_at = 0, 0
                    completed += 1
                except Exception as exc:
                    if not self.active():
                        break
                    state = 'protected' if isinstance(exc,SecurityError) and '白名单' in str(exc) else 'failed'
                    detail = str(exc) if isinstance(exc,SecurityError) or type(exc).__name__ == 'PanelError' else '加入失败，下一轮自动重试。'
                    attempts = row['attempts'] + 1
                    retry_at = time.time() + min(900,INTERVAL * 2**min(attempts-1,4)) if state == 'failed' else 0
                with self.store.lock, self.store.db:
                    self.store.db.execute('''UPDATE site_visit_ips SET state=?,detail=?,attempts=?,retry_at=?,updated=? WHERE source=? AND ip=?''',
                                          (state,detail,attempts,retry_at,time.time(),self.source,row['ip']))
            return completed
        except Exception as exc:
            message = str(exc) if isinstance(exc,(ValueError,SecurityError)) or type(exc).__name__ == 'PanelError' else '规则统计失败，下一分钟重试。'
            with self.store.lock, self.store.db:
                self.store.db.execute('UPDATE site_visit_rule SET checked=?,next_check=?,last_error=? WHERE id=1', (now,now+INTERVAL,message))
            return 0

    def public(self):
        with self.store.lock:
            config = self.config()
            counts = dict(self.store.db.execute('SELECT state,COUNT(*) FROM site_visit_ips WHERE source=? GROUP BY state',(self.source,)).fetchall())
            rows = [dict(row) for row in self.store.db.execute('SELECT ip,count,last_seen,state,detail,retry_at,updated FROM site_visit_ips WHERE source=? ORDER BY updated DESC LIMIT 50',(self.source,))]
            return {'domain':self.domain,'website':config['website'],'enabled':bool(config['enabled'] and config['source']==self.source),
                    'interval':INTERVAL,'busy':self.busy,'checkedAt':config['checked'],'nextCheckAt':config['next_check'],
                    'lastRows':config['last_rows'],'lastIps':config['last_ips'],'unparsed':config['unparsed'],
                    'lastError':config['last_error'],'totalIps':sum(counts.values()),
                    'listed':sum(counts.get(s,0) for s in ('listed','existing','inactive')),
                    'pending':sum(counts.get(s,0) for s in ('pending','failed')),
                    'protected':counts.get('protected',0),'results':rows}

    def run(self):
        while not self.stop_event.is_set():
            config = self.config()
            wait = max(0,min(INTERVAL,(config['next_check'] or time.time()+INTERVAL)-time.time())) if self.active() else INTERVAL
            if self.wake_event.wait(wait):
                self.wake_event.clear()
                continue
            if self.active():
                self.busy = True
                try:
                    self.process_once()
                finally:
                    self.busy = False

    def start(self):
        self.thread = threading.Thread(target=self.run,daemon=True,name='site-visit-rule')
        self.thread.start()

    def stop(self):
        self.stop_event.set(); self.wake_event.set()
