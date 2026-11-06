"""Windows text log shipper for Nginx and Tomcat; buildable as LogAgent.exe."""
import argparse
import base64
import codecs
from contextlib import closing
from datetime import date, datetime, timedelta
import glob
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import platform
import shutil
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from urllib import error, parse, request
import uuid
import xml.etree.ElementTree as ET

try:
    from log_cleaner import DailyCleaner, candidate_files, clean_options, compile_rules, day_files
except ImportError:  # imported as agent.agent by the platform tests
    from agent.log_cleaner import DailyCleaner, candidate_files, clean_options, compile_rules, day_files


CHUNK = 256 * 1024
MAX_LINE = 64 * 1024
DISPLAY_LINE = 8192
VERSION = '1.1.2'
# A day that could not be cleaned yet (file not rotated, queue full) is retried this often.
DAILY_RETRY = 300


def load_config(path):
    data = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    uuid.UUID(data['agentId'])
    url = parse.urlsplit(data['platformUrl'])
    if (url.scheme not in ('http', 'https') or not url.hostname or url.username or
            url.password or url.query or url.fragment or not 20 <= len(data['token']) <= 200):
        raise ValueError('Invalid platform address or agent credentials')
    if not isinstance(data.get('sources'), list) or not 1 <= len(data['sources']) <= 20:
        raise ValueError('Configure at least one log file')
    data.setdefault('interval', 3)
    data.setdefault('initialLines', 200)
    data.setdefault('maxQueueMB', 256)
    if not 1 <= data['interval'] <= 60 or data['initialLines'] not in (0, 200, 500) or not 8 <= data['maxQueueMB'] <= 4096:
        raise ValueError('Invalid interval, initialLines or maxQueueMB')
    for source in data['sources']:
        if not source.get('path') or source.get('kind') not in ('access.log', 'error.log', 'custom.log'):
            raise ValueError('Invalid log path or kind')
        encoding = codecs.lookup(source.setdefault('encoding', 'utf-8')).name
        if encoding not in ('utf-8', 'utf-8-sig', 'gbk', 'gb18030', 'cp1252'):
            raise ValueError('Log encoding must be UTF-8, GBK, GB18030 or CP1252')
        if source.setdefault('mode', 'tail') not in ('tail', 'daily'):
            raise ValueError('Log mode must be tail or daily')
        if source['mode'] == 'daily':
            daily_options(source)
    return data


def daily_options(source):
    """Validate a date-1 source: access_{date}.log is cleaned once that day is over."""
    source.setdefault('daysAgo', 1)
    source.setdefault('dateFormat', '%Y-%m-%d')
    source.setdefault('runAfter', '00:30')
    source.setdefault('neighbors', 1)
    source.setdefault('dropPaths', [])
    if source['kind'] != 'access.log' or '{date}' not in source['path'] or any(c in source['path'] for c in '*?['):
        raise ValueError('Daily mode needs an access log path containing {date} and no wildcard')
    if type(source['daysAgo']) is not int or not 1 <= source['daysAgo'] <= 30:
        raise ValueError('daysAgo must be 1-30')
    if type(source['neighbors']) is not int or not 0 <= source['neighbors'] <= 2:
        raise ValueError('neighbors must be 0-2')
    if not isinstance(source['dateFormat'], str) or '%' not in source['dateFormat'] or any(c in source['dateFormat'] for c in '/\\'):
        raise ValueError('Invalid dateFormat')
    datetime.strptime(source['runAfter'], '%H:%M')
    if not isinstance(source['dropPaths'], list) or len(source['dropPaths']) > 50:
        raise ValueError('dropPaths must be a list of regular expressions')
    for pattern in source['dropPaths']:
        re.compile(pattern)


class QueueFull(Exception):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise error.HTTPError(req.full_url, code, 'Agent redirects are disabled', headers, fp)


class Agent:
    def __init__(self, config, state_dir):
        self.config = config
        self.directory = Path(state_dir)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.directory / 'agent.sqlite3')
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS cursors (source TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS source_patterns (source TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS daily_jobs (
                source TEXT NOT NULL,day TEXT NOT NULL,finished REAL NOT NULL,report TEXT NOT NULL,
                PRIMARY KEY(source,day));
            CREATE TABLE IF NOT EXISTS outbox (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,
                kind TEXT NOT NULL,source TEXT NOT NULL,raw TEXT NOT NULL,
                collected REAL NOT NULL,bytes INTEGER NOT NULL);
        ''')
        self.last_error = ''
        self.statuses = []
        self.failures = 0
        self.next_send = 0
        self.daily_retry = {}
        self.day_override = None
        # Cleaning a day reads hundreds of MB; it runs beside the upload / heartbeat loop.
        self.clean_in_background = True
        self.cleaning = {}

    @staticmethod
    def identity(path):
        info = path.stat()
        return f'{info.st_dev}:{info.st_ino}'

    def cursor(self, key):
        row = self.db.execute('SELECT value FROM cursors WHERE source=?', (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def queue_depth(self):
        return self.db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0]

    def commit(self, key, cursor, source, kind, lines):
        # The outbox and source position advance in the same durable transaction.
        self.enqueue([(kind, line) for line in lines], source, lambda: self.db.execute(
            'INSERT OR REPLACE INTO cursors VALUES(?,?)', (key, json.dumps(cursor))))

    def enqueue(self, events, source, finish, ids=None):
        ids = ids or [uuid.uuid4().hex for _ in events]
        rows = [(event_id, kind, str(source), line, time.time(), len(line.encode('utf-8')) + 256)
                for event_id, (kind, line) in zip(ids, events)]
        used = self.db.execute('SELECT COALESCE(SUM(bytes),0) FROM outbox').fetchone()[0]
        if used + sum(row[-1] for row in rows) > self.config['maxQueueMB'] * 1024 * 1024:
            raise QueueFull('Offline queue is full; collection will resume after upload')
        with self.db:
            self.db.executemany('INSERT INTO outbox(event_id,kind,source,raw,collected,bytes) VALUES(?,?,?,?,?,?)', rows)
            finish()

    @staticmethod
    def fresh(path):
        return {'identity': Agent.identity(path), 'position': 0, 'partial': '', 'anchor': '',
                'skipPartial': False, 'discarding': False}

    def decode_line(self, line, encoding, truncated=False):
        cut = truncated or len(line) > DISPLAY_LINE
        text = line[:DISPLAY_LINE].rstrip(b'\r').decode(encoding, errors='replace')
        return text + ' [line truncated]' if cut else text

    def read_chunk(self, key, path, source, cursor):
        info = path.stat()
        position = cursor['position']
        anchor = bytes.fromhex(cursor.get('anchor', ''))
        with path.open('rb') as stream:
            if position > info.st_size:
                cursor = self.fresh(path); position = 0; anchor = b''
            if anchor:
                stream.seek(position - len(anchor))
                if stream.read(len(anchor)) != anchor:
                    cursor = self.fresh(path); position = 0
            stream.seek(position)
            chunk = stream.read(CHUNK)
            lines = []
            partial = base64.b64decode(cursor['partial'])
            if cursor['skipPartial']:
                newline = chunk.find(b'\n')
                chunk = chunk[newline + 1:] if newline >= 0 else b''
                cursor['skipPartial'] = newline < 0
            elif cursor.get('discarding'):
                newline = chunk.find(b'\n')
                if newline >= 0:
                    lines.append(self.decode_line(partial, source['encoding'], True))
                    partial = b''; cursor['discarding'] = False
                    chunk = chunk[newline + 1:]
                else:
                    chunk = b''
            if not cursor['discarding'] and not cursor['skipPartial']:
                parts = (partial + chunk).split(b'\n')
                partial = parts.pop()
                lines.extend(self.decode_line(line, source['encoding']) for line in parts)
                if len(partial) > MAX_LINE:
                    partial = partial[:DISPLAY_LINE]; cursor['discarding'] = True
            position = stream.tell()
            stream.seek(max(0, position - 64))
            cursor['anchor'] = stream.read(min(64, position)).hex()
        cursor['position'] = position
        cursor['partial'] = base64.b64encode(partial).decode('ascii')
        self.commit(key, cursor, path, source['kind'], lines)
        return cursor, position < info.st_size

    @staticmethod
    def file_key(path, source):
        return source['kind'] + '|' + os.path.normcase(str(path.resolve()))

    def collect_file(self, path, source, from_start=False):
        key = self.file_key(path, source)
        cursor = self.cursor(key)
        identity = self.identity(path)
        if cursor is None:
            # A wildcard may discover the renamed file before the replacement.
            # Reuse its durable position instead of reading its initial tail twice.
            for row in self.db.execute('SELECT source,value FROM cursors WHERE source LIKE ?', (source['kind'] + '|%',)):
                known = json.loads(row['value'])
                if known['identity'] == identity:
                    cursor = known
                    break
        if cursor is None and from_start:
            cursor = self.fresh(path)
        if cursor is None:
            cursor = self.fresh(path)
            size = path.stat().st_size
            with path.open('rb') as stream:
                if self.config['initialLines']:
                    start = max(0, size - CHUNK)
                    stream.seek(start)
                    data = stream.read(CHUNK)
                    if start:
                        data = data.split(b'\n', 1)[1] if b'\n' in data else b''
                    parts = data.split(b'\n')
                    partial = parts.pop()
                    lines = [self.decode_line(line, source['encoding']) for line in parts[-self.config['initialLines']:]]
                    cursor['partial'] = base64.b64encode(partial[:MAX_LINE]).decode('ascii')
                    cursor['discarding'] = len(partial) > MAX_LINE
                else:
                    lines = []
                    if size:
                        stream.seek(size - 1)
                        cursor['skipPartial'] = stream.read(1) != b'\n'
                cursor['position'] = size
                stream.seek(max(0, size - 64))
                cursor['anchor'] = stream.read(min(size, 64)).hex()
            self.commit(key, cursor, path, source['kind'], lines)
            return
        if cursor['identity'] != identity:
            # Drain a renamed file before switching to its replacement.
            for old in list(path.parent.glob(path.stem + '*'))[:100]:
                if old.is_file() and self.identity(old) == cursor['identity']:
                    old_key = source['kind'] + '|' + os.path.normcase(str(old.resolve()))
                    known = self.cursor(old_key)
                    if known and known['identity'] == cursor['identity'] and known['position'] > cursor['position']:
                        cursor = known
                    for _ in range(4):
                        cursor, more = self.read_chunk(key, old, source, cursor)
                        if not more:
                            break
                    if more:
                        return
                    self.commit(old_key, cursor, old, source['kind'], [])
                    break
            cursor = self.fresh(path)
        for _ in range(4):
            cursor, more = self.read_chunk(key, path, source, cursor)
            if not more:
                break

    @staticmethod
    def matching_files(pattern):
        matches = []
        for value in glob.iglob(pattern, recursive=True):
            path = Path(value)
            try:
                if path.is_file():
                    matches.append((path.stat().st_mtime_ns, str(path)))
            except OSError:
                continue
        # Daily logs must stay visible when a directory holds months of history.
        return [Path(value) for _, value in sorted(matches, reverse=True)[:100]]

    def clean_settings(self):
        """Cleaning rules from the platform; the last good copy is used while it is unreachable."""
        req = request.Request(self.config['platformUrl'].rstrip('/') + '/v1/clean-rules',
                              headers={'X-Agent-ID': self.config['agentId'], 'Authorization': 'Bearer ' + self.config['token'],
                                       'User-Agent': 'LogAgent/' + VERSION})
        try:
            with request.build_opener(NoRedirect()).open(req, timeout=10) as response:
                data = json.loads(response.read(1024 * 1024 + 1))
            data = {'version': str(data['version'])[:64], 'rules': data['rules'], 'options': data['options']}
            compile_rules(data['rules']), clean_options(data['options'])
            with self.db:
                self.db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)', ('cleanRules', json.dumps(data)))
            return {**data, 'source': 'platform'}
        except Exception:
            row = self.db.execute("SELECT value FROM settings WHERE name='cleanRules'").fetchone()
            if row:
                logging.warning('Cleaning rules unavailable from the platform; using the last downloaded copy')
                return {**json.loads(row[0]), 'source': 'cached'}
            logging.warning('Cleaning rules unavailable from the platform; using built-in cleaning only')
            return {'version': '', 'rules': [], 'options': {}, 'source': 'default'}

    def collect_daily(self, source, now=None):
        """Clean the whole day N days ago once, then queue its aggregated rows and report."""
        now = now or datetime.now()
        day = self.day_override or now.date() - timedelta(days=source['daysAgo'])
        template = os.path.expandvars(source['path'])
        key = 'daily|' + os.path.normcase(os.path.abspath(template))
        primary = Path(candidate_files(template, day, source['dateFormat'], 0)[0])
        status = {'path': str(primary), 'kind': source['kind'], 'mode': 'daily', 'day': day.isoformat()}
        done = self.db.execute('SELECT report FROM daily_jobs WHERE source=? AND day=?', (key, day.isoformat())).fetchone()
        if done:
            report = json.loads(done[0])
            return {**status, 'status': 'ok', 'rows': report['rowsEmitted'], 'aiRows': report['aiRows']}
        if not self.day_override and now.strftime('%H:%M') < source['runAfter'] or time.monotonic() < self.daily_retry.get(key, 0):
            return {**status, 'status': 'waiting'}
        job = self.cleaning.get(key)
        if job and job['day'] != day:
            job = None  # A finished-late job for an older day is superseded; its thread just ends.
        if job is None:
            paths = [Path(p) for p in day_files(template, day)]
            if not paths:
                self.daily_retry[key] = time.monotonic() + DAILY_RETRY
                return {**status, 'status': 'missing'}
            job = self.start_cleaning(key, source, day, primary, paths)
            if not self.clean_in_background:
                job['thread'].join()
        if job['thread'].is_alive():
            percent = min(99, job['cleaner'].bytes_read * 100 // max(1, job['size']))
            if time.monotonic() - job['logged'] >= 30:
                job['logged'] = time.monotonic()
                logging.info('Cleaning %s for %s: %s%% of %.0f MB read', primary.name, day, percent, job['size'] / 1048576)
            return {**status, 'status': 'cleaning', 'percent': percent}
        del self.cleaning[key]
        if job['error']:
            logging.error('Cleaning %s for %s failed: %s; retrying in %s s', primary.name, day, job['error'], DAILY_RETRY)
            self.daily_retry[key] = time.monotonic() + DAILY_RETRY
            return {**status, 'status': 'error'}
        rows, report = job['rows'], job['report']
        logging.info('Cleaned %s in %.0f s: %s lines of that day, %s rows queued, %s for AI; per file %s',
                     day, job['seconds'], report['targetDay'], len(rows), report['aiRows'],
                     ', '.join(f"{Path(f['path']).name}={f['targetDay']}" for f in report['files']))
        events = [(source['kind'], row) for row in rows]
        events.append(('custom.log', json.dumps(report, ensure_ascii=False, separators=(',', ':'))))
        try:
            self.enqueue(events, primary, lambda: self.db.execute(
                'INSERT INTO daily_jobs VALUES(?,?,?,?)', (key, day.isoformat(), time.time(), json.dumps(report))),
                ids=self.daily_ids(key, day, events))
        except QueueFull:
            self.daily_retry[key] = time.monotonic() + DAILY_RETRY
            raise
        return {**status, 'status': 'ok', 'rows': len(rows), 'aiRows': report['aiRows']}

    def start_cleaning(self, key, source, day, primary, paths):
        rules = self.clean_settings()  # Uses this thread's database connection; the worker never does.
        options = clean_options(rules['options'])
        cleaner = DailyCleaner(day, source['encoding'], drop_static=options['dropStatic'], drop_paths=source['dropPaths'],
                               widespread_ips=options['widespreadIps'], context_rows=options['contextRows'],
                               rules=compile_rules(rules['rules']), drop_preflight=options['dropPreflight'])
        job = {'day': day, 'cleaner': cleaner, 'size': sum(p.stat().st_size for p in paths), 'logged': time.monotonic(),
               'rows': None, 'report': None, 'error': '', 'seconds': 0}

        def work():
            began = time.monotonic()
            try:
                for path in paths:
                    cleaner.feed(path)
                job['rows'] = cleaner.rows()
                job['report'] = {**cleaner.report(len(job['rows'])), 'rulesVersion': rules['version'], 'rulesSource': rules['source']}
            except Exception as exc:
                job['error'] = f'{type(exc).__name__}: {exc}'[:300]
            job['seconds'] = time.monotonic() - began

        logging.info('Cleaning %s started: %s (%.0f MB in total)', day, ', '.join(p.name for p in paths), job['size'] / 1048576)
        job['thread'] = threading.Thread(target=work, daemon=True, name='daily-clean')
        self.cleaning[key] = job
        job['thread'].start()
        return job

    def daily_ids(self, key, day, events):
        """Content-derived IDs: cleaning the same day again re-sends nothing the platform already has."""
        ids, seen = [], {}
        for kind, line in events:
            basis = 'report' if kind == 'custom.log' else line
            text = f"{self.config['agentId']}|{key}|{day.isoformat()}|{basis}"
            seen[text] = seen.get(text, 0) + 1
            ids.append(hashlib.sha256(f'{text}|{seen[text]}'.encode('utf-8')).hexdigest()[:32])
        return ids

    def collect(self):
        self.statuses = []
        collection_error = ''
        for source in self.config['sources']:
            if source.get('mode') == 'daily':
                try:
                    self.statuses.append(self.collect_daily(source))
                except QueueFull as exc:
                    collection_error = str(exc)
                    self.statuses.append({'path': source['path'], 'kind': source['kind'], 'mode': 'daily', 'status': 'error'})
                except OSError:
                    collection_error = 'Cannot read a configured log file; check path and permissions'
                    self.statuses.append({'path': source['path'], 'kind': source['kind'], 'mode': 'daily', 'status': 'error'})
                continue
            pattern = os.path.expandvars(source['path'])
            paths = self.matching_files(pattern)
            pattern_key = source['kind'] + '|' + os.path.normcase(os.path.abspath(pattern))
            initialized = self.db.execute('SELECT 1 FROM source_patterns WHERE source=?', (pattern_key,)).fetchone()
            # Existing cursors also identify upgraded collectors that predate this table.
            initialized = bool(initialized or any(self.cursor(self.file_key(path, source)) for path in paths))
            if not paths:
                self.statuses.append({'path': pattern, 'kind': source['kind'], 'status': 'missing'})
            for path in paths:
                if not path.is_file():
                    continue
                try:
                    self.collect_file(path, source, from_start=initialized)
                    self.statuses.append({'path': str(path), 'kind': source['kind'], 'status': 'ok'})
                except QueueFull as exc:
                    collection_error = str(exc)
                    self.last_error = collection_error
                    return
                except OSError:
                    collection_error = 'Cannot read a configured log file; check path and permissions'
                    self.statuses.append({'path': str(path), 'kind': source['kind'], 'status': 'error'})
            with self.db:
                self.db.execute('INSERT OR IGNORE INTO source_patterns(source) VALUES(?)', (pattern_key,))
        self.last_error = collection_error

    def pending(self):
        rows = []
        size = 0
        for row in self.db.execute('SELECT * FROM outbox ORDER BY seq LIMIT 500'):
            event = {'eventId': row['event_id'], 'kind': row['kind'], 'source': row['source'],
                     'raw': row['raw'], 'collectedAt': row['collected']}
            size += len(json.dumps(event, ensure_ascii=False).encode('utf-8'))
            if size > 512 * 1024:
                break
            rows.append((row['seq'], event))
        return rows

    def send(self):
        rows = self.pending()
        payload = {'events': [event for _, event in rows],
                   'metadata': {'hostname': socket.gethostname(), 'version': VERSION + ' / ' + platform.system(),
                                'queueDepth': max(0, self.queue_depth() - len(rows)), 'lastError': self.last_error,
                                'sources': self.statuses[:20]}}
        data = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode('utf-8')
        req = request.Request(self.config['platformUrl'].rstrip('/') + '/v1/ingest', data=data,
                              headers={'Content-Type': 'application/json', 'X-Agent-ID': self.config['agentId'],
                                       'Authorization': 'Bearer ' + self.config['token'], 'User-Agent': 'LogAgent/' + VERSION})

        with request.build_opener(NoRedirect()).open(req, timeout=12) as response:
            result = json.loads(response.read(65537))
        if type(result.get('accepted')) is not int or result['accepted'] != len(rows):
            raise ValueError('Platform did not confirm the batch; it remains queued')
        with self.db:
            self.db.executemany('DELETE FROM outbox WHERE seq=?', [(seq,) for seq, _ in rows])
        return len(rows)

    def tick(self):
        self.collect()
        if time.monotonic() < self.next_send:
            return
        self.upload()

    def upload(self, rounds=4):
        try:
            for _ in range(rounds):
                self.send()
                if not self.queue_depth():
                    break
            self.failures = 0
            self.next_send = 0
        except Exception as exc:
            self.failures += 1
            self.next_send = time.monotonic() + min(60, 3 * 2 ** min(self.failures, 5))
            code = f' (HTTP {exc.code})' if isinstance(exc, error.HTTPError) else ''
            self.last_error = 'Upload failed' + code + '; logs remain in the offline queue'
            logging.warning(self.last_error)

    def close(self):
        self.db.close()


def install_task(config_path, remove=False):
    if os.name != 'nt' or not getattr(sys, 'frozen', False):
        raise ValueError('Install using the Windows executable')
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print('Run install.cmd or uninstall.cmd as administrator.')
        return 1
    task_name = 'OnePanelLogAgent'
    if remove:
        subprocess.run(['schtasks', '/end', '/tn', task_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['schtasks', '/delete', '/tn', task_name, '/f'], check=False)
        print('Startup task removed. Configuration and offline queue are preserved.')
        return 0
    incoming = load_config(config_path)
    program_data = Path(os.environ.get('ProgramData', r'C:\ProgramData')).resolve()
    destination = (program_data / 'OnePanelLogAgent').resolve()
    if destination.parent != program_data:
        raise ValueError('Invalid installation directory')
    destination.mkdir(parents=True, exist_ok=True)
    exe, config = destination / 'LogAgent.exe', destination / 'config.json'
    if config.is_file() and load_config(config)['agentId'] != incoming['agentId']:
        raise ValueError('Another agent is already installed. Use its existing configuration to preserve its queue.')
    # A foreground collector must stop before its durable state is relocated.
    source_state = config_path.parent / 'runtime'
    target_state = destination / 'runtime'
    state_lock = None
    try:
        if source_state.exists() and source_state.resolve() != target_state.resolve():
            import msvcrt
            state_lock = (source_state / 'agent.lock').open('a+b')
            state_lock.write(b'1'); state_lock.flush(); state_lock.seek(0)
            try:
                msvcrt.locking(state_lock.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise ValueError('Stop run.cmd before installing the startup task.') from None
        subprocess.run(['schtasks', '/end', '/tn', task_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        transfer_state(source_state, target_state)
    finally:
        if state_lock:
            state_lock.close()
    for source, target in ((Path(sys.executable), exe), (config_path, config)):
        if source.resolve() != target.resolve():
            for attempt in range(10):
                try:
                    shutil.copy2(source, target)
                    break
                except PermissionError:
                    if attempt == 9:
                        raise
                    time.sleep(.5)
    subprocess.run(['icacls', str(destination), '/inheritance:r', '/grant:r',
                    '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'], check=True, stdout=subprocess.DEVNULL)
    ET.register_namespace('', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    namespace = '{http://schemas.microsoft.com/windows/2004/02/mit/task}'
    task = ET.Element(namespace + 'Task', {'version': '1.2'})
    def node(parent, name, text=None, **attributes):
        result = ET.SubElement(parent, namespace + name, attributes)
        if text is not None:
            result.text = text
        return result
    trigger = node(node(task, 'Triggers'), 'BootTrigger'); node(trigger, 'Enabled', 'true')
    principal = node(node(task, 'Principals'), 'Principal', id='Agent')
    node(principal, 'UserId', 'S-1-5-18'); node(principal, 'RunLevel', 'HighestAvailable')
    settings_node = node(task, 'Settings')
    for name, value in [('MultipleInstancesPolicy','IgnoreNew'), ('DisallowStartIfOnBatteries','false'),
                        ('StopIfGoingOnBatteries','false'), ('StartWhenAvailable','true'),
                        ('ExecutionTimeLimit','PT0S'), ('Enabled','true')]:
        node(settings_node, name, value)
    retry = node(settings_node, 'RestartOnFailure'); node(retry, 'Interval', 'PT1M'); node(retry, 'Count', '999')
    action = node(node(task, 'Actions', Context='Agent'), 'Exec')
    node(action, 'Command', str(exe))
    node(action, 'Arguments', subprocess.list2cmdline(['--config', str(config)]))
    node(action, 'WorkingDirectory', str(destination))
    with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as temporary:
        task_path = Path(temporary.name)
        temporary.write(ET.tostring(task, encoding='utf-16', xml_declaration=True))
    try:
        subprocess.run(['schtasks', '/create', '/tn', task_name, '/xml', str(task_path), '/f'], check=True)
        subprocess.run(['schtasks', '/run', '/tn', task_name], check=True)
    finally:
        task_path.unlink(missing_ok=True)
    print('Installed and started. Configuration:', config)
    return 0


def transfer_state(source, destination):
    """Preserve the first portable run's cursor and unacknowledged rows on install."""
    original = source / 'agent.sqlite3'
    target = destination / 'agent.sqlite3'
    if not original.is_file() or original.resolve() == target.resolve():
        return
    with closing(sqlite3.connect(original)) as old:
        if target.is_file():
            if old.execute('SELECT COUNT(*) FROM outbox').fetchone()[0]:
                raise ValueError('An installed queue exists. Upload the portable queue before updating the task.')
            return
        destination.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(target)) as new:
            old.backup(new)


def main():
    parser = argparse.ArgumentParser(description='Windows Nginx / Tomcat log collector')
    parser.add_argument('--config', default='config.json')
    parser.add_argument('--once', action='store_true', help='Collect and upload once')
    parser.add_argument('--day', type=date.fromisoformat, help='Daily sources: clean this day (YYYY-MM-DD) now, then exit')
    parser.add_argument('--install', action='store_true', help='Install a startup task; administrator required')
    parser.add_argument('--uninstall', action='store_true', help='Remove the startup task; preserve queue')
    args = parser.parse_args()
    config_path = Path(args.config).resolve()
    if args.install or args.uninstall:
        try:
            return install_task(config_path, args.uninstall)
        except Exception as exc:
            print(str(exc) if type(exc) is ValueError else 'Task installation failed. Check administrator rights, package files and task permissions.')
            return 1
    state_dir = config_path.parent / 'runtime'
    state_dir.mkdir(parents=True, exist_ok=True)
    lock = None
    agent = None
    try:
        if os.name == 'nt':
            import msvcrt
            lock = (state_dir / 'agent.lock').open('a+b')
            lock.write(b'1'); lock.flush(); lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s',
                            handlers=[RotatingFileHandler(state_dir / 'agent.log', maxBytes=1024*1024, backupCount=3, encoding='utf-8'),
                                      logging.StreamHandler()])
        agent = Agent(load_config(config_path), state_dir)
        agent.day_override = args.day
        agent.clean_in_background = not args.day  # A manual day run waits for its result.
        args.once = args.once or bool(args.day)
        logging.info('Nginx collector started; configuration: %s', config_path.name)
        while True:
            agent.tick()
            if args.day and not agent.failures:
                agent.upload(rounds=1000000)  # A manual day run drains its whole queue before exiting.
            if args.once:
                return 1 if agent.failures else 0
            time.sleep(agent.config['interval'])
    except KeyboardInterrupt:
        return 0
    except Exception:
        print('Collector could not start. Check config.json and whether another instance is running.')
        return 1
    finally:
        if agent:
            agent.close()
        if lock:
            lock.close()


if __name__ == '__main__':
    raise SystemExit(main())
