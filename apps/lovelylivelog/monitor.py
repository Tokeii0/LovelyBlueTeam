"""Read appended bytes only; preserve partial lines and detect replaced files."""
from concurrent.futures import ThreadPoolExecutor
import threading
import time

MAX_CHUNK = 1024 * 1024
MAX_PARTIAL = 2 * 1024 * 1024


class Monitor:
    def __init__(self, client, store, interval=3):
        self.client, self.store, self.interval = client, store, interval
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.sources = {}
        self.last_error = ''
        self.thread = None

    def collect(self, website, kind):
        meta = self.client.metadata(website['id'])
        field = 'accessLog' if kind == 'access.log' else 'errorLog'
        path = meta.get(field + 'Path')
        if not meta.get(field):
            return {'enabled': False, 'newCount': 0, 'checkedAt': time.time()}
        if not isinstance(path, str) or not path.startswith('/') or not path.endswith('/' + kind):
            raise ValueError("面板未返回有效的网站日志路径。")
        source = f"{self.client.config['url']}|{self.client.config['prefix']}|{website['id']}|{kind}|{path}"
        cursor = self.store.cursor(source)
        if cursor is None:
            raw, _, size = self.client.read_range(path, 65536, None)
            cursor = {'offset': size, 'anchor': raw[-64:].hex(), 'partial': raw.rsplit(b'\n', 1)[-1].hex(), 'generation': 0}
            self.store.append(source, cursor, website['id'], kind, [])
            return {'enabled': True, 'path': path, 'newCount': 0, 'baseline': True, 'checkedAt': time.time()}
        count, rotated, backlog = 0, False, False
        # Bounded catch-up per tick; the persisted cursor keeps the unread remainder.
        for _ in range(4):
            anchor = bytes.fromhex(cursor['anchor'])
            start = max(0, cursor['offset'] - len(anchor))
            raw, actual_start, size = self.client.read_segment(path, start, MAX_CHUNK)
            if size < cursor['offset'] or actual_start != start or raw[:len(anchor)] != anchor:
                rotated = True
                cursor = {'offset': 0, 'anchor': '', 'partial': '', 'generation': cursor['generation'] + 1}
                raw, actual_start, size = self.client.read_segment(path, 0, MAX_CHUNK)
                anchor = b''
            new_bytes = raw[len(anchor):]
            joined = bytes.fromhex(cursor['partial']) + new_bytes
            parts = joined.split(b'\n')
            partial = parts.pop()
            if len(partial) > MAX_PARTIAL:
                raise ValueError("单条日志超过 2 MB，增量读取已暂停；请在 1Panel 中处理异常日志行。")
            lines = [part.rstrip(b'\r').decode('utf-8', errors='replace') for part in parts]
            cursor.update(offset=actual_start + len(raw), anchor=raw[-64:].hex(), partial=partial.hex())
            self.store.append(source, cursor, website['id'], kind, lines)
            count += len(lines)
            backlog = cursor['offset'] < size
            if not backlog or not new_bytes:
                break
        return {'enabled': True, 'path': path, 'newCount': count, 'rotated': rotated, 'backlog': backlog, 'checkedAt': time.time()}

    def _collect_safe(self, item):
        website, kind = item
        try:
            status = self.collect(website, kind)
        except Exception as exc:
            from server import PanelError
            message = str(exc) if isinstance(exc, (PanelError, ValueError)) else '读取失败，下一轮重试。'
            status = {'error': message, 'checkedAt': time.time()}
        with self.lock:
            self.sources[f"{website['id']}:{kind}"] = status

    def status(self, website=None, kind=None):
        with self.lock:
            if website is not None:
                return dict(self.sources.get(f'{website}:{kind}', {'waiting': True}))
            return {'sources': dict(self.sources), 'error': self.last_error, 'running': bool(self.thread and self.thread.is_alive())}

    def run(self):
        websites, refresh_at = [], 0
        pool = ThreadPoolExecutor(max_workers=3)
        try:
            while not self.stop_event.is_set():
                try:
                    if time.monotonic() >= refresh_at:
                        websites = self.client.websites()
                        refresh_at = time.monotonic() + 60
                    list(pool.map(self._collect_safe, [(w, k) for w in websites for k in ('access.log', 'error.log')]))
                    with self.lock:
                        self.last_error = ''
                except Exception as exc:
                    from server import PanelError
                    with self.lock:
                        self.last_error = str(exc) if isinstance(exc, PanelError) else '网站列表读取失败，将自动重试。'
                self.stop_event.wait(self.interval)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True, name='new-log-monitor')
        self.thread.start()

    def stop(self):
        self.stop_event.set()
