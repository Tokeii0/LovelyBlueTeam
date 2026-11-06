"""Local 1Panel v2 incremental logs and DeepSeek traffic defense."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import error, parse, request
import webbrowser

ROOT = Path(__file__).resolve().parent
INSTANCE_ID = hashlib.sha256(os.path.normcase(str(ROOT)).encode('utf-8')).hexdigest()
STATIC = ROOT / "static"
STATIC_TYPES = {"js": "text/javascript; charset=utf-8", "css": "text/css; charset=utf-8", "svg": "image/svg+xml"}
STATIC_ASSET = re.compile(r"/([a-z0-9][a-z0-9-]*\.(js|css|svg))")
MAX_RESPONSE = 8 * 1024 * 1024
LOG_WINDOWS = (200, 500, 1000, 2000, 5000)  # Lines per page of the website log viewer.


class PanelError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def load_config() -> dict:
    values = {}
    config_file = ROOT / ".env"
    if config_file.exists():
        for line in config_file.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip("\"'")
    for key in ("PANEL_URL", "PANEL_API_KEY", "PANEL_API_PREFIX", "PORT", "REQUEST_TIMEOUT",
                "AGENT_BIND", "AGENT_PORT", "AGENT_PUBLIC_URL"):
        if key in os.environ:
            values[key] = os.environ[key]
    if not values.get("PANEL_API_KEY") or values["PANEL_API_KEY"] == "replace_with_your_api_key":
        raise ValueError("请在 .env 文件中填写 PANEL_API_KEY。")
    url = values.get("PANEL_URL", "").rstrip("/")
    parts = parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.query or parts.fragment:
        raise ValueError("PANEL_URL 必须是有效的 http / https 面板地址。")
    prefix = values.get("PANEL_API_PREFIX", "/api/v2").rstrip("/")
    if prefix not in ("/api/v1", "/api/v2"):
        raise ValueError("PANEL_API_PREFIX 应为 /api/v1 或 /api/v2。")
    port = int(values.get("PORT", "8787"))
    timeout = float(values.get("REQUEST_TIMEOUT", "12"))
    agent_port = int(values.get('AGENT_PORT', '8788'))
    if not 1 <= port <= 65535 or not 1 <= timeout <= 60:
        raise ValueError("PORT 应为 1–65535，REQUEST_TIMEOUT 应为 1–60 秒。")
    if not 1 <= agent_port <= 65535:
        raise ValueError('AGENT_PORT 应为 1–65535。')
    return {"url": url, "key": values["PANEL_API_KEY"], "prefix": prefix, "port": port, "timeout": timeout,
            'agentBind': values.get('AGENT_BIND', '127.0.0.1'), 'agentPort': agent_port,
            'agentPublicUrl': values.get('AGENT_PUBLIC_URL', '')}


class PanelClient:
    def __init__(self, config: dict):
        self.config = config
        self._log_meta: dict[int, tuple[float, dict]] = {}
        self._lock = threading.Lock()

    def signed_headers(self) -> dict:
        timestamp = str(int(time.time()))
        token = hashlib.md5(("1panel" + self.config["key"] + timestamp).encode()).hexdigest()
        return {"1Panel-Token": token, "1Panel-Timestamp": timestamp}

    def call(self, path: str, body: dict | None = None):
        headers = {**self.signed_headers(), "Accept": "application/json"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        req = request.Request(self.config["url"] + self.config["prefix"] + path, data=data, headers=headers)
        try:
            with request.urlopen(req, timeout=self.config["timeout"]) as response:
                raw = response.read(MAX_RESPONSE + 1)
        except error.HTTPError as exc:
            if exc.code in (401, 403):
                raise PanelError("认证失败：请检查 API 密钥、API 是否启用、IP 白名单及两台机器的时间。", 502) from exc
            raise PanelError(f"1Panel 返回 HTTP {exc.code}，请检查面板地址和接口版本。") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise PanelError("读取超时，将自动重试。较大的日志文件可能需要更长时间。", 504) from exc
        except (error.URLError, OSError) as exc:
            raise PanelError("无法连接 1Panel，请检查网络、VPN 和面板地址。") from exc
        if len(raw) > MAX_RESPONSE:
            raise PanelError("日志响应超过 8 MB，请降低读取行数。")
        try:
            payload = json.loads(raw.decode("utf-8-sig"))
        except (ValueError, UnicodeError) as exc:
            raise PanelError("面板未返回 JSON，请检查面板地址、安全入口及接口权限。") from exc
        if not isinstance(payload, dict):
            raise PanelError("1Panel 返回了无法识别的响应。")
        if payload.get("code") != 200:
            # Upstream error text can contain paths, keys, or log contents. Do not forward it.
            code = payload.get("code")
            if code in (401, 403):
                raise PanelError("认证失败：请检查 API 密钥、API 是否启用、IP 白名单及两台机器的时间。")
            safe_code = str(code) if isinstance(code, int) else "未知"
            raise PanelError(f"1Panel 接口返回错误（代码 {safe_code}），请在面板中检查该网站的日志。")
        return payload.get("data")

    def websites(self) -> list[dict]:
        data = self.call("/websites/list")
        if data is None:
            return []
        if not isinstance(data, list):
            raise PanelError("网站列表格式与接口文档不一致。")
        result = []
        # WebsiteDTO also contains TLS private keys. Only return display fields.
        for website in data:
            result.append({
                "id": website["id"],
                "name": website.get("primaryDomain") or website.get("alias") or str(website["id"]),
                "alias": website.get("alias", ""),
                "remark": website.get("remark", ""),
                "status": website.get("status", ""),
                "accessLog": bool(website.get("accessLog")),
                "errorLog": bool(website.get("errorLog")),
            })
        return sorted(result, key=lambda website: website["name"].lower())

    def metadata(self, website_id: int) -> dict:
        with self._lock:
            cached = self._log_meta.get(website_id)
        if cached is None or time.monotonic() - cached[0] >= 30:
            data = self.call(f"/websites/{website_id}")
            if not isinstance(data, dict):
                raise PanelError("日志信息格式与接口文档不一致。")
            meta = {key: data.get(key) for key in ("accessLog", "errorLog", "accessLogPath", "errorLogPath")}
            with self._lock:
                self._log_meta[website_id] = (time.monotonic(), meta)
            return meta
        return cached[1]

    def read_range(self, path: str, window: int, before: int | None, range_header: str | None = None):
        headers = {**self.signed_headers(), "Accept-Encoding": "identity"}
        headers["Range"] = range_header or (f"bytes=-{window}" if before is None else f"bytes={max(0, before - window)}-{before - 1}")
        url = self.config["url"] + self.config["prefix"] + "/files/download?" + parse.urlencode({"path": path})
        req = request.Request(url, headers=headers)
        try:
            with request.urlopen(req, timeout=self.config["timeout"]) as response:
                if response.status == 206:
                    match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", response.headers.get("Content-Range", ""))
                    if not match:
                        raise PanelError("面板返回的日志分段信息不正确。")
                    start, end, size = map(int, match.groups())
                    if end < start or end - start + 1 > MAX_RESPONSE:
                        raise PanelError("日志分段大小异常。")
                    if before is not None and before > size:
                        raise PanelError("日志文件已轮转或缩小，请点击“回到实时”重新读取。", 409)
                    raw = response.read(end - start + 2)
                    if len(raw) != end - start + 1:
                        raise PanelError("日志分段读取不完整，请刷新重试。")
                    return raw, start, size
                # A server ignoring Range may safely return a small entire file.
                length = int(response.headers.get("Content-Length", "0"))
                if length > MAX_RESPONSE:
                    raise PanelError("面板未支持分段读取，请检查 1Panel 版本或反向代理的 Range 设置。")
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise PanelError("日志响应过大，面板未正确支持分段读取。")
                if any(value in response.headers.get("Content-Type", "") for value in ("application/json", "text/html")):
                    raise PanelError("日志文件读取失败，请在 1Panel 中检查该网站的日志和 API 权限。")
                size = len(raw)
                if before is not None:
                    if before > size:
                        raise PanelError("日志文件已轮转或缩小，请点击“回到实时”重新读取。", 409)
                    raw = raw[:before]
                return raw, 0, size
        except error.HTTPError as exc:
            if exc.code == 416 and exc.headers.get("Content-Range") == "bytes */0":
                if before is not None:
                    raise PanelError("日志文件已清空，请点击“回到实时”重新读取。", 409) from exc
                return b"", 0, 0
            if exc.code == 416:
                raise PanelError("日志文件已轮转或缩小，请点击“回到实时”重新读取。", 409) from exc
            if exc.code in (401, 403):
                raise PanelError("认证失败：请检查 API 密钥、API 是否启用及 IP 白名单。") from exc
            raise PanelError(f"读取日志文件失败（HTTP {exc.code}），请在 1Panel 中检查该网站的日志。") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise PanelError("读取超时，将自动重试。请检查面板连接。", 504) from exc
        except (error.URLError, OSError) as exc:
            raise PanelError("无法连接 1Panel，请检查网络、VPN 和面板地址。") from exc

    def read_segment(self, path: str, start: int, window: int):
        raw, actual_start, size = self.read_range(path, window, None, f"bytes={start}-{start + window - 1}")
        if actual_start == 0 and len(raw) == size:
            return raw[start:start + window], start, size
        return raw, actual_start, size

    def logs(self, website_id: int, kind: str, limit: int, before: int | None = None) -> dict:
        meta = self.metadata(website_id)
        log_key = "accessLog" if kind == "access.log" else "errorLog"
        path = meta.get(log_key + "Path") or ""
        result = {"enabled": bool(meta.get(log_key)), "path": path, "lines": [],
                  "before": 0, "hasOlder": False, "latest": before is None,
                  "fetchedAt": time.time(), "limit": limit, "fileSize": 0}
        if not result["enabled"]:
            return result
        if not isinstance(path, str) or not path.startswith("/") or not path.endswith("/" + kind):
            raise PanelError("面板未返回有效的网站日志路径，请检查接口版本。")
        window = 64 * 1024
        while True:
            raw, start, size = self.read_range(path, window, before)
            # Discard a partial leading line before decoding (including split UTF-8).
            if start > 0:
                boundary = raw.find(b"\n")
                discarded = boundary + 1 if boundary >= 0 else len(raw)
                start += discarded
                raw = raw[discarded:]
            lines = raw.splitlines(keepends=True)
            if len(lines) >= limit or start == 0:
                break
            if window >= MAX_RESPONSE:
                raise PanelError("单条日志过长，读取窗口超过 8 MB，请在 1Panel 中查看该文件。")
            window = min(MAX_RESPONSE, window * 2)
        skipped = max(0, len(lines) - limit)
        cursor = start + sum(map(len, lines[:skipped]))
        result["lines"] = [line.rstrip(b"\r\n").decode("utf-8", errors="replace") for line in lines[skipped:]]
        result["before"] = cursor
        result["hasOlder"] = cursor > 0
        result["fileSize"] = size
        result["fetchedAt"] = time.time()
        return result


class LogServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, client, store=None, monitor=None, ai=None, hub=None, rule=None, blacklist=None,
                 clean_rules=None, af=None, notifier=None, deep=None, geo=None, syslog=None):
        super().__init__(address, LogHandler)
        self.client = client
        self.store, self.monitor, self.ai = store, monitor, ai
        self.hub = hub
        self.rule = rule
        self.blacklist = blacklist
        self.clean_rules = clean_rules
        self.af = af
        self.notifier = notifier
        self.deep = deep
        self.geo = geo
        self.syslog = syslog


class LogHandler(BaseHTTPRequestHandler):
    server: LogServer

    def log_message(self, format, *args):
        # Access logs would contain website IDs and search parameters.
        pass

    def respond(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        try:
            self.end_headers()
            self.wfile.write(body)
        except ConnectionError:
            pass

    def send_json(self, status: int, data):
        self.respond(status, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def check_source(self):
        port = self.server.server_address[1]
        allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        host = self.headers.get("Host", "").lower()
        if host not in allowed_hosts:
            self.send_json(403, {"error": "仅支持通过本机地址访问。"})
            return False
        origin = self.headers.get("Origin")
        if self.headers.get("Sec-Fetch-Site") == "cross-site" or (origin and origin not in {f"http://{h}" for h in allowed_hosts}):
            self.send_json(403, {"error": "不允许跨站访问。"})
            return False
        return True

    def do_GET(self):
        if not self.check_source():
            return
        parsed = parse.urlsplit(self.path)
        path = parsed.path
        # Top-level static assets only: a plain file name with a known type, no subdirectories.
        asset = STATIC_ASSET.fullmatch(path)
        try:
            if path == "/":
                self.respond(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif asset and (STATIC / asset[1]).is_file():
                self.respond(200, (STATIC / asset[1]).read_bytes(), STATIC_TYPES[asset[2]])
            elif path == "/api/config":
                self.send_json(200, {"appId": "1panel-log-guard", "instanceId": INSTANCE_ID, "panelUrl": self.server.client.config["url"], "apiPrefix": self.server.client.config["prefix"], "defaultInterval": 3})
            elif path == "/api/websites":
                excluded = self.server.store.excluded_sites() if self.server.store else set()
                self.send_json(200, {"websites": [{**site, "aiExcluded": site["id"] in excluded}
                                                  for site in self.server.client.websites()]})
            elif path == "/api/events" and self.server.store:
                params = parse.parse_qs(parsed.query)
                website_id = int(params.get("id", [""])[0])
                kind = params.get("type", ["access.log"])[0]
                limit = int(params.get("limit", ["500"])[0])
                after = int(params['after'][0]) if 'after' in params else None
                if website_id <= 0 or kind not in ("access.log", "error.log") or limit not in LOG_WINDOWS or (after is not None and not 0 <= after <= 2**63 - 1):
                    raise ValueError()
                data = self.server.store.feed(website_id, kind, after, limit)
                status = self.server.monitor.status(website_id, kind) if self.server.monitor else {}
                global_error = self.server.monitor.status().get('error') if self.server.monitor else ''
                self.send_json(200, {**data, "status": status, "error": global_error,
                                     "fetchedAt": status.get('checkedAt', time.time())})
            elif path == "/api/ai" and self.server.ai:
                params = parse.parse_qs(parsed.query)
                page = int(params.get('page', ['1'])[0])
                page_size = int(params.get('pageSize', ['20'])[0])
                verdict = params.get('verdict', ['all'])[0]
                through = int(params['through'][0]) if 'through' in params else None
                source = params.get('source',['all'])[0]
                agent_id = params.get('agent',[''])[0]
                self.send_json(200, {**self.server.store.dashboard(page, page_size, verdict, through,source,agent_id),
                                     "settings": self.server.ai.public(agent_id) if source == 'agent' and agent_id else self.server.ai.public()})
            elif path == "/api/ai/waf" and self.server.ai:
                self.send_json(200, {"waf": self.server.ai.refresh_waf()})
            elif path == '/api/agents' and self.server.hub:
                self.send_json(200, self.server.hub.overview())
            elif path == '/api/site-rule' and self.server.rule:
                self.send_json(200, self.server.rule.public())
            elif path == '/api/clean-rules' and self.server.clean_rules:
                self.send_json(200, self.server.clean_rules.overview())
            elif path == '/api/af' and self.server.af:
                self.send_json(200, self.server.af.public())
            elif path == '/api/syslog/status' and self.server.syslog:
                self.send_json(200, self.server.syslog.public())
            elif path == '/api/blacklist/manual' and self.server.blacklist:
                self.send_json(200, self.server.blacklist.manual_list())
            elif path == '/api/af/log' and self.server.af:
                self.send_json(200, {'log': self.server.af.read_log()})
            elif path == '/api/notify' and self.server.notifier:
                self.send_json(200, self.server.notifier.public())
            elif path == '/api/deep' and self.server.deep:
                self.send_json(200, self.server.deep.sessions())
            elif path == '/api/deep/session' and self.server.deep:
                self.send_json(200, self.server.deep.session(int(parse.parse_qs(parsed.query).get('id', [''])[0])))
            elif path == '/api/notify/log' and self.server.notifier:
                self.send_json(200, {'log': self.server.notifier.read_log()})
            elif path=='/api/blacklist' and self.server.blacklist:
                format=parse.parse_qs(parsed.query).get('format',['json'])[0]
                if format not in ('json','text'): raise ValueError('导出格式不正确。')
                snapshot=self.server.blacklist.snapshot()
                if format=='text':
                    self.respond(200,self.server.blacklist.text(snapshot).encode('utf-8'),'text/plain; charset=utf-8')
                else:self.send_json(200,snapshot)
            elif path == '/api/agents/logs' and self.server.hub:
                params = parse.parse_qs(parsed.query)
                self.send_json(200, self.server.hub.feed(
                    params.get('agent', [''])[0], params.get('type', ['all'])[0],
                    params.get('q', [''])[0], int(params.get('page', ['1'])[0]),
                    int(params['through'][0]) if 'through' in params else None))
            elif path == "/api/logs":
                params = parse.parse_qs(parsed.query)
                website_id = int(params.get("id", [""])[0])
                kind = params.get("type", ["access.log"])[0]
                limit = int(params.get("limit", ["500"])[0])
                latest_value = params.get("latest", ["true"])[0]
                before = int(params.get("before", ["0"])[0]) if latest_value == "false" else None
                if website_id <= 0 or kind not in ("access.log", "error.log") or limit not in LOG_WINDOWS or latest_value not in ("true", "false") or (before is not None and not 1 <= before <= 2**63 - 1):
                    raise ValueError("日志参数不正确。")
                data = self.server.client.logs(website_id, kind, limit, before)
                if self.server.store:
                    data["total"] = self.server.store.stored_total(website_id, kind)
                self.send_json(200, data)
            else:
                self.send_json(404, {"error": "页面不存在。"})
        except (ValueError, IndexError):
            self.send_json(400, {"error": "分析历史参数不正确。" if path == '/api/ai' else "日志参数不正确。", **({'complete':False} if path=='/api/blacklist' else {})})
        except PanelError as exc:
            self.send_json(503 if path=='/api/blacklist' else exc.status, {"error": str(exc), **({'complete':False} if path=='/api/blacklist' else {})})
        except Exception:
            self.send_json(503 if path=='/api/blacklist' else 500, {"error": "读取失败，请检查面板和本机配置后重试。",'complete':False})

    def do_POST(self):
        if not self.check_source():
            return
        from security import SecurityError, save_settings
        path = parse.urlsplit(self.path).path
        try:
            if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
                raise ValueError('请求必须使用 JSON 格式。')
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 16384:
                raise ValueError('请求大小不正确。')
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError('请求格式不正确。')
            rules = self.server.clean_rules
            if path == '/api/shutdown':
                if body.get('instanceId') != INSTANCE_ID:
                    self.send_json(409, {"error": "运行实例与当前项目目录不一致，未停止。"})
                    return
                self.send_json(200, {"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True, name='shutdown').start()
            elif path.startswith('/api/clean-rules/') and rules:
                action = path.rsplit('/', 1)[1]
                if action == 'save':
                    self.send_json(200, rules.save(body))
                    if rules.blocker:
                        rules.blocker.wake_event.set()
                elif action == 'delete':
                    self.send_json(200, rules.delete(body.get('id')))
                elif action == 'move':
                    self.send_json(200, rules.move(body.get('id'), body.get('direction')))
                elif action == 'options':
                    self.send_json(200, rules.set_options(body))
                elif action == 'test':
                    self.send_json(200, rules.test(body))
                elif action == 'rescan' and rules.blocker:
                    rules.blocker.rescan()
                    self.send_json(200, rules.overview())
                else:
                    self.send_json(404, {"error": "接口不存在。"})
            elif path.startswith('/api/syslog/') and self.server.syslog:
                service = self.server.syslog
                if path == '/api/syslog/settings':
                    self.send_json(200, service.save_settings(body))
                elif path == '/api/syslog/search':
                    self.send_json(200, service.feed(body))
                elif path == '/api/syslog/detail':
                    self.send_json(200, service.detail(body.get('id')))
                else:
                    self.send_json(404, {"error": "接口不存在。"})
            elif path.startswith('/api/af/') and self.server.af:
                from af_firewall import save_af_settings
                action = path.rsplit('/', 1)[1]
                if action == 'settings':
                    save_af_settings(ROOT, body)
                    self.server.af.wake_event.set()
                    self.send_json(200, self.server.af.public())
                elif action == 'test':
                    self.send_json(200, self.server.af.test())
                elif action == 'sync':
                    self.send_json(200, self.server.af.sync(manual=True))
                else:
                    self.send_json(404, {"error": "接口不存在。"})
            elif path == '/api/geo' and self.server.geo:
                self.send_json(200, self.server.geo.lookup_many(body.get('ips')))
            elif path == '/api/deep/start' and self.server.deep:
                self.send_json(200, self.server.deep.start(body))
            elif path == '/api/deep/ask' and self.server.deep:
                self.send_json(200, self.server.deep.ask(body))
            elif path == '/api/deep/delete' and self.server.deep:
                self.send_json(200, self.server.deep.delete(body.get('id')))
            elif path.startswith('/api/notify/') and self.server.notifier:
                from notify import save_notify_settings
                notifier, action = self.server.notifier, path.rsplit('/', 1)[1]
                if action == 'settings':
                    save_notify_settings(notifier.root, body)
                    notifier.wake_event.set()
                    self.send_json(200, notifier.public())
                elif action == 'test':
                    self.send_json(200, notifier.test())
                elif action == 'groups':
                    self.send_json(200, notifier.groups())
                elif action == 'members':
                    self.send_json(200, notifier.members(body))
                elif action == 'save':
                    self.send_json(200, notifier.save(body))
                elif action == 'delete':
                    self.send_json(200, notifier.delete(body.get('id')))
                elif action == 'preview':
                    self.send_json(200, notifier.preview(body))
                elif action == 'send-test':
                    self.send_json(200, notifier.send_test(body))
                else:
                    self.send_json(404, {"error": "接口不存在。"})
            elif path=='/api/blacklist/key' and self.server.blacklist:
                self.send_json(200,{'key':self.server.blacklist.key()})
            elif path == '/api/blacklist/manual/add' and self.server.blacklist:
                self.send_json(200, self.server.blacklist.manual_add(body))
            elif path == '/api/blacklist/manual/remove' and self.server.blacklist:
                self.send_json(200, self.server.blacklist.manual_remove(body.get('ip')))
            elif path == '/api/blacklist/rules/list' and self.server.blacklist:
                self.send_json(200, self.server.blacklist.rules())
            elif path == '/api/blacklist/rules/remove' and self.server.blacklist:
                self.send_json(200, self.server.blacklist.remove_rules(body))
            elif path == '/api/blacklist/rules/clear' and self.server.blacklist:
                self.send_json(200, self.server.blacklist.clear_all(body))
            elif path == '/api/site-rule' and self.server.rule:
                self.send_json(200, self.server.rule.configure(body.get('enabled')))
            elif path == '/api/websites/ai' and self.server.store:
                website = body.get('website')
                site = next((s for s in self.server.client.websites() if s['id'] == website), None)
                if site is None:
                    raise ValueError('网站不存在，请重新加载网站列表。')
                excluded = self.server.store.set_ai_excluded(website, body.get('excluded'), site['name'])
                self.send_json(200, {'website': website, 'aiExcluded': excluded})
            elif path == '/api/agents/register' and self.server.hub:
                agent_id, payload = self.server.hub.enroll(body)
                self.respond(200, payload, 'application/zip')
            elif path == '/api/agents/state' and self.server.hub:
                self.server.hub.set_enabled(body.get('agentId'), body.get('enabled'))
                self.send_json(200, {'ok': True})
            elif path.startswith('/api/ai/') and not self.server.ai:
                self.send_json(503, {'error': 'AI 服务尚未启动。'})
            elif path == '/api/ai/settings':
                data = save_settings(ROOT, body)
                self.server.ai.wake_event.set()
                self.send_json(200, {"settings": data})
            elif path in ('/api/ai/block', '/api/ai/unblock'):
                if type(body.get('id')) is not int or body['id'] <= 0:
                    raise ValueError('判断记录编号无效。')
                if path.endswith('/unblock'):
                    decision = self.server.store.decision(body['id'])
                    self.server.ai.waf.remove(decision['ip'])
                    self.server.store.update_ip_decisions(decision['ip'], 'unblocked', '已移除本程序创建的规则；停止再次自动封禁')
                else:
                    self.server.ai.block_decision(body['id'])
                self.send_json(200, {"ok": True, "decision": self.server.store.decision(body['id'])})
            else:
                self.send_json(404, {"error": "接口不存在。"})
        except (PanelError, SecurityError) as exc:
            self.send_json(exc.status, {"error": str(exc)})
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            message = str(exc) if (path.startswith(('/api/agents/', '/api/clean-rules/', '/api/af/', '/api/syslog/', '/api/notify/', '/api/blacklist/manual/', '/api/blacklist/rules/', '/api/deep/')) or path in ('/api/site-rule', '/api/websites/ai', '/api/geo')) and type(exc) is ValueError else ''
            self.send_json(400, {"error": message or "设置或操作参数不正确，请检查模型、批次、并发数、IP / CIDR 和置信度。"})
        except Exception:
            self.send_json(500, {"error": "操作失败，请检查连接和 WAF 状态。"})


def stop_running_server():
    """Ask only this checkout's local server to exit through its normal cleanup."""
    try:
        port = '8787'
        path = ROOT / '.env'
        if path.exists():
            for line in path.read_text(encoding='utf-8-sig').splitlines():
                if '=' in line and line.split('=', 1)[0].strip() == 'PORT':
                    port = line.split('=', 1)[1].strip().strip('"\'')
        port = int(os.environ.get('PORT', port))
        if not 1 <= port <= 65535:
            raise ValueError('PORT 应为 1–65535。')
        base = f'http://127.0.0.1:{port}'
        opener = request.build_opener(request.ProxyHandler({}))
        with opener.open(base + '/api/config', timeout=5) as response:
            identity = json.load(response)
        if identity.get('appId') != '1panel-log-guard' or identity.get('instanceId') != INSTANCE_ID:
            raise ValueError('端口上的程序不是当前目录的实例，或版本过旧。请在对应启动窗口按 Ctrl+C 停止。')
        req = request.Request(base + '/api/shutdown', data=json.dumps({'instanceId': INSTANCE_ID}).encode(),
                              headers={'Content-Type': 'application/json'})
        with opener.open(req, timeout=5) as response:
            result = json.load(response)
        if result.get('ok') is not True:
            raise ValueError('程序未确认停止请求。')
        print('已发送停止请求，程序将保存待写入日志并退出。')
        return 0
    except error.URLError as exc:
        if isinstance(exc.reason, ConnectionRefusedError):
            print('程序未运行，无需停止。')
            return 0
        print('无法发送停止请求，请检查端口配置，或在启动窗口按 Ctrl+C 停止。')
    except (OSError, ValueError, AttributeError):
        print('停止失败：请确认当前目录和 PORT 配置；旧版本请在启动窗口按 Ctrl+C 停止。')
    return 1


def main():
    parser = argparse.ArgumentParser(description="1Panel 本机网站日志查看器")
    parser.add_argument("--no-browser", action="store_true", help="启动时不自动打开浏览器")
    parser.add_argument("--stop", action="store_true", help="正常停止当前目录的运行实例")
    args = parser.parse_args()
    if args.stop:
        return stop_running_server()
    try:
        from storage import Store
        from monitor import Monitor
        from security import AiWorker, settings
        from hub import Hub
        from site_rule import SiteVisitRule
        from blacklist import BlacklistService
        from clean_rules import CleanRules, RuleBlocker
        from af_firewall import AfSync
        from syslog_server import SyslogService
        from notify import KeywordNotifier
        from deep_analysis import DeepAnalysis
        from geoip import GeoIP
        config = load_config()
        settings(ROOT)  # Validate optional AI settings before launching.
        local_url = f"http://127.0.0.1:{config['port']}"
        try:
            with request.urlopen(local_url + '/api/config', timeout=1) as existing:
                identity = json.load(existing)
            if identity.get('appId') == '1panel-log-guard':
                print(f"程序已在运行：{local_url}")
                if not args.no_browser:
                    webbrowser.open(local_url)
                return 0
        except (OSError, ValueError, AttributeError):
            pass
        client = PanelClient(config)
        store = Store(ROOT / 'runtime' / 'state.sqlite3')
        monitor = Monitor(client, store)
        ai = AiWorker(ROOT, client, store)
        blacklist=BlacklistService(ROOT,ai.waf)
        clean_rules = CleanRules(store)
        ai.clean_rules = clean_rules
        blocker = RuleBlocker(ROOT, client, store, ai.waf, clean_rules)
        clean_rules.blocker = blocker
        hub = Hub(store,blacklist,clean_rules)
        rule = SiteVisitRule(ROOT, client, store, ai.waf)
        af = AfSync(ROOT, store, blacklist)
        syslog = SyslogService(ROOT, ai.waf, af)
        site_names = lambda: {site['id']: site['name'] for site in client.websites()}
        geo = GeoIP(ROOT / 'data')
        if geo.error:
            print(f"GeoIP 未启用：{geo.error}")
        notifier = KeywordNotifier(ROOT, store, site_names, geo=geo)
        deep = DeepAnalysis(ROOT, store, clean_rules, site_names, geo=geo)
        server = LogServer(("127.0.0.1", config["port"]), client, store, monitor, ai, hub, rule,blacklist,clean_rules,af,
                           notifier, deep, geo, syslog)
    except (ValueError, OSError) as exc:
        print(f"启动失败：{exc}")
        return 1
    url = f"http://127.0.0.1:{config['port']}"
    print(f"网站日志查看器已启动：{url}")
    print("保留此窗口以持续查看；按 Ctrl+C 停止。")
    hub.start_receiver(config['agentBind'], config['agentPort'], config['url'], config['agentPublicUrl'])
    print(f"Windows 代理接收地址：{hub.advertised_url or hub.receiver_error}")
    monitor.start()
    ai.start()
    rule.start()
    af.start()
    blocker.start()
    notifier.start()
    syslog.start()
    if not args.no_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n日志查看器已停止。")
    finally:
        monitor.stop()
        ai.stop()
        rule.stop()
        af.stop()
        blocker.stop()
        notifier.stop()
        syslog.stop()
        hub.stop_receiver()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
