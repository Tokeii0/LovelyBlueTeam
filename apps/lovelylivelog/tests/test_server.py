import hashlib
import json
from pathlib import Path
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib import error, request, parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server import LogServer, PanelClient, PanelError
import server as server_module


class MockPanel(BaseHTTPRequestHandler):
    key = "test-secret"
    requests = []
    enabled = True
    lines = ["重复日志"] * 203 + ["末尾中文日志"]

    def log_message(self, *args):
        pass

    def reply(self, data, code=200):
        payload = json.dumps({"code": code, "data": data}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def check_auth(self):
        timestamp = self.headers.get("1Panel-Timestamp", "")
        token = hashlib.md5(("1panel" + self.key + timestamp).encode()).hexdigest()
        return self.headers.get("1Panel-Token") == token and timestamp.isdigit()

    def do_GET(self):
        if not self.check_auth():
            return self.reply(None, 401)
        self.requests.append((self.command, self.path, None))
        website = {"id": 1, "primaryDomain": "中文.example", "alias": "test", "status": "Running",
                   "accessLog": self.enabled, "errorLog": self.enabled,
                   "accessLogPath": "/www/sites/test/log/access.log", "errorLogPath": "/www/sites/test/log/error.log",
                   "webSiteSSL": {"privateKey": "TLS-PRIVATE-SECRET"}, "password": "DB-SECRET"}
        if self.path.endswith("/websites/list"):
            return self.reply([website])
        if self.path.endswith("/websites/1"):
            return self.reply(website)
        if self.path.startswith("/api/v1/files/download?"):
            path = parse.parse_qs(parse.urlsplit(self.path).query)["path"][0]
            if path not in (website["accessLogPath"], website["errorLogPath"]):
                return self.reply(None, 403)
            content = ("\n".join(self.lines) + "\n").encode() if self.lines else b""
            value = self.headers["Range"].removeprefix("bytes=")
            if value.startswith("-"):
                start, end = max(0, len(content) - int(value[1:])), len(content) - 1
            else:
                first, last = value.split("-")
                start, end = int(first), min(int(last), len(content) - 1)
            if start > end:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{len(content)}")
                self.end_headers()
                return
            payload = content[start:end + 1]
            self.send_response(206)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(content)}")
            self.end_headers()
            self.wfile.write(payload)
            return
        self.reply(None, 404)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), MockPanel)
        cls.thread = threading.Thread(target=cls.upstream.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()
        cls.upstream.server_close()

    def setUp(self):
        MockPanel.requests = []
        MockPanel.enabled = True
        MockPanel.lines = ["重复日志"] * 203 + ["末尾中文日志"]
        self.client = PanelClient({"url": f"http://127.0.0.1:{self.upstream.server_port}",
                                   "key": MockPanel.key, "prefix": "/api/v1", "timeout": 2})

    def test_signed_authentication_and_sensitive_website_fields(self):
        with patch("server.time.time", return_value=1700000000):
            websites = self.client.websites()
        self.assertEqual(websites[0]["name"], "中文.example")
        serialized = json.dumps(websites)
        self.assertNotIn("TLS-PRIVATE-SECRET", serialized)
        self.assertNotIn("DB-SECRET", serialized)
        self.assertEqual(MockPanel.requests[0][:2], ("GET", "/api/v1/websites/list"))

    def test_latest_reads_tail_and_preserves_duplicate_lines(self):
        data = self.client.logs(1, "access.log", 200)
        self.assertEqual(len(data["lines"]), 200)
        self.assertEqual(data["lines"].count("重复日志"), 199)
        self.assertEqual(data["lines"][-1], "末尾中文日志")
        self.assertTrue(data["hasOlder"])
        self.assertTrue(data["latest"])
        self.assertGreater(data["before"], 0)
        self.assertTrue(MockPanel.requests[-1][1].startswith('/api/v1/files/download?'))
        self.assertTrue(all(r[0] == "GET" for r in MockPanel.requests))
        self.client.logs(1, "access.log", 200)
        self.assertEqual(len([r for r in MockPanel.requests if r[1].endswith("/websites/1")]), 1)

    def test_history_cursor_preserves_all_lines_without_gaps(self):
        MockPanel.lines = [f"日志 {index}" for index in range(1107)]
        pages = []
        data = self.client.logs(1, "error.log", 200)
        while True:
            pages.insert(0, data["lines"])
            if not data["hasOlder"]:
                break
            previous = data["before"]
            data = self.client.logs(1, "error.log", 200, previous)
            self.assertFalse(data["latest"])
            self.assertLess(data["before"], previous)
        self.assertEqual([line for page in pages for line in page], MockPanel.lines)

    def test_range_expansion_handles_utf8_split_at_chunk_boundary(self):
        MockPanel.lines = [f"{index} 中文" + "中" * 210 for index in range(511)]
        data = self.client.logs(1, "access.log", 200)
        self.assertEqual(data["lines"], MockPanel.lines[-200:])
        history = self.client.logs(1, "access.log", 200, data["before"])
        self.assertEqual(history["lines"], MockPanel.lines[-400:-200])
        self.assertGreater(len(MockPanel.requests), 4)

    def test_empty_and_truncated_files(self):
        MockPanel.lines = []
        data = self.client.logs(1, "access.log", 200)
        self.assertEqual(data["lines"], [])
        self.assertFalse(data["hasOlder"])
        MockPanel.lines = [f"old {index}" for index in range(400)]
        old = self.client.logs(1, "access.log", 200)
        MockPanel.lines = ["new"]
        with self.assertRaisesRegex(PanelError, "轮转|缩小"):
            self.client.logs(1, "access.log", 200, old["before"])
        self.assertEqual(self.client.logs(1, "access.log", 200)["lines"], ["new"])

    def test_disabled_log_does_not_read_file(self):
        MockPanel.enabled = False
        data = self.client.logs(1, "error.log", 200)
        self.assertFalse(data["enabled"])
        self.assertEqual(data["lines"], [])
        self.assertEqual(len(MockPanel.requests), 1)

    def test_upstream_authentication_failure_is_actionable(self):
        self.client.config["key"] = "wrong-key"
        with self.assertRaisesRegex(PanelError, "认证失败"):
            self.client.websites()

    def test_invalid_json_and_secret_error_are_not_forwarded(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, *args): return self.payload
        response = Response()
        for payload in (b'<html>test-secret</html>', b'{"code":500,"message":"test-secret"}'):
            response.payload = payload
            with patch("server.request.urlopen", return_value=response):
                with self.assertRaises(PanelError) as raised:
                    self.client.websites()
                self.assertNotIn("test-secret", str(raised.exception))

    def test_network_failure_has_localized_message(self):
        with patch("server.request.urlopen", side_effect=error.URLError("test-secret")):
            with self.assertRaisesRegex(PanelError, "无法连接 1Panel") as raised:
                self.client.websites()
            self.assertNotIn("test-secret", str(raised.exception))

    def test_local_routes_reject_private_files_and_cross_origin(self):
        server = LogServer(("127.0.0.1", 0), self.client)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with request.urlopen(base + "/api/config") as response:
                public_config = response.read().decode()
                self.assertNotIn(MockPanel.key, public_config)
                self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
            # Every asset in static/ is served without listing it in server.py.
            for asset in sorted(Path(server_module.STATIC).glob("*")):
                if asset.suffix in (".js", ".css", ".svg"):
                    with request.urlopen(base + "/" + asset.name) as response:
                        self.assertEqual(response.status, 200)
            for path in ("/.env", "/server.py", "/../.env", "/missing.js", "/static/app.js", "/%2e%2e/server.py", "/index.html"):
                with self.assertRaises(error.HTTPError) as raised:
                    request.urlopen(base + path)
                self.assertEqual(raised.exception.code, 404)
            for params in ("id=-1", "id=1&type=../../etc/passwd", "id=1&limit=999999", "id=1&latest=maybe"):
                with self.assertRaises(error.HTTPError) as raised:
                    request.urlopen(base + "/api/logs?" + params)
                self.assertEqual(raised.exception.code, 400)
            for headers in ({"Origin": "https://other.example"}, {"Host": "other.example"}, {"Sec-Fetch-Site": "cross-site"}):
                with self.assertRaises(error.HTTPError) as raised:
                    request.urlopen(request.Request(base + "/api/websites", headers=headers))
                self.assertEqual(raised.exception.code, 403)
            self.assertEqual(MockPanel.requests, [])
            with request.urlopen(base + "/api/logs?id=1&limit=200") as response:
                data = json.load(response)
                self.assertEqual(data["lines"][-1], "末尾中文日志")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
