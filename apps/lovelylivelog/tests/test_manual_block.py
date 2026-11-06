import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib import error, request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from blacklist import BlacklistService
from security import SecurityError, Waf
from server import LogServer
from storage import Store
from test_incremental_security import FakePanel


class ManualBlockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.env = patch.dict('os.environ', {}, clear=True); self.env.start()
        self.root.joinpath('.env').write_text(('AI_ANALYSIS_MODE=ai\nAUTO_BLOCK=true\n' + 'PANEL_API_KEY=panel-secret\nIP_ALLOWLIST=8.8.5.0/24\n'), encoding='utf-8')
        self.store = Store(self.root / 'state.sqlite3'); self.panel = FakePanel()
        self.service = BlacklistService(self.root, Waf(self.panel, self.store))

    def tearDown(self):
        self.store.close(); self.env.stop(); self.temp.cleanup()

    def created(self):
        return [c[1] for c in self.panel.calls if c[0] == '/xpack/waf/rule/ip/create']

    def test_adds_public_ips_with_reason(self):
        data = self.service.manual_add({'ips': '8.8.4.7\n8.8.4.8, 8.8.4.7', 'reason': 'Tomcat 管理后台爆破'})
        self.assertEqual([(r['ip'], r['state']) for r in data['results']], [('8.8.4.7', 'listed'), ('8.8.4.8', 'listed')])
        rule = self.created()[0]
        self.assertTrue(rule['name'].startswith('manual_'))
        self.assertEqual(rule['ipv4'], '8.8.4.7')
        self.assertIn('Manual [', rule['description']); self.assertIn('手动加黑：Tomcat 管理后台爆破', rule['description'])
        self.assertEqual({r['ip']: r['label'] for r in self.service.manual_list()['rows']},
                         {'8.8.4.7': '已加入黑名单', '8.8.4.8': '已加入黑名单'})

    def test_existing_rule_is_reported_not_duplicated(self):
        self.panel.black.append({'name': 'manual', 'type': 'ipv4', 'ipv4': '8.8.4.0/24', 'state': 'on'})
        data = self.service.manual_add({'ips': '8.8.4.9'})
        self.assertEqual(data['results'][0]['state'], 'existing')
        self.assertEqual(self.created(), [])

    def test_protected_addresses_are_never_written(self):
        data = self.service.manual_add({'ips': '10.20.31.150 8.8.5.5 127.0.0.1 10.20.30.13'})
        self.assertEqual([r['state'] for r in data['results']], ['protected'] * 4)
        self.assertIn('内网地址', data['results'][0]['detail'])
        self.assertIn('保护名单', data['results'][1]['detail'])
        self.assertIn('面板地址', data['results'][3]['detail'])
        self.assertEqual(self.created(), [])

    def test_waf_whitelist_conflict(self):
        self.panel.white.append({'name': 'w', 'type': 'ipv4', 'ipv4': '8.8.4.20', 'state': 'on'})
        data = self.service.manual_add({'ips': '8.8.4.20'})
        self.assertEqual(data['results'][0]['state'], 'protected')
        self.assertIn('白名单', data['results'][0]['detail'])

    def test_input_validation(self):
        for body, message in [({'ips': ''}, '1–50'), ({'ips': '8.8.4.0/24'}, '网段'), ({'ips': 'abc'}, '有效'),
                              ({'ips': ' '.join(f'8.8.4.{i}' for i in range(51))}, '1–50'),
                              ({'ips': '8.8.4.1', 'reason': 'x' * 101}, '100'),
                              ({'ips': '8.8.4.1', 'reason': 'a\nb'}, '换行')]:
            with self.assertRaisesRegex(ValueError, message):
                self.service.manual_add(body)

    def test_remove_only_manual_entries(self):
        self.service.manual_add({'ips': '8.8.4.7'})
        rows = self.service.manual_remove('8.8.4.7')['rows']
        self.assertEqual(rows[0]['state'], 'unblocked')
        self.assertEqual(self.panel.black, [])
        with self.assertRaisesRegex(ValueError, '手动加入'):
            self.service.manual_remove('8.8.4.99')
        self.panel.black.append({'name': 'other', 'type': 'ipv4', 'ipv4': '8.8.4.30', 'state': 'on'})
        self.service.manual_add({'ips': '8.8.4.30'})  # already listed by someone else
        with self.assertRaises(SecurityError):
            self.service.manual_remove('8.8.4.30')
        self.assertEqual(len(self.panel.black), 1)

    def test_routes(self):
        server = LogServer(('127.0.0.1', 0), self.panel, self.store, blacklist=self.service)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f'http://127.0.0.1:{server.server_port}'

        def call(path, body=None):
            req = request.Request(url + path, data=None if body is None else json.dumps(body).encode(),
                                  headers={'Content-Type': 'application/json'})
            try:
                with request.urlopen(req, timeout=5) as response:
                    return response.status, json.load(response)
            except error.HTTPError as response:
                return response.code, json.load(response)
        try:
            status, data = call('/api/blacklist/manual/add', {'ips': '8.8.4.7', 'reason': '测试'})
            self.assertEqual((status, data['results'][0]['state']), (200, 'listed'))
            self.assertEqual(call('/api/blacklist/manual')[1]['rows'][0]['ip'], '8.8.4.7')
            status, data = call('/api/blacklist/manual/add', {'ips': '1.2.3.0/24'})
            self.assertEqual(status, 400); self.assertIn('网段', data['error'])
            self.assertEqual(call('/api/blacklist/manual/remove', {'ip': '8.8.4.7'})[0], 200)
        finally:
            server.shutdown(); server.server_close()


if __name__ == '__main__':
    unittest.main()
