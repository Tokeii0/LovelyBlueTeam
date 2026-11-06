from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib import error, request

from security import AiWorker, Waf
from server import LogServer
from storage import Store


class ReadOnlyPanel:
    config = {'url': 'http://10.20.30.13:18479', 'prefix': '/api/v2'}

    def __init__(self):
        self.enabled = self.blacklist = self.healthy = True
        self.calls = []

    def call(self, path, body=None):
        self.calls.append((path, body))
        if path == '/xpack/waf/status':
            return {'healthy': self.healthy, 'open': True, 'openrestyVersion': 'test-version'}
        if path == '/xpack/waf/config/global':
            return {'waf': {'state': 'on' if self.enabled else 'off'},
                    'ipBlack': {'state': 'on' if self.blacklist else 'off'}}
        raise AssertionError('Unexpected panel write or endpoint: ' + path)


class HistoryStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.joinpath('.env').write_text(
            ('AI_ANALYSIS_MODE=ai\n' + 'PANEL_API_KEY=panel-fixture\nDEEPSEEK_API_KEY=deepseek-fixture\n'
            'AI_ENABLED=true\nAUTO_BLOCK=false\n'), encoding='utf-8')
        self.env = patch.dict('os.environ', {}, clear=True)
        self.env.start()
        self.store = Store(self.root / 'state.sqlite3')
        self.panel = ReadOnlyPanel()
        self.worker = AiWorker(self.root, self.panel, self.store)

    def tearDown(self):
        self.worker.stop()
        for thread in (self.worker.thread, self.worker.health_thread):
            if thread:
                thread.join(3)
                self.assertFalse(thread.is_alive())
        self.store.close()
        self.env.stop()
        self.temp.cleanup()

    def add(self, attack=False, ip='8.8.8.8', evidence=None):
        return self.store.add_decision(1, {
            'ip': ip, 'is_attack': attack, 'confidence': .99,
            'attack_type': 'scanner' if attack else 'none',
            'reason': '扫描行为' if attack else '正常访问',
            'evidence_ids': evidence or []}, 'review' if attack else 'normal')

    def test_normal_and_attack_history_include_time_reason_and_original_evidence(self):
        self.store.append('test', {}, 1, 'access.log', ['first request', 'second request'])
        self.store.mark([1, 2], 'analyzed')
        normal = self.add(evidence=[1])
        attack = self.add(True, evidence=[2])
        data = self.store.dashboard()
        self.assertEqual([d['id'] for d in data['decisions']], [attack, normal])
        self.assertEqual([d['attack'] for d in data['decisions']], [1, 0])
        self.assertEqual(data['decisions'][1]['reason'], '正常访问')
        self.assertGreater(data['decisions'][1]['created'], 0)
        self.assertEqual(data['decisions'][1]['evidence'], [{'id': 1, 'raw': 'first request'}])
        self.assertEqual(data['decisions'][1]['evidenceCount'], 1)
        self.assertEqual(data['history']['normalTotal'], 1)
        self.assertEqual(data['history']['attackTotal'], 1)
        self.assertEqual(data['summary']['analyzed'], 2)

    def test_normal_history_never_offers_unblock_for_shared_ip(self):
        self.store.set_block('8.8.8.8', 'fixture', True, 'listed')
        self.add(True)
        normal = self.add()
        rows = self.store.dashboard()['decisions']
        self.assertEqual(rows[0]['id'], normal)
        self.assertFalse(rows[0]['canUnblock'])
        self.assertTrue(rows[1]['canUnblock'])
        with self.assertRaisesRegex(ValueError, '只能'):
            self.worker.block_decision(normal)
        self.assertEqual(self.panel.calls, [])

    def test_history_pagination_does_not_shift_when_new_decisions_arrive(self):
        expected = [self.add(attack=i % 3 == 0) for i in range(45)][::-1]
        first = self.store.dashboard(page_size=20)
        snapshot = first['history']['through']
        self.add(True)
        second = self.store.dashboard(page=2, page_size=20, through=snapshot)
        third = self.store.dashboard(page=3, page_size=20, through=snapshot)
        actual = [d['id'] for data in (first, second, third) for d in data['decisions']]
        self.assertEqual(actual, expected)
        self.assertEqual(second['history']['total'], 45)
        self.assertEqual(self.store.dashboard()['history']['total'], 46)

    def test_result_filters_page_clamping_and_empty_history(self):
        empty = self.store.dashboard()
        self.assertEqual(empty['history']['pages'], 1)
        self.assertEqual(empty['decisions'], [])
        for i in range(52):
            self.add(attack=i % 2 == 0)
        for verdict, attack in [('normal', 0), ('attack', 1)]:
            data = self.store.dashboard(page=99, verdict=verdict)
            self.assertEqual(data['history']['total'], 26)
            self.assertEqual(data['history']['page'], 2)
            self.assertEqual(len(data['decisions']), 6)
            self.assertTrue(all(d['attack'] == attack for d in data['decisions']))

    def test_history_is_retained_when_database_is_reopened(self):
        saved = self.add()
        self.store.close()
        self.store = Store(self.root / 'state.sqlite3')
        self.assertEqual(self.store.dashboard()['decisions'][0]['id'], saved)

    def test_history_rejects_invalid_parameters(self):
        for options in ({'page': 0}, {'page': True}, {'page_size': 21}, {'page_size': 20.0},
                        {'verdict': 'all OR 1=1'}, {'through': -1}, {'through': 2**63}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.store.dashboard(**options)

    def test_waf_switches_and_health_have_separate_messages(self):
        self.panel.healthy = False
        data = self.worker.refresh_waf()
        self.assertTrue(data['enabled'])
        self.assertTrue(data['blacklistEnabled'])
        self.assertFalse(data['healthy'])
        self.assertIn('已开启', data['message'])
        self.assertIn('健康检查未通过', data['message'])
        self.assertGreater(data['checkedAt'], 0)
        self.panel.healthy = True
        self.assertTrue(self.worker.refresh_waf()['healthy'])
        self.panel.blacklist = False
        self.assertIn('IP 黑名单开关未开启', self.worker.refresh_waf()['message'])
        self.panel.enabled = False
        self.assertIn('总开关已关闭', self.worker.refresh_waf()['message'])

    def test_failed_status_read_does_not_report_previously_ready_state(self):
        self.worker.refresh_waf()
        with patch.object(self.panel, 'call', side_effect=RuntimeError('private-upstream-detail')):
            data = self.worker.refresh_waf()
        self.assertIsNone(data['enabled'])
        self.assertIsNone(data['healthy'])
        self.assertTrue(data['error'])
        self.assertNotIn('private-upstream-detail', json.dumps(data))

    def test_waf_refresh_continues_while_ai_request_is_waiting(self):
        started, release, checked = threading.Event(), threading.Event(), threading.Event()
        timestamp = datetime.now(timezone.utc).strftime('%d/%b/%Y:%H:%M:%S +0000')
        self.store.append('test', {}, 1, 'access.log', [
            f'8.8.8.8 - - [{timestamp}] "GET / HTTP/1.1" 200 10 "-" "test"'])

        class SlowModel:
            def analyze(inner, events, config):
                started.set()
                if not release.wait(5):
                    raise AssertionError('Test model was not released')
                return [{'ip': '8.8.8.8', 'is_attack': False, 'confidence': .99,
                         'attack_type': 'none', 'reason': '正常请求', 'evidence_ids': [events[0]['id']]}]

        original = self.worker.waf.status
        def status():
            data = original()
            if not data['healthy']:
                checked.set()
            return data

        self.worker.model = SlowModel()
        self.worker.waf.status = status
        self.worker.start()
        try:
            self.assertTrue(started.wait(2))
            self.assertTrue(self.worker.busy)
            self.panel.healthy = False
            self.worker.health_wake.set()
            self.assertTrue(checked.wait(2), 'WAF status was blocked by the model request')
            self.assertTrue(self.worker.busy)
        finally:
            release.set()

    def test_history_and_manual_waf_check_http_routes_use_only_read_operations(self):
        for i in range(25):
            self.add(attack=i % 2 == 0)
        server = LogServer(('127.0.0.1', 0), self.panel, self.store, None, self.worker)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            with request.urlopen(base + '/api/ai?verdict=normal&page=1&pageSize=20') as response:
                data = json.load(response)
            self.assertEqual(data['history']['total'], 12)
            self.assertTrue(all(d['attack'] == 0 for d in data['decisions']))
            self.assertNotIn('deepseek-fixture', json.dumps(data))
            self.panel.healthy = False
            with request.urlopen(base + '/api/ai/waf') as response:
                self.assertFalse(json.load(response)['waf']['healthy'])
            self.panel.healthy = True
            with request.urlopen(base + '/api/ai/waf') as response:
                self.assertTrue(json.load(response)['waf']['healthy'])
            for query in ('page=0', 'pageSize=999', 'verdict=garbage', 'through=-1', 'page=bad'):
                with self.assertRaises(error.HTTPError) as raised:
                    request.urlopen(base + '/api/ai?' + query)
                self.assertEqual(raised.exception.code, 400)
            self.assertTrue(all(body is None for _, body in self.panel.calls))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    unittest.main()
