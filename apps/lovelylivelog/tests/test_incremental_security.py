from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib import request, error

from monitor import Monitor
from security import (AiWorker, DeepSeek, SecurityError, Waf, normalized_event, protection_reason,
                      public_settings, save_settings, settings)
from server import LogServer
from storage import Store


class BytePanel:
    config = {'url': 'http://10.20.30.13:18479', 'prefix': '/api/v2'}

    def __init__(self, content=b'old line\n'):
        self.content, self.reads = content, []

    def metadata(self, website):
        return {'accessLog': True, 'errorLog': True, 'accessLogPath': '/sites/test/log/access.log', 'errorLogPath': '/sites/test/log/error.log'}

    def read_range(self, path, window, before):
        self.reads.append(('tail', window))
        start = max(0, len(self.content) - window)
        return self.content[start:], start, len(self.content)

    def read_segment(self, path, start, window):
        self.reads.append(('segment', start, window))
        return self.content[start:start + window], start, len(self.content)


class FakePanel(BytePanel):
    """No network: emulate the verified WAF API contract for action tests."""
    def __init__(self):
        super().__init__()
        self.black, self.white, self.calls = [], [], []
        self.active = True
        self.timeout_after_create = False
        self.before_create = None

    def call(self, path, body=None):
        self.calls.append((path, body))
        if path == '/xpack/waf/status':
            return {'healthy': self.active, 'open': self.active}
        if path == '/xpack/waf/config/global':
            return {'waf': {'state': 'on' if self.active else 'off'}, 'ipBlack': {'state': 'on'}}
        if path == '/xpack/waf/rule/ip/search':
            if self.before_create and body['type'] == 'ipBlack':
                callback, self.before_create = self.before_create, None
                callback()
            rows = self.black if body['type'] == 'ipBlack' else self.white
            return {'items': [dict(r) for r in rows], 'total': len(rows)}
        if path == '/xpack/waf/rule/ip/create':
            self.black.append(dict(body))
            if self.timeout_after_create:
                raise SecurityError('timeout after accepted write')
            return None
        if path == '/xpack/waf/rule/ip/delete':
            self.black = [r for r in self.black if r['name'] != body['name']]
            return None
        raise AssertionError('Unexpected endpoint: ' + path)


class FakeModel:
    def __init__(self, attack=True, confidence=.99):
        self.attack, self.confidence, self.calls = attack, confidence, []
        self.failure = False

    def analyze(self, events, config):
        self.calls.append(events)
        if self.failure:
            raise SecurityError('模拟 AI 请求失败')
        return [{'ip': ip, 'is_attack': self.attack, 'confidence': self.confidence,
                 'attack_type': 'scanner' if self.attack else 'none', 'reason': '测试中的扫描行为' if self.attack else '正常请求',
                 'evidence_ids': [e['id'] for e in events if e['ip'] == ip]}
                for ip in sorted({e['ip'] for e in events})]


def access(ip='8.8.8.8', path='/.env', time_text=None):
    timestamp = time_text or datetime.now(timezone.utc).strftime('%d/%b/%Y:%H:%M:%S +0000')
    return f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" 404 42 "-" "test-agent"'


class IncrementalSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.joinpath('.env').write_text(('AI_ANALYSIS_MODE=ai\n' + 'PANEL_API_KEY=panel-test-secret\nDEEPSEEK_API_KEY=ai-test-secret\nIP_ALLOWLIST=8.8.6.173/32\nAI_ENABLED=true\nAUTO_BLOCK=true\n'), encoding='utf-8')
        self.store = Store(self.root / 'state.sqlite3')
        self.panel = FakePanel()
        self.model = FakeModel()
        self.worker = AiWorker(self.root, self.panel, self.store, self.model)
        self.env = patch.dict('os.environ', {}, clear=True)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.store.close()
        self.temp.cleanup()

    def put(self, lines, website=1):
        self.store.append('source', {'offset': 0}, website, 'access.log', lines)

    def test_initial_baseline_is_not_replayed_and_duplicates_are_preserved(self):
        client = BytePanel(b'old\n')
        monitor = Monitor(client, self.store)
        monitor.collect({'id': 1}, 'access.log')
        self.assertEqual(self.store.feed(1, 'access.log', None, 100)['events'], [])
        client.content += b'new\nnew\n'
        monitor.collect({'id': 1}, 'access.log')
        monitor.collect({'id': 1}, 'access.log')
        rows = self.store.feed(1, 'access.log', None, 100)['events']
        self.assertEqual([r['raw'] for r in rows], ['new', 'new'])
        self.assertEqual(sum(r[0] == 'tail' for r in client.reads), 1)

    def test_split_utf8_and_partial_lines_survive_restart(self):
        client = BytePanel(b'old\n')
        monitor = Monitor(client, self.store)
        monitor.collect({'id': 1}, 'access.log')
        text = '新增中文'.encode()
        client.content += text[:5]
        monitor.collect({'id': 1}, 'access.log')
        self.assertEqual(self.store.feed(1, 'access.log', None, 100)['events'], [])
        client.content += text[5:] + b'\n'
        Monitor(client, self.store).collect({'id': 1}, 'access.log')
        self.assertEqual(self.store.feed(1, 'access.log', None, 100)['events'][0]['raw'], '新增中文')

    def test_file_replacement_and_truncation_resume_from_new_file(self):
        client = BytePanel(b'original long old content\n')
        monitor = Monitor(client, self.store)
        monitor.collect({'id': 1}, 'access.log')
        client.content = b'new file\n'
        result = monitor.collect({'id': 1}, 'access.log')
        self.assertTrue(result['rotated'])
        client.content = b'another completely different file with longer content\n'
        result = monitor.collect({'id': 1}, 'access.log')
        self.assertTrue(result['rotated'])
        self.assertEqual(len(self.store.feed(1, 'access.log', None, 100)['events']), 2)

    def test_backlog_has_no_gaps_and_feed_checkpoint_catches_more_pages(self):
        client = BytePanel(b'old\n')
        monitor = Monitor(client, self.store)
        monitor.collect({'id': 1}, 'access.log')
        expected = [f'row {n}' for n in range(500)]
        client.content += ('\n'.join(expected) + '\n').encode()
        with patch('monitor.MAX_CHUNK', 128):
            for _ in range(100):
                status = monitor.collect({'id': 1}, 'access.log')
                if not status['backlog']:
                    break
        result, after = [], 0
        while True:
            page = self.store.feed(1, 'access.log', after, 100)
            result.extend(r['raw'] for r in page['events'])
            after = page['after']
            if not page['hasMore']:
                break
        self.assertEqual(result, expected)

    def test_current_ai_schema_rejects_unseen_ips_and_mismatched_evidence(self):
        events = [{'id':1,'ip':'8.8.8.8'},{'id':2,'ip':'1.1.1.1'}]
        response = {'decisions':[{'ip':'8.8.8.8','is_attack':True,'confidence':.99,'attack_type':'scanner','reason':'原因','evidence_ids':[2]},
                                 {'ip':'1.1.1.1','is_attack':False,'confidence':.9,'attack_type':'none','reason':'正常','evidence_ids':[]}]}
        with self.assertRaises(ValueError): DeepSeek.validate(response, events)
        response['decisions'][0].update(ip='9.9.9.9', evidence_ids=[1])
        with self.assertRaises(ValueError): DeepSeek.validate(response, events)
        response['decisions'][0].update(ip='8.8.8.8', evidence_ids=[1], confidence=float('nan'))
        with self.assertRaises(ValueError): DeepSeek.validate(response, events)

    def test_high_confidence_recent_evidence_is_listed_once_and_verified(self):
        self.put([access(), access(path='/wp-admin')])
        self.assertEqual(self.worker.process_once(), 2)
        self.put([access(), access(path='/config')])
        self.worker.process_once()
        writes = [b for p,b in self.panel.calls if p.endswith('/create')]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]['scope'], 'ipBlack')
        self.assertEqual(writes[0]['ipv4'], '8.8.8.8')
        self.assertEqual(self.store.block('8.8.8.8')['state'], 'existing')
        self.assertEqual(self.store.dashboard()['summary']['listed'], 1)

    def test_low_confidence_single_evidence_and_normal_requests_do_not_block(self):
        for lines, model in [([access(),access()],FakeModel(confidence=.7)), ([access()],FakeModel()), ([access(),access()],FakeModel(attack=False))]:
            self.worker.model = model
            self.put(lines)
            self.worker.process_once()
        self.assertEqual(self.panel.black, [])

    def test_admin_allowlist_private_ip_and_mapped_ipv6_are_protected(self):
        self.put([access('8.8.6.173'), access('8.8.6.173')])
        self.worker.process_once()
        self.put([access('10.0.0.1'), access('10.0.0.1')])
        self.worker.process_once()
        self.assertEqual(self.panel.black, [])
        self.assertEqual(self.store.dashboard()['decisions'][0]['state'], 'protected')
        self.assertTrue(protection_reason('::ffff:8.8.6.173', settings(self.root), '10.20.30.13'))

    def test_archived_records_ai_failure_and_disabled_analysis_do_not_block(self):
        self.put([access(time_text='01/Jan/2020:12:00:00 +0000')])
        self.assertEqual(self.worker.process_once(), 0)
        self.assertEqual(len(self.model.calls), 0)
        self.put([access(),access()]); self.model.failure = True
        with self.assertRaises(SecurityError): self.worker.process_once()
        self.assertEqual(len(self.store.pending(100)), 2)
        save_settings(self.root, {'enabled':False})
        self.assertEqual(self.worker.process_once(), 0)
        self.assertEqual(self.panel.black, [])

    def test_expired_backlog_does_not_delay_fresh_logs_by_full_ai_intervals(self):
        self.put([access(time_text='01/Jan/2020:12:00:00 +0000')] * 200 + [access(), access()])
        self.model.attack = False
        original = self.model.analyze
        def analyze(events, config):
            result = original(events, config)
            self.worker.stop()
            return result
        self.model.analyze = analyze
        self.worker.start()
        self.worker.thread.join(timeout=3)
        self.assertFalse(self.worker.thread.is_alive())
        self.assertEqual(len(self.model.calls), 1)
        self.assertEqual(self.store.dashboard()['summary']['analyzed'], 2)

    def test_disabling_auto_block_while_checking_rules_cancels_the_write(self):
        self.put([access(),access()])
        self.panel.before_create = lambda: save_settings(self.root, {'autoBlock':False})
        self.worker.process_once()
        self.assertEqual(self.panel.black, [])

    def test_stopped_worker_cannot_start_a_new_automatic_block(self):
        verdict = {'ip':'8.8.8.8','is_attack':True,'confidence':.99,'attack_type':'scanner','reason':'测试判断','evidence_ids':[1,2]}
        decision_id = self.store.add_decision(1, verdict, 'review')
        self.worker.stop()
        self.worker.block_decision(decision_id, automatic=True)
        self.assertEqual(self.panel.calls, [])

    def test_waf_disabled_is_recorded_as_inactive_instead_of_enforced(self):
        self.panel.active = False
        self.put([access(),access()]); self.worker.process_once()
        self.assertEqual(self.store.dashboard()['decisions'][0]['state'], 'inactive')

    def test_waf_whitelist_prevents_creation(self):
        self.panel.white = [{'name':'trusted','state':'on','type':'ipv4','ipv4':'8.8.8.0/24'}]
        self.put([access(),access()]); self.worker.process_once()
        self.assertEqual(self.panel.black, [])

    def test_ambiguous_create_timeout_reconciles_without_duplicate_write(self):
        self.panel.timeout_after_create = True
        self.put([access(),access()]); self.worker.process_once()
        self.assertEqual(len(self.panel.black), 1)
        self.assertEqual(self.store.block('8.8.8.8')['state'], 'listed')

    def test_server_generated_rule_name_is_verified_and_used_for_removal(self):
        original = self.panel.call
        def call(path, body=None):
            result = original(path, body)
            if path.endswith('/create'):
                self.panel.black[-1]['name'] = 'server-generated-rule'
            return result
        self.panel.call = call
        self.put([access(),access()]); self.worker.process_once()
        self.assertEqual(self.store.block('8.8.8.8')['name'], 'server-generated-rule')
        self.worker.waf.remove('8.8.8.8')
        self.assertEqual(self.panel.black, [])

    def test_existing_rules_cannot_be_deleted_and_modified_own_rules_are_preserved(self):
        self.panel.black = [{'name':'admin-rule','type':'ipv4','ipv4':'8.8.8.8','state':'on'}]
        self.worker.waf.add('8.8.8.8', 'reason')
        with self.assertRaises(SecurityError): self.worker.waf.remove('8.8.8.8')
        self.panel.black = []
        self.worker.waf.add('8.8.8.8', 'reason')
        self.panel.black[0]['ipv4'] = '8.8.8.0/24'
        with self.assertRaises(SecurityError): self.worker.waf.remove('8.8.8.8')
        self.assertEqual(len(self.panel.black), 1)

    def test_manual_unblock_is_verified_and_prevents_automatic_reblocking(self):
        self.put([access(),access()]); self.worker.process_once()
        self.worker.waf.remove('8.8.8.8')
        self.assertEqual(self.panel.black, [])
        self.put([access(),access()]); self.worker.process_once()
        self.assertEqual(self.panel.black, [])

    def test_settings_keep_panel_key_and_never_echo_deepseek_key(self):
        result = save_settings(self.root, {'key':'replacement-secret','model':'deepseek-flash','threshold':.96})
        self.assertNotIn('replacement-secret', json.dumps(result))
        self.assertNotIn('key', public_settings(settings(self.root)))
        self.assertIn('PANEL_API_KEY=panel-test-secret', self.root.joinpath('.env').read_text())
        save_settings(self.root, {'key':''})
        self.assertEqual(settings(self.root)['key'], 'replacement-secret')
        with self.assertRaises(ValueError): save_settings(self.root, {'model':'model\nPANEL_API_KEY=bad'})

    def test_sensitive_query_values_are_redacted_but_attack_evidence_is_kept(self):
        event = normalized_event({'id':1,'website':1,'raw':access(path='/api?token=secret&patient_id=123&q=union%20select')})
        self.assertNotIn('secret', event['target'])
        self.assertNotIn('patient_id=123', event['target'])
        self.assertIn('union', event['target'])

    def test_mutating_local_routes_reject_cross_site_requests_and_arbitrary_ips(self):
        server = LogServer(('127.0.0.1',0), self.panel, self.store, None, self.worker)
        thread = threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            req = request.Request(base+'/api/ai/block', data=b'{"ip":"8.8.8.8"}',headers={'Content-Type':'application/json'})
            with self.assertRaises(error.HTTPError) as raised: request.urlopen(req)
            self.assertEqual(raised.exception.code, 400)
            req = request.Request(base+'/api/ai/block', data=b'{"id":1}',headers={'Content-Type':'application/json','Origin':'https://attacker.example'})
            with self.assertRaises(error.HTTPError) as raised: request.urlopen(req)
            self.assertEqual(raised.exception.code, 403)
            with request.urlopen(base+'/api/ai') as response:
                raw = response.read().decode()
                self.assertNotIn('ai-test-secret', raw)
            self.assertEqual(self.panel.black, [])
        finally:
            server.shutdown(); server.server_close()


if __name__ == '__main__':
    unittest.main()
