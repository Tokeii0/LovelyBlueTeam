"""Source isolation across the HTTP settings view, queue and mandatory rules."""
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib import request
import uuid
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from clean_rules import CleanRules, RuleBlocker
from hub import Hub
from security import AiWorker, save_settings
from server import LogServer
from storage import Store
from test_incremental_security import FakeModel, FakePanel, access
from test_rule_block import FakeWaf


class SourceRoutingApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict('os.environ', {}, clear=True)
        self.env.start()
        self.root.joinpath('.env').write_text(
            'AI_ANALYSIS_MODE=ai\nAI_ENABLED=true\nAUTO_BLOCK=true\nDEEPSEEK_API_KEY=test-only\n', encoding='utf-8')
        self.store = Store(self.root / 'state.sqlite3')
        self.hub = Hub(self.store)
        self.local = self.register('LovelyLog')
        self.other = self.register('Other server')
        self.set_local(True)
        self.panel = FakePanel()
        self.worker = AiWorker(self.root, self.panel, self.store)

    def register(self, name):
        return self.hub.register({'name': name, 'platformUrl': 'http://127.0.0.1:8788',
                                  'sources': [{'kind': 'access.log', 'path': '/post.log'}]})['agentId']

    def set_local(self, enabled):
        save_settings(self.root, {'localAgentIds': [self.local] if enabled else []})

    def upload(self, agent, ip='8.8.8.8', when=None):
        self.hub.ingest(agent, {'events': [{'eventId': uuid.uuid4().hex, 'kind': 'access.log',
            'source': '/post.log', 'raw': access(ip, '/.env'), 'collectedAt': when or time.time()}]})

    def tearDown(self):
        self.worker.stop()
        self.store.close()
        self.env.stop()
        self.temp.cleanup()

    def test_http_scoped_settings_keep_platform_ai_and_lovelylog_local(self):
        server = LogServer(('127.0.0.1', 0), self.panel, self.store, ai=self.worker, hub=self.hub)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            def config(query):
                with request.urlopen(base + '/api/ai?' + query, timeout=5) as response:
                    return json.load(response)['settings']
            platform = config('source=panel')
            local = config('source=agent&agent=' + self.local)
            other = config('source=agent&agent=' + self.other)
            self.assertEqual(platform['analysisMode'], 'ai')
            self.assertTrue(platform['autoBlock'])
            self.assertEqual(other['analysisMode'], 'ai')
            self.assertEqual(local['analysisMode'], 'local')
            self.assertFalse(local['autoBlock'])
            self.assertEqual(local['platformAnalysisMode'], 'ai')
            self.assertEqual(local['scopedAgentId'], self.local)
            self.assertNotIn('key', local)
            self.assertNotIn('test-only', json.dumps(local))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)

    def test_queue_source_filter_excludes_panel_and_unselected_agents(self):
        self.store.append('panel', {}, 1, 'access.log', [access('1.1.1.1', '/.env')])
        self.upload(self.other, '8.8.4.4')
        self.upload(self.local)
        rows = self.store.pending(100, agent_ids=[self.local])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['agent_id'], self.local)
        self.assertLess(rows[0]['id'], 0)
        self.assertEqual(self.store.pending(100, agent_ids=[]), [])
        self.assertEqual(len(self.store.pending(100)), 3)
        self.hub.set_enabled(self.local, False)
        self.assertEqual(self.store.pending(100, agent_ids=[self.local]), [])

    def test_mandatory_rules_ignore_local_source_but_still_apply_to_other_server(self):
        rules, waf = CleanRules(self.store), FakeWaf()
        rules.save({'name': 'sensitive config', 'action': 'block', 'path': r'/\.env'})
        blocker = RuleBlocker(self.root, self.panel, self.store, waf, rules)
        self.upload(self.local)
        self.upload(self.other, '8.8.4.4')
        blocker.scan()
        blocker.process()
        self.assertEqual([ip for ip, _, _ in waf.added], ['8.8.4.4'])
        self.assertIsNone(self.store.db.execute("SELECT ip FROM rule_block_ips WHERE ip='8.8.8.8'").fetchone())

    def test_old_local_source_rule_queue_requires_review_after_policy_change(self):
        self.set_local(False)
        rules, waf = CleanRules(self.store), FakeWaf()
        rules.save({'name': 'sensitive config', 'action': 'block', 'path': r'/\.env'})
        blocker = RuleBlocker(self.root, self.panel, self.store, waf, rules)
        self.upload(self.local)
        blocker.scan()
        self.set_local(True)
        blocker.process()
        self.assertEqual(waf.added, [])
        row = self.store.db.execute("SELECT state,detail FROM rule_block_ips WHERE ip='8.8.8.8'").fetchone()
        self.assertEqual(row['state'], 'review')
        self.assertIn('人工', row['detail'])

    def test_panel_local_review_can_be_backfilled_to_ai_without_historical_auto_ban(self):
        save_settings(self.root, {'analysisMode': 'local', 'enabled': True})
        old = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        raw = json.dumps({'time': old, 'ip': '8.8.8.8', 'method': 'POST', 'uri': '/query', 'status': 200,
                          'decoded_body': {'query': 'union select 1'}, 'decode_state': 'plain'})
        self.store.append('panel', {}, 1, 'access.log', [raw, raw])
        self.assertEqual(self.worker.process_once(), 2)
        self.assertEqual(self.panel.black, [])
        self.store.db.execute("UPDATE events SET ai_state='pending'")
        self.store.db.commit()
        save_settings(self.root, {'analysisMode': 'ai', 'autoBlock': True})
        model = FakeModel(attack=True)
        self.worker.model = model
        self.assertTrue(all(r['reviewed_locally'] for r in self.store.pending(10)))
        self.assertEqual(self.worker.process_once(), 2)
        self.assertEqual(len(model.calls), 1)
        self.assertTrue(all(e['_historical'] for e in model.calls[0]))
        row = self.store.db.execute("SELECT state,historical FROM decisions WHERE provider='deepseek'").fetchone()
        self.assertEqual((row['state'], row['historical']), ('review', 1))
        self.assertEqual(self.panel.black, [])


if __name__ == '__main__':
    unittest.main()
