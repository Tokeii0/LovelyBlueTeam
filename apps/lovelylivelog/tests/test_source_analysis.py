"""Trusted source IDs isolate LovelyLog's manual local review from the AI feed."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hub import Hub
from security import AiWorker, SecurityError, model_signature, save_settings, settings
from source_policy import is_local_source, local_agent_ids
from storage import Store
from test_incremental_security import FakeModel, FakePanel, access


class SourceAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict('os.environ', {}, clear=True)
        self.env.start()
        self.store = Store(self.root / 'state.sqlite3')
        self.hub = Hub(self.store)
        self.local_agent = self.agent('LovelyLog')
        self.ai_agent = self.agent('other-server')
        self.root.joinpath('.env').write_text(
            'AI_ANALYSIS_MODE=ai\nAI_ENABLED=true\nAUTO_BLOCK=true\nDEEPSEEK_API_KEY=test-key\n'
            f"LOCAL_RULE_AGENT_IDS={self.local_agent['agentId']}\n", encoding='utf-8')
        self.panel, self.model = FakePanel(), FakeModel()
        self.worker = AiWorker(self.root, self.panel, self.store, self.model)
        self.sequence = 0

    def tearDown(self):
        self.worker.stop()
        self.store.close()
        self.env.stop()
        self.temp.cleanup()

    def agent(self, name):
        return self.hub.register({'name': name, 'platformUrl': 'http://127.0.0.1:8788',
                                  'sources': [{'kind': 'access.log', 'path': '/site/post.log'}]})

    def put(self, agent=None, ip='8.8.8.8', body=None, when=None, spoof=None):
        agent = agent or self.local_agent
        self.sequence += 1
        data = {'time': when or datetime.now(timezone.utc).isoformat(), 'ip': ip, 'method': 'POST',
                'uri': '/business/query', 'status': 200,
                'decoded_body': body if body is not None else {'query': 'UNION SELECT 1'},
                'decode_state': 'plain', 'content_type': 'application/json'}
        data.update(spoof or {})
        self.hub.ingest(agent['agentId'], {'events': [{'eventId': f'{self.sequence:032x}', 'kind': 'access.log',
                         'source': '/site/post.log', 'collectedAt': time.time(), 'raw': json.dumps(data)}]})
        return -self.store.db.execute('SELECT MAX(id) FROM agent_events').fetchone()[0]

    def test_only_trusted_agent_envelope_or_normalized_fields_select_local(self):
        config = settings(self.root)
        local_id = self.local_agent['agentId']
        self.assertTrue(is_local_source(config, {'source_type': 'agent', 'agent_id': local_id}))
        self.assertTrue(is_local_source(config, {'_source_type': 'agent', '_agent_id': local_id}))
        for record in ({'source_type': 'panel', 'agent_id': local_id},
                       {'source_type': 'panel', '_source_type': 'agent', '_agent_id': local_id},
                       {'source_type': 'agent', 'agent_id': self.ai_agent['agentId'], 'name': 'LovelyLog'},
                       {'raw': json.dumps({'source_type': 'agent', 'agent_id': local_id})},
                       {'_sourceKey': 'agent:' + local_id}):
            self.assertFalse(is_local_source(config, record))

    def test_mixed_feed_only_sends_other_sources_to_ai_and_can_autoblock_them(self):
        local_id = self.put()
        self.put(self.ai_agent, ip='9.9.9.9')
        self.put(self.ai_agent, ip='9.9.9.9')
        self.store.append('panel-fixture', {}, 1, 'access.log', [access(ip='1.1.1.1'), access(ip='1.1.1.1')])
        self.assertEqual(self.worker.process_once(), 5)
        model_events = [e for call in self.model.calls for e in call]
        self.assertEqual({e['ip'] for e in model_events}, {'9.9.9.9', '1.1.1.1'})
        self.assertTrue(all('_localRequestBody' not in e and '_localTarget' not in e for e in model_events))
        self.assertEqual({r['ipv4'] for r in self.panel.black}, {'9.9.9.9', '1.1.1.1'})
        local = self.store.db.execute("SELECT * FROM decisions WHERE ip='8.8.8.8'").fetchone()
        self.assertEqual((local['provider'], local['state'], local['agent_id']),
                         ('local', 'review', self.local_agent['agentId']))
        self.assertEqual(json.loads(local['evidence']), [local_id])
        self.assertEqual(self.worker.performance['localRows'], 1)
        self.assertEqual(self.worker.performance['aiRows'], 4)

    def test_local_history_and_normal_rows_bind_current_ids_without_model(self):
        malicious = self.put(when='2020-01-01T00:00:00+00:00')
        normal = self.put(ip='1.1.1.1', body={'head': {'method': 'business.query'}})
        with patch('security.chat_completion', side_effect=AssertionError('must not call AI')):
            self.assertEqual(self.worker.process_once(), 2)
        self.assertEqual(self.model.calls, [])
        self.assertEqual(self.panel.black, [])
        rows = self.store.db.execute('SELECT * FROM decisions').fetchall()
        self.assertEqual({r['provider'] for r in rows}, {'local'})
        by_ip = {r['ip']: r for r in rows}
        self.assertEqual(json.loads(by_ip['8.8.8.8']['evidence']), [malicious])
        self.assertEqual(json.loads(by_ip['1.1.1.1']['evidence']), [normal])
        self.assertEqual(by_ip['8.8.8.8']['historical'], 1)
        self.assertIn('未确认安全', by_ip['1.1.1.1']['reason'])

    def test_raw_source_spoof_cannot_avoid_ai(self):
        self.put(self.ai_agent, ip='9.9.9.9', spoof={'agent_id': self.local_agent['agentId'],
                 'source_type': 'agent', '_agent_id': self.local_agent['agentId'],
                 'analysisMode': 'local', 'name': 'LovelyLog'})
        self.assertEqual(self.worker.process_once(), 1)
        self.assertEqual(len(self.model.calls), 1)
        row = self.store.db.execute('SELECT provider,agent_id FROM decisions').fetchone()
        self.assertEqual((row['provider'], row['agent_id']), ('deepseek', self.ai_agent['agentId']))

    def test_ai_pause_does_not_starve_local_or_busy_poll_ai_only_backlog(self):
        save_settings(self.root, {'enabled': False, 'batchSize': 2})
        for _ in range(5):
            self.put(self.ai_agent, ip='9.9.9.9')
        self.put()
        self.assertEqual(self.worker.process_once(), 1)
        self.assertEqual(self.model.calls, [])
        self.assertEqual(len(self.store.pending(20)), 5)
        self.assertEqual(self.worker._pending_records(settings(self.root), 1), [])
        self.assertEqual(self.worker.process_once(), 0)
        self.assertTrue(self.worker.public(self.local_agent['agentId'])['enabled'])
        self.assertFalse(self.worker.public()['enabled'])

    def test_no_api_key_still_processes_explicit_local_source(self):
        self.root.joinpath('.env').write_text(
            ('AUTO_BLOCK=true\n' + f"AI_ANALYSIS_MODE=ai\nAI_ENABLED=true\nLOCAL_RULE_AGENT_IDS={self.local_agent['agentId']}\n"), encoding='utf-8')
        self.put(self.ai_agent, ip='9.9.9.9')
        self.put()
        self.assertEqual(self.worker.process_once(), 1)
        self.assertFalse(self.worker.public()['configured'])
        self.assertTrue(self.worker.public(self.local_agent['agentId'])['configured'])
        self.assertEqual(len(self.store.pending(10)), 1)

    def test_source_public_status_and_legacy_global_pause_are_consistent(self):
        scoped = self.worker.public(self.local_agent['agentId'])
        self.assertEqual((scoped['analysisMode'], scoped['autoBlock'], scoped['configured'], scoped['enabled']),
                         ('local', False, True, True))
        self.assertEqual((scoped['platformAnalysisMode'], scoped['platformAutoBlock'], scoped['analysisScope']),
                         ('ai', True, 'agent'))
        self.assertEqual(scoped['scopedAgentId'], self.local_agent['agentId'])
        self.assertEqual(self.worker.public(self.ai_agent['agentId'])['analysisMode'], 'ai')
        self.assertTrue(self.worker.public()['autoBlock'])
        save_settings(self.root, {'analysisMode': 'local', 'enabled': False})
        self.assertFalse(self.worker.public(self.ai_agent['agentId'])['enabled'])
        self.assertTrue(self.worker.public(self.local_agent['agentId'])['enabled'])

    def test_settings_list_roundtrip_signature_and_invalid_values_are_atomic(self):
        initial = settings(self.root)
        ids = [self.local_agent['agentId'], self.ai_agent['agentId']]
        self.assertEqual(local_agent_ids(' first, second,first '), ['first', 'second'])
        saved = save_settings(self.root, {'localAgentIds': ids, 'autoBlock': True})
        self.assertEqual(saved['localAgentIds'], ids)
        self.assertTrue(saved['autoBlock'])
        self.assertNotEqual(model_signature(initial), model_signature(settings(self.root)))
        self.assertEqual(save_settings(self.root, {'localAgentIds': ','.join(ids)})['localAgentIds'], ids)
        before = self.root.joinpath('.env').read_text(encoding='utf-8')
        for invalid in (None, 1, ['valid', 123], 'valid\nAI_ENABLED=false', 'bad/id'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                save_settings(self.root, {'localAgentIds': invalid})
            self.assertEqual(self.root.joinpath('.env').read_text(encoding='utf-8'), before)

    def test_direct_automatic_calls_cannot_block_local_provider_or_local_agent(self):
        self.put()
        self.worker.process_once()
        decision_id = self.store.db.execute('SELECT id FROM decisions').fetchone()[0]
        self.worker.block_decision(decision_id, automatic=True)
        self.assertEqual(self.panel.black, [])
        self.store.db.execute("UPDATE decisions SET provider='deepseek' WHERE id=?", (decision_id,))
        self.store.db.commit()
        self.worker.block_decision(decision_id, automatic=True)
        self.assertEqual(self.panel.black, [])
        self.store.db.execute("UPDATE decisions SET provider='local' WHERE id=?", (decision_id,))
        self.store.db.commit()
        save_settings(self.root, {'localAgentIds': []})
        self.worker.block_decision(decision_id, automatic=True)
        self.assertEqual(self.panel.black, [])
        self.worker.block_decision(decision_id)
        self.assertEqual(len(self.panel.black), 1)
        self.assertTrue(self.panel.black[0]['name'].startswith('manual_'))

    def test_inflight_routing_change_keeps_old_ai_rows_queued_for_local_review(self):
        self.put(self.ai_agent, ip='9.9.9.9')
        original = self.model.analyze
        def changed(events, config):
            save_settings(self.root, {'localAgentIds': [self.local_agent['agentId'], self.ai_agent['agentId']]})
            return original(events, config)
        with patch.object(self.model, 'analyze', side_effect=changed):
            self.assertEqual(self.worker.process_once(), 0)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM decisions').fetchone()[0], 0)
        self.assertEqual(len(self.store.pending(10)), 1)
        self.assertEqual(self.worker.process_once(), 1)
        self.assertEqual(self.store.db.execute('SELECT provider FROM decisions').fetchone()[0], 'local')
        self.assertEqual(len(self.model.calls), 1)

    def test_ai_failure_does_not_cancel_local_review_in_the_same_wave(self):
        self.put()
        self.put(self.ai_agent, ip='9.9.9.9')
        self.model.failure = True
        with self.assertRaises(SecurityError):
            self.worker.process_once()
        row = self.store.db.execute('SELECT provider,state,ip FROM decisions').fetchone()
        self.assertEqual(tuple(row), ('local', 'review', '8.8.8.8'))
        self.assertEqual(len(self.store.pending(10)), 1)


if __name__ == '__main__':
    unittest.main()
