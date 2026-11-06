"""End-to-end result-cache checks with real storage/receipts and fake paid models."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ai_cache import CacheLease
from hub import Hub
from security import AiWorker, save_settings
from storage import Store
from test_incremental_security import FakeModel, FakePanel


class MeteredModel(FakeModel):
    def __init__(self, store, attack=False):
        super().__init__(attack=attack)
        self.store = store

    def analyze(self, events, config):
        result = super().analyze(events, config)
        self.store.add_ai_usage(config['provider'], config['model'],
                                {'prompt_tokens': 100, 'completion_tokens': 10})
        return result


class AiResultCachePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.environment = patch.dict('os.environ', {}, clear=True)
        self.environment.start()
        self.no_http = patch('security.chat_completion', side_effect=AssertionError('Unexpected real model call'))
        self.no_http.start()
        self.root.joinpath('.env').write_text(('AI_ANALYSIS_MODE=ai\n' + 'DEEPSEEK_API_KEY=test-only-primary\nAI_ENABLED=true\n'
                                             'AUTO_BLOCK=false\nAI_BATCH_SIZE=800\n'), encoding='utf-8')
        self.store = Store(self.root / 'state.sqlite3')
        self.hub = Hub(self.store)
        self.agent = self.hub.register({'name': 'LovelyLog cache fixture', 'platformUrl': 'http://127.0.0.1:8788',
                                       'sources': [{'kind': 'access.log', 'path': '/site/post.log'}]})
        self.at, self.counter = time.time(), 0
        self.panel, self.model = FakePanel(), MeteredModel(self.store)
        self.worker = self.make_worker()

    def tearDown(self):
        self.worker.stop()
        self.store.close()
        self.no_http.stop()
        self.environment.stop()
        self.temp.cleanup()

    def make_worker(self):
        worker = AiWorker(self.root, self.panel, self.store, self.model)
        worker.result_cache.clock = lambda: self.at
        return worker

    def put(self, body=None, ip='8.8.8.8', **extra):
        body = body if body is not None else {'body': {'method_code': 'query', 'patient_id': 'patient-a'}}
        raw_body = json.dumps(body, ensure_ascii=False, sort_keys=True)
        raw = {'time': datetime.fromtimestamp(self.at, timezone.utc).isoformat(), 'ip': ip, 'method': 'POST',
               'uri': '/business/query', 'status': 200, 'http_user_agent': 'miniProgram/wx fixture',
               'decoded_body': body, 'decode_state': 'decrypted', 'body_unresolved': 0,
               'body_sha256': hashlib.sha256(raw_body.encode()).hexdigest(), 'content_type': 'application/json', **extra}
        self.counter += 1
        event_id = f'{self.counter:032x}'
        self.hub.ingest(self.agent['agentId'], {'events': [{'eventId': event_id, 'kind': 'access.log',
            'source': '/site/post.log', 'collectedAt': time.time(), 'raw': json.dumps(raw, ensure_ascii=False)}]})
        return event_id

    def receipt(self, event_id):
        return self.hub.verdicts(self.agent['agentId'], {'eventIds': [event_id]})['events'][0]

    def test_repeat_in_later_wave_reuses_result_and_binds_new_ids_and_receipts(self):
        first = self.put()
        self.assertEqual(self.worker.process_once(), 1)
        first_receipt = self.receipt(first)
        self.at += 10
        second = self.put()
        self.assertEqual(self.worker.process_once(), 1)
        self.assertEqual(len(self.model.calls), 1)
        current = self.receipt(second)
        self.assertEqual(current['ai_state'], 'analyzed')
        self.assertEqual(current['decision']['state'], 'normal')
        self.assertTrue(current['decision']['cited'])
        self.assertNotEqual(first_receipt['decision']['id'], current['decision']['id'])
        self.assertEqual(self.receipt(first)['decision']['id'], first_receipt['decision']['id'])
        source_id = self.store.db.execute('SELECT id FROM agent_events WHERE event_id=?', (second,)).fetchone()[0]
        evidence = self.store.db.execute('SELECT evidence FROM decisions WHERE id=?', (current['decision']['id'],)).fetchone()[0]
        self.assertEqual(json.loads(evidence), [-source_id])
        self.assertEqual(self.store.ai_usage_today()['requests'], 1)
        self.assertEqual(self.store.ai_cache_usage_today(), {'hits': 1, 'rows': 1})
        self.assertEqual(self.worker.performance['requests'], 0)

    def test_cache_survives_store_and_worker_restart(self):
        self.put()
        self.worker.process_once()
        self.worker.stop()
        self.store.close()
        self.store = Store(self.root / 'state.sqlite3')
        self.hub = Hub(self.store)
        self.model.store = self.store
        self.worker = self.make_worker()
        self.at += 10
        new = self.put()
        self.assertEqual(self.worker.process_once(), 1)
        self.assertEqual(len(self.model.calls), 1)
        self.assertEqual(self.receipt(new)['ai_state'], 'analyzed')
        self.assertEqual(self.store.ai_usage_today()['requests'], 1)
        self.assertEqual(self.store.ai_cache_usage_today()['hits'], 1)

    def test_changed_original_payload_cannot_hide_behind_identical_redaction(self):
        self.put()
        self.worker.process_once()
        self.at += 10
        self.put({'body': {'method_code': 'query', 'patient_id': 'patient-b'}})
        self.worker.process_once()
        self.assertEqual(len(self.model.calls), 2)
        self.assertEqual(self.model.calls[0][0]['requestBody'], self.model.calls[1][0]['requestBody'])
        self.assertNotEqual(self.model.calls[0][0]['_requestFingerprint'], self.model.calls[1][0]['_requestFingerprint'])
        self.assertEqual(self.store.ai_cache_usage_today()['hits'], 0)

    def test_rapid_repeat_requires_new_model_judgment(self):
        self.put()
        self.worker.process_once()
        self.at += 1
        self.put()
        self.worker.process_once()
        self.assertEqual(len(self.model.calls), 2)
        self.assertEqual(self.store.ai_cache_usage_today()['hits'], 0)

    def test_mixed_ip_batch_sends_only_uncached_ip_and_commits_both(self):
        self.put()
        self.worker.process_once()
        self.at += 10
        cached, fresh = self.put(), self.put(ip='1.1.1.1')
        self.assertEqual(self.worker.process_once(), 2)
        self.assertEqual(len(self.model.calls), 2)
        self.assertEqual({row['ip'] for row in self.model.calls[-1]}, {'1.1.1.1'})
        for event_id in (cached, fresh):
            self.assertEqual(self.receipt(event_id)['decision']['state'], 'normal')
            self.assertTrue(self.receipt(event_id)['decision']['cited'])
        self.assertEqual(self.worker.performance['requests'], 1)
        self.assertEqual(self.worker.performance['cacheHits'], 1)
        self.assertEqual(self.store.ai_cache_usage_today(), {'hits': 1, 'rows': 1})

    def test_new_pattern_for_same_ip_preserves_full_context_for_model(self):
        self.put()
        self.worker.process_once()
        self.at += 10
        self.put()
        self.put({'body': {'method_code': 'different-operation'}})
        self.assertEqual(self.worker.process_once(), 2)
        self.assertEqual(len(self.model.calls[-1]), 2)
        self.assertEqual(self.store.ai_cache_usage_today()['hits'], 0)

    def test_attack_verdict_is_never_reused(self):
        self.model.attack = True
        self.put()
        self.worker.process_once()
        self.at += 10
        self.put()
        self.worker.process_once()
        self.assertEqual(len(self.model.calls), 2)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM ai_result_cache').fetchone()[0], 0)
        self.assertEqual(self.store.ai_cache_usage_today()['hits'], 0)
        self.assertEqual(self.panel.black, [])

    def test_incomplete_or_truncated_body_never_enters_result_cache(self):
        for extra in ({'decode_state': 'encrypted'}, {'body_unresolved': 1}, {'body_truncated': True}):
            self.put(**extra)
            self.worker.process_once()
            self.at += 10
            self.put(**extra)
            self.worker.process_once()
            self.at += 10
        self.assertEqual(len(self.model.calls), 6)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM ai_result_cache').fetchone()[0], 0)

    def test_fallback_cache_does_not_pollute_primary_route(self):
        save_settings(self.root, {'fallbackEnabled': True, 'fallbackProvider': 'openai',
            'fallbackKey': 'test-only-backup', 'fallbackBaseUrl': 'https://backup.example/v1',
            'fallbackModel': 'backup-model'})
        backup = MeteredModel(self.store)
        self.worker.openai = backup
        self.model.failure = True
        self.put()
        self.worker.process_once()
        self.assertEqual((len(self.model.calls), len(backup.calls)), (1, 1))
        self.at += 10
        fallback_event = self.put()
        self.worker.process_once()
        self.assertEqual((len(self.model.calls), len(backup.calls)), (2, 1))
        self.assertEqual(self.receipt(fallback_event)['decision']['model'], 'backup-model')
        self.assertEqual(self.worker.performance['requests'], 1)
        self.model.failure = False
        self.at += 10
        primary_event = self.put()
        self.worker.process_once()
        self.assertEqual((len(self.model.calls), len(backup.calls)), (3, 1))
        self.assertEqual(self.receipt(primary_event)['decision']['provider'], 'deepseek')
        self.at += 10
        self.put()
        self.worker.process_once()
        self.assertEqual((len(self.model.calls), len(backup.calls)), (3, 1))
        self.assertEqual(self.store.ai_usage_today()['requests'], 2)
        self.assertEqual(self.store.ai_cache_usage_today()['hits'], 2)

    def test_cache_wait_timeout_keeps_pending_and_never_tries_paid_fallback(self):
        save_settings(self.root, {'fallbackEnabled': True, 'fallbackProvider': 'openai',
            'fallbackKey': 'test-only-backup', 'fallbackBaseUrl': 'https://backup.example/v1',
            'fallbackModel': 'backup-model'})
        backup = MeteredModel(self.store)
        self.worker.openai = backup
        pending = self.put()
        with patch.object(self.worker.result_cache, 'acquire', side_effect=lambda item: CacheLease(item, 'timeout')):
            with self.assertRaises(TimeoutError):
                self.worker.process_once()
        self.assertEqual(self.model.calls, [])
        self.assertEqual(backup.calls, [])
        self.assertEqual(self.receipt(pending)['ai_state'], 'pending')
        self.assertNotIn('decision', self.receipt(pending))
        self.assertEqual(self.worker.performance['requests'], 0)
        self.assertEqual(self.store.ai_usage_today()['requests'], 0)

    def test_cache_maintenance_failure_does_not_replay_already_paid_judgment(self):
        event_id = self.put()
        with patch.object(self.worker.result_cache, 'write', side_effect=OSError('Cache storage unavailable')):
            self.assertEqual(self.worker.process_once(), 1)
        self.assertEqual(self.receipt(event_id)['ai_state'], 'analyzed')
        self.assertEqual(self.worker.process_once(), 0)
        self.assertEqual(len(self.model.calls), 1)
        self.assertEqual(self.store.ai_usage_today()['requests'], 1)


if __name__ == '__main__':
    unittest.main()
