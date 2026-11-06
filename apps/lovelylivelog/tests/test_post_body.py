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
from analysis_batches import prompt_payload, request_groups
from hub import Hub
from security import AiWorker, normalized_event
from storage import Store
from test_incremental_security import FakeModel, FakePanel


def post_raw(body=None, ip='8.8.8.8', when=None):
    return json.dumps({'time': when or datetime.now(timezone.utc).isoformat(), 'ip': ip,
                      'method': 'POST', 'uri': '/business/query', 'status': 200,
                      'decoded_body': body or {'body': {'body_content': {'query': 'union select 1', 'patient_id': 'patient-private'}}},
                      'decode_state': 'decrypted', 'body_sha256': 'original-body-fingerprint',
                      'content_type': 'application/json'})


class PostBodyTests(unittest.TestCase):
    def test_normalization_redaction_fingerprint_and_compact_prompt(self):
        event = {'id': 1, 'website': 12, 'raw': post_raw()}
        first = normalized_event(event)
        self.assertEqual(first['method'], 'POST')
        payload, samples = prompt_payload([first])
        self.assertIn('L1', payload['bodies'])
        self.assertNotIn('patient-private', json.dumps(payload))
        self.assertIn('union select 1', json.dumps(payload))
        second = normalized_event({**event, 'id': 2, 'raw': post_raw({'body': {'query': 'normal'}})})
        self.assertEqual(len(request_groups([first, second])), 2)
        third = normalized_event({**event, 'id': 3, 'raw': post_raw({'patient_id': 'different-private'})})
        fourth = normalized_event({**event, 'id': 4, 'raw': post_raw({'patient_id': 'another-private'})})
        self.assertNotEqual(third['_requestFingerprint'], fourth['_requestFingerprint'])
        large = normalized_event({**event, 'raw': post_raw({'query': 'q'*10000})})
        self.assertTrue(large['truncated'])
        self.assertTrue(large['bodyMeta']['truncated'])
        identifiers = normalized_event({**event, 'raw':post_raw({'account_id':'13800138000','card_number':'000000000000000000','auth_code':'auth-private'})})
        for private in ('13800138000','000000000000000000','auth-private'):
            self.assertNotIn(private, json.dumps(identifiers))

    def test_ingest_ai_block_and_scoped_receipts(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict('os.environ', {}, clear=True):
            root = Path(temp)
            root.joinpath('.env').write_text(('AI_ANALYSIS_MODE=ai\n' + 'DEEPSEEK_API_KEY=test-key\nAI_ENABLED=true\nAUTO_BLOCK=true\n'), encoding='utf-8')
            store = Store(root/'state.sqlite3')
            try:
                hub = Hub(store)
                config = hub.register({'name':'LovelyLog fixture', 'platformUrl':'http://127.0.0.1:8788',
                                       'sources':[{'kind':'access.log', 'path':'/site/post.log'}]})
                other = hub.register({'name':'other', 'platformUrl':config['platformUrl'], 'sources':config['sources']})
                events = [{'eventId':f'{i:032x}', 'kind':'access.log', 'source':'/site/post.log',
                           'collectedAt':time.time(), 'raw':post_raw()} for i in [1, 2]]
                self.assertEqual(hub.ingest(config['agentId'], {'events':events})['inserted'], 2)
                self.assertEqual(hub.ingest(config['agentId'], {'events':events})['inserted'], 0)
                with self.assertRaises(ValueError):
                    hub.ingest(config['agentId'], {'events':[{**events[0], 'raw':post_raw({'query':'different'})}]})
                panel, model = FakePanel(), FakeModel()
                worker = AiWorker(root, panel, store, model)
                self.assertEqual(worker.process_once(), 2)
                self.assertIn('union select 1', json.dumps(model.calls))
                self.assertNotIn('patient-private', json.dumps(model.calls))
                self.assertEqual(len(panel.black), 1)
                receipts = hub.verdicts(config['agentId'], {'eventIds':[e['eventId'] for e in events]})['events']
                self.assertTrue(all(r['ai_state']=='analyzed' and r['decision']['state']=='listed' for r in receipts))
                foreign = hub.verdicts(other['agentId'], {'eventIds':[events[0]['eventId']]})['events'][0]
                self.assertEqual(foreign['ai_state'], 'unknown')
                self.assertNotIn('decision', foreign)
                # The same opaque body in an old log remains a historical review, not a new live ban.
                old = {**events[0], 'eventId':'3'*32, 'raw':post_raw(ip='1.1.1.1', when='2020-01-01T00:00:00+00:00')}
                hub.ingest(config['agentId'], {'events':[old]})
                worker.process_once()
                receipt = hub.verdicts(config['agentId'], {'eventIds':[old['eventId']]})['events'][0]
                self.assertEqual(receipt['decision']['historical'], 1)
                self.assertEqual(len(panel.black), 1)
                # Backfill uploaded now must not jump ahead of a live POST already waiting for AI.
                old = {**events[0], 'eventId':'4'*32, 'raw':post_raw(when='2020-01-01T00:00:00+00:00')}
                live = {**events[0], 'eventId':'5'*32, 'raw':post_raw()}
                hub.ingest(config['agentId'], {'events':[old]})
                hub.ingest(config['agentId'], {'events':[live]})
                self.assertEqual(store.pending(1)[0]['raw'], live['raw'])
            finally:
                store.close()


if __name__ == '__main__':
    unittest.main()
