"""Local detection must never call a model or automatically write a blacklist."""
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from clean_rules import CleanRules, RuleBlocker
from deep_analysis import DeepAnalysis
from security import AiWorker, SecurityError, chat_completion, normalized_event, save_settings, settings, with_fallback
from site_rule import SiteVisitRule
from storage import Store
from test_incremental_security import FakeModel, FakePanel


class LocalModeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict('os.environ', {}, clear=True)
        self.env.start()
        self.root.joinpath('.env').write_text(
            'AI_ANALYSIS_MODE=local\nAI_ENABLED=true\nAUTO_BLOCK=true\nAI_FALLBACK_ENABLED=true\n', encoding='utf-8')
        self.store = Store(self.root / 'state.sqlite3')
        self.panel, self.model = FakePanel(), FakeModel()
        self.worker = AiWorker(self.root, self.panel, self.store, self.model)
        self.worker.deepseek = self.model
        self.worker.openai = self.model

    def tearDown(self):
        self.worker.stop()
        self.store.close()
        self.env.stop()
        self.temp.cleanup()

    def put(self, query, ip='8.8.8.8'):
        raw = json.dumps({'time': (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(),
                          'ip': ip, 'method': 'POST', 'uri': '/business/query', 'status': 200,
                          'decoded_body': {'query': query}, 'decode_state': 'plain',
                          'content_type': 'application/json'})
        self.store.append('fixture', {}, 1, 'access.log', [raw])
        return raw

    def test_local_mode_needs_no_keys_and_forces_manual_blocking(self):
        config = settings(self.root)
        self.assertFalse(config['autoBlock'])
        self.assertTrue(self.worker.public()['configured'])
        saved = save_settings(self.root, {'analysisMode': 'local', 'autoBlock': True})
        self.assertFalse(saved['autoBlock'])
        # Returning to AI must not silently restore a previously enabled automatic action.
        restored = save_settings(self.root, {'analysisMode': 'ai', 'fallbackEnabled': False})
        self.assertFalse(restored['autoBlock'])
        save_settings(self.root, {'analysisMode': 'local'})
        with self.assertRaises(ValueError):
            save_settings(self.root, {'analysisMode': 'invalid'})

    def test_local_pending_rows_produce_review_without_any_model_call(self):
        self.put('union select password from users')
        self.put('ordinary business request', ip='1.1.1.1')
        with patch('security.chat_completion', side_effect=AssertionError('paid call')):
            self.assertEqual(self.worker.process_once(), 2)
        self.assertEqual(self.model.calls, [])
        self.assertEqual(self.panel.black, [])
        self.assertEqual(self.store.pending(10), [])
        rows = self.store.db.execute('SELECT provider,model,state,ip FROM decisions ORDER BY id').fetchall()
        self.assertEqual([(r['provider'], r['state']) for r in rows], [('local', 'review'), ('local', 'normal')])
        self.assertEqual(self.worker.performance['requests'], 0)
        self.assertEqual(self.store.ai_usage_today()['requests'], 0)

    def test_explicit_manual_selection_still_blocks_and_auto_selection_does_not(self):
        self.put('union select password from users')
        self.worker.process_once()
        decision_id = self.store.db.execute('SELECT id FROM decisions').fetchone()[0]
        self.worker.block_decision(decision_id, automatic=True)
        self.assertEqual(self.panel.black, [])
        self.worker.block_decision(decision_id)
        self.assertEqual(len(self.panel.black), 1)
        self.assertTrue(self.panel.black[0]['name'].startswith('manual_'))

    def test_local_does_not_bypass_detection_via_old_cleaning_archive_rules(self):
        rules = CleanRules(self.store)
        rules.save({'name': 'archive business path', 'action': 'archive', 'path': '/business/query', 'includeSuspicious': True})
        self.worker.clean_rules = rules
        self.put('../../etc/passwd')
        self.assertEqual(self.worker.process_once(), 1)
        self.assertEqual(self.store.db.execute('SELECT state FROM decisions').fetchone()[0], 'review')

    def test_ai_entry_points_and_other_automatic_origins_are_blocked(self):
        config, paid = settings(self.root), Mock()
        with self.assertRaises(SecurityError):
            with_fallback(config, paid)
        paid.assert_not_called()
        with patch('security.request.build_opener') as opener:
            with self.assertRaises(SecurityError):
                chat_completion(config, [], 20)
            opener.assert_not_called()
        deep = DeepAnalysis(self.root, self.store)
        with patch('deep_analysis.chat_completion') as provider:
            with self.assertRaises(SecurityError):
                deep.chat([], 20)
            provider.assert_not_called()
        for origin in ('DeepSeek', 'CleanRule', 'SiteVisit', 'AFSyslog'):
            with self.subTest(origin=origin), self.assertRaises(SecurityError):
                self.worker.waf.add('8.8.8.8', 'test', origin=origin)
        self.assertEqual(self.panel.calls, [])

    def test_old_mandatory_block_rules_are_suspended_in_local_mode(self):
        rules = CleanRules(self.store)
        rules.save({'name': 'sensitive path', 'action': 'block', 'path': r'/\.env'})
        blocker = RuleBlocker(self.root, self.panel, self.store, self.worker.waf, rules)
        self.store.append('fixture', {}, 1, 'access.log', [
            '8.8.8.8 - - [05/Nov/2026:10:00:00 +0800] "GET /.env HTTP/1.1" 404 0'])
        blocker.scan()
        blocker.process()
        self.assertEqual(self.panel.black, [])
        self.assertEqual(self.store.db.execute('SELECT state FROM rule_block_ips').fetchone()[0], 'pending')
        visit = SiteVisitRule(self.root, self.panel, self.store, self.worker.waf)
        self.store.db.execute('UPDATE site_visit_rule SET enabled=1,source=?', (visit.source,))
        self.assertFalse(visit.active())

    def test_unredacted_local_input_is_never_attached_to_ai_normalization(self):
        raw = self.put('business data')
        record = {'id': 1, 'website': 1, 'raw': raw}
        self.assertNotIn('_localRequestBody', normalized_event(record))
        self.assertNotIn('_localTarget', normalized_event(record))
        local = normalized_event(record, local=True)
        self.assertIn('_localRequestBody', local)
        self.assertIn('_localTarget', local)


if __name__ == '__main__':
    unittest.main()
