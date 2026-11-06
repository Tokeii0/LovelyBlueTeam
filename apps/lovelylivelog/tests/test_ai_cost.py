import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from analysis_batches import compact_events, plan_batches, prompt_payload, prompt_size
from security import SYSTEM_PROMPT, DeepSeek
from storage import Store
from test_deepseek_http import Response

UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.79'


def event(i, ip='8.8.9.176', target=None, status=200, at=1792362617.0):
    return {'id': i, 'website': 7, 'ip': ip, 'time': '19/Oct/2026:06:30:17 +0800', 'recordedAt': at + i, 'method': 'GET',
            'target': target or f'/Dicom/GetPhoneMenuList?n={i}', 'status': status, 'userAgent': UA, 'truncated': False}


class PromptPayloadTests(unittest.TestCase):
    def test_rows_reference_each_user_agent_and_source_once(self):
        from datetime import datetime

        events = [event(i) for i in range(6)] + [event(10, ip='8.8.8.8', target='/.env', status=404)]
        payload, samples = prompt_payload(events)
        self.assertEqual(samples, compact_events(events))  # Evidence is still validated against the same samples.
        self.assertEqual(payload['sources'], ['website 7'])
        first = payload['clients'][0]
        self.assertEqual(first['user_agents'], [UA])
        self.assertEqual(first['rows'][0], ['L1', 0, 'GET', '/Dicom/GetPhoneMenuList?n=0', 200, 1, 0, 0, 0, 0, 0])
        self.assertEqual(payload['clients'][1]['rows'][0][:5], ['L7', 6, 'GET', '/.env', 404])
        self.assertEqual(payload['base_time'], datetime.fromtimestamp(events[0]['recordedAt']).strftime('%Y-%m-%d %H:%M:%S'))
        old = len(json.dumps({'untrusted_access_logs': samples}, ensure_ascii=False))
        self.assertLess(prompt_size(events), old * .5)

    def test_compact_batches_hold_more_ips(self):
        events = [event(i, ip=f'8.8.9.{i}') for i in range(40)]
        self.assertEqual(len(plan_batches(events)), 3)  # 16 IPs per request before
        self.assertEqual(len(plan_batches(events, max_patterns=48, max_ips=24, measure=prompt_size)), 2)

    def test_measured_batches_share_overhead_and_respect_exact_boundary(self):
        events = [event(i, ip=f'8.8.9.{i % 3 + 1}') for i in range(12)]
        for item in events:
            item.update(requestBody={'head': {'timestamp': 1792362617000 + item['id'],
                                             'sys_track_code': f"YQ_1792362617000000_{item['id']:02d}"},
                                     'body': {'value': item['id']}},
                        bodyMeta={'state': 'decoded', 'truncated': False})
        before = json.dumps(events, ensure_ascii=False)
        limit = prompt_size(events)
        batches = plan_batches(events, max_patterns=48, max_ips=24,
                               max_characters=limit, measure=prompt_size)
        self.assertEqual(len(batches), 1)
        self.assertEqual(sorted(e['id'] for e in batches[0]), list(range(12)))
        self.assertEqual(prompt_size(batches[0]), limit)
        self.assertGreater(len(plan_batches(events, max_patterns=48, max_ips=24,
                                            max_characters=limit - 1, measure=prompt_size)), 1)
        self.assertEqual(json.dumps(events, ensure_ascii=False), before)

    def test_measured_batch_limits_preserve_events_sources_and_request_groups(self):
        events = []
        for scope in ('agent recent', 'agent history'):
            for ip in range(3):
                for pattern in range(3):
                    for occurrence in range(2):
                        item = event(len(events), ip=f'8.8.9.{ip + 1}', target=f'/api/{pattern}')
                        item.update(_analysisScope=scope, _sourceKey=scope,
                                    requestBody={'head': {'timestamp': 1792362617000,
                                                         'sys_track_code': 'YQ_1792362617000000_01'},
                                                 'body': {'pattern': pattern}},
                                    bodyMeta={'state': 'decoded', 'truncated': False})
                        events.append(item)
        before = json.dumps(events, ensure_ascii=False)
        for patterns, ips, limit in ((2, 24, 100000), (48, 1, 100000), (48, 24, 2200)):
            with self.subTest(patterns=patterns, ips=ips, characters=limit):
                batches = plan_batches(events, max_patterns=patterns, max_ips=ips,
                                       max_characters=limit, measure=prompt_size)
                self.assertEqual(sorted(e['id'] for batch in batches for e in batch), list(range(len(events))))
                for batch in batches:
                    self.assertEqual(len({e['_analysisScope'] for e in batch}), 1)
                    self.assertLessEqual(len({e['ip'] for e in batch}), ips)
                    self.assertLessEqual(len({e['patternId'] for e in compact_events(batch)}), patterns)
                    self.assertLessEqual(prompt_size(batch), limit)
                    # The two original occurrences remain together, not split to fit a limit.
                    self.assertTrue(all(e['occurrences'] == 2 for e in compact_events(batch)))
        self.assertEqual(json.dumps(events, ensure_ascii=False), before)

    def test_single_oversized_group_is_kept_intact_and_separate(self):
        large = [dict(event(i, target='/large'), requestBody={'value': 'x' * 2000}) for i in (1, 2)]
        small = event(3, target='/small')
        limit = prompt_size([small])
        batches = plan_batches(large + [small], max_characters=limit, measure=prompt_size)
        self.assertEqual(batches, [large, [small]])
        self.assertGreater(prompt_size(batches[0]), limit)
        self.assertEqual(prompt_size(batches[1]), limit)

    def test_system_prompt_is_static_and_describes_the_row_layout(self):
        self.assertIn('row_fields', SYSTEM_PROMPT)
        self.assertIn('evidence_ids 为 []', SYSTEM_PROMPT)


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'state.sqlite3')

    def tearDown(self):
        self.store.close(); self.temp.cleanup()

    def test_provider_usage_is_recorded_per_day(self):
        verdict = {'decisions': [{'ip': '8.8.8.8', 'is_attack': False, 'confidence': .9, 'attack_type': 'none',
                                  'reason': '正常业务访问', 'evidence_ids': []}]}
        usage = {'prompt_tokens': 3000, 'prompt_cache_hit_tokens': 512, 'prompt_cache_miss_tokens': 2488, 'completion_tokens': 40}
        result = {'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps(verdict)}}], 'usage': usage}
        deepseek = DeepSeek(lambda model, data: self.store.add_ai_usage('deepseek', model, data))
        config = {'model': 'deepseek-flash', 'baseUrl': 'https://api.deepseek.com', 'key': 'test-only-key'}
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.return_value = Response(result)
            deepseek.analyze([event(1, ip='8.8.8.8')], config)
            deepseek.analyze([event(2, ip='8.8.8.8')], config)
            body = json.loads(factory.return_value.open.call_args.args[0].data)
        self.assertEqual(body['messages'][0]['content'], SYSTEM_PROMPT)
        self.assertIn('"clients":', body['messages'][1]['content'])
        self.assertEqual(self.store.ai_usage_today(),
                         {'requests': 2, 'prompt': 6000, 'cacheHit': 1024, 'cacheMiss': 4976, 'completion': 80})

    def test_normal_verdict_without_citations_keeps_local_samples(self):
        events = [dict(event(i, ip='8.8.8.8'), id=i) for i in (1, 2, 3)]
        verdict = {'ip': '8.8.8.8', 'is_attack': False, 'confidence': .9, 'attack_type': 'none', 'reason': '正常业务访问',
                   'evidence_ids': []}
        decision_id = self.store.complete_analysis(events, [verdict], 'deepseek', 'deepseek-flash')[0][0]
        stored = self.store.db.execute('SELECT evidence FROM decisions WHERE id=?', (decision_id,)).fetchone()[0]
        self.assertEqual(json.loads(stored), [1, 3])

    def test_compatible_provider_cache_usage_and_missing_fields(self):
        self.store.add_ai_usage('openai', 'fixture', {
            'prompt_tokens': 1000, 'prompt_tokens_details': {'cached_tokens': 640}, 'completion_tokens': 20})
        self.store.add_ai_usage('openai', 'fixture', {'prompt_tokens': 500, 'completion_tokens': 10})
        self.assertEqual(self.store.ai_usage_today(),
                         {'requests': 2, 'prompt': 1500, 'cacheHit': 640, 'cacheMiss': 860, 'completion': 30})

    def test_invalid_usage_does_not_create_impossible_cache_totals(self):
        self.store.add_ai_usage('openai', 'fixture', {
            'prompt_tokens': 100, 'prompt_tokens_details': {'cached_tokens': 200}})
        self.store.add_ai_usage('openai', 'fixture', {
            'prompt_tokens': True, 'prompt_tokens_details': {'cached_tokens': -5}, 'completion_tokens': '20'})
        self.assertEqual(self.store.ai_usage_today(),
                         {'requests': 2, 'prompt': 100, 'cacheHit': 100, 'cacheMiss': 0, 'completion': 0})


if __name__ == '__main__':
    unittest.main()
