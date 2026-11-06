import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib import error

from analysis_batches import compact_events, plan_batches, request_groups
from jev import Jev, CRITERIA, ENDPOINT
from security import AiWorker, DeepSeek, SecurityError, normalized_event, save_settings, settings
from storage import Store
from test_incremental_security import FakeModel, FakePanel, access


class Response:
    def __init__(self, value):
        self.data = json.dumps(value).encode()
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, *args): return self.data


def event(index, target='/health', ip='8.8.8.8'):
    return normalized_event({'id': index, 'website': 1, 'raw': access(ip=ip, path=target)})


def answer_for(body, scores=None, category='none', confidence=.99):
    answers = {}
    for name, question in body['questions'].items():
        if question['type'] == 'noul':
            answers[name] = {'type': 'noul', 'noul': (scores or {}).get(name, .01)}
        else:
            probabilities = {key: 0 for key in CRITERIA}
            probabilities[category] = 1
            answers[name] = {'type': 'choice', 'choice': category, 'confidence': confidence,
                             'probabilities': probabilities}
    return {'model': 'typesafe/jev-1.13-20260917', 'answers': answers,
            'usage': {'input_tokens': 100, 'output_tokens': 10, 'cost': .0000042}}


class AnalysisSpeedJevTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.joinpath('.env').write_text(
            ('AI_ANALYSIS_MODE=ai\n' + 'PANEL_API_KEY=panel-fixture\nDEEPSEEK_API_KEY=deepseek-fixture\n'
            'AI_ENABLED=true\nAUTO_BLOCK=true\nAI_BATCH_SIZE=500\nAI_CONCURRENCY=4\n'), encoding='utf-8')
        self.env = patch.dict('os.environ', {}, clear=True); self.env.start()
        self.store = Store(self.root / 'state.sqlite3')
        self.panel = FakePanel()
        self.model = FakeModel(attack=False)
        self.worker = AiWorker(self.root, self.panel, self.store, self.model)

    def tearDown(self):
        self.worker.stop()
        for thread in (self.worker.thread, self.worker.health_thread):
            if thread: thread.join(3)
        self.store.close(); self.env.stop(); self.temp.cleanup()

    def put(self, lines):
        self.store.append('fixture', {}, 1, 'access.log', lines)

    def test_identical_requests_keep_counts_and_first_last_real_ids(self):
        events = [event(i) for i in range(1, 1001)]
        compact = compact_events(events)
        self.assertEqual(len(compact), 2)
        self.assertEqual([e['id'] for e in compact], [1, 1000])
        self.assertEqual(compact[0]['occurrences'], 1000)
        self.assertNotIn('_requestFingerprint', json.dumps(compact))
        self.assertEqual(len(plan_batches(events)), 1)

    def test_redacted_or_truncated_different_payloads_are_never_merged(self):
        hidden = [event(1, '/api?token=one'), event(2, '/api?token=two')]
        self.assertEqual(hidden[0]['target'], hidden[1]['target'])
        self.assertEqual(len(request_groups(hidden)), 2)
        long = [event(3, '/' + 'a' * 1700 + 'one'), event(4, '/' + 'a' * 1700 + 'two')]
        self.assertEqual(long[0]['target'], long[1]['target'])
        self.assertEqual(len(request_groups(long)), 2)

    def test_deepseek_cannot_invent_an_evidence_id_hidden_by_aggregation(self):
        events = [event(1), event(2), event(3)]
        output = {'decisions': [{'ip': '8.8.8.8', 'is_attack': True, 'confidence': .99,
                                'attack_type': 'scanner', 'reason': 'fixture', 'evidence_ids': ['L1', 'L3']}]}
        response = {'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps(output)}}]}
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.return_value = Response(response)
            with self.assertRaises(SecurityError): DeepSeek().analyze(events, settings(self.root))

    def test_bounded_batches_cover_every_input_without_duplicate_or_sampling_loss(self):
        events = [event(i + 1, f'/path/{i % 170}', ip='8.8.8.' + str(i % 20 + 1)) for i in range(1200)]
        batches = plan_batches(events)
        self.assertEqual(sorted(e['id'] for b in batches for e in b), list(range(1, 1201)))
        for batch in batches:
            self.assertLessEqual(len(request_groups(batch)), 32)
            self.assertLessEqual(len({e['ip'] for e in batch}), 16)

    def test_concurrency_is_bounded_and_success_marks_all_original_rows(self):
        save_settings(self.root, {'concurrency': 3})
        self.put([access(path=f'/path/{i}') for i in range(120)])
        lock = threading.Lock()
        active, maximum = 0, 0
        original = self.model.analyze
        def slow(events, config):
            nonlocal active, maximum
            with lock:
                active += 1; maximum = max(maximum, active)
            try:
                time.sleep(.05)
                return original(events, config)
            finally:
                with lock: active -= 1
        self.model.analyze = slow
        self.assertEqual(self.worker.process_once(), 120)
        self.assertGreaterEqual(maximum, 2)
        self.assertLessEqual(maximum, 3)
        self.assertEqual(self.store.dashboard()['summary']['pending'], 0)
        self.assertEqual(self.store.dashboard()['summary']['analyzed'], 120)
        self.assertEqual(sum(d['record_count'] for d in self.store.dashboard()['decisions']), 120)

    def test_completed_batches_survive_other_batch_failure_and_are_not_replayed(self):
        save_settings(self.root, {'concurrency': 3})
        self.put([access(path=f'/path/{i}') for i in range(96)])
        barrier = threading.Barrier(3)
        original = self.model.analyze
        def partial(events, config):
            barrier.wait(timeout=2)
            if events[0]['id'] == 1:
                raise SecurityError('fixture failure')
            return original(events, config)
        self.model.analyze = partial
        with self.assertRaises(SecurityError): self.worker.process_once()
        before = self.store.dashboard()['summary']['analyzed']
        self.assertEqual(before, 64)
        self.model.analyze = original
        self.assertEqual(self.worker.process_once(), 32)
        self.assertEqual(self.store.dashboard()['summary']['analyzed'], 96)

    def test_backlog_drains_without_waiting_the_configured_idle_interval(self):
        save_settings(self.root, {'batchSize': 25, 'interval': 300, 'concurrency': 1})
        self.put([access()] * 100)
        original = self.model.analyze
        def finish(events, config):
            output = original(events, config)
            if len(self.model.calls) == 4: self.worker.stop()
            return output
        self.model.analyze = finish
        began = time.monotonic()
        self.worker.start(); self.worker.thread.join(timeout=3)
        self.assertFalse(self.worker.thread.is_alive())
        self.assertLess(time.monotonic() - began, 3)
        self.assertEqual(self.store.dashboard()['summary']['analyzed'], 100)

    def test_skipped_rows_are_visible_as_skipped_and_raw_logs_remain(self):
        self.put([access(time_text='01/Jan/2020:12:00:00 +0000'), 'unparseable raw log'])
        self.assertEqual(self.worker.process_once(), 0)
        data = self.store.dashboard()
        self.assertEqual(data['summary']['analyzed'], 0)
        self.assertEqual(data['summary']['skipped'], 2)
        self.assertEqual(data['summary']['expired'], 1)
        self.assertEqual(data['summary']['unparsed'], 1)
        self.assertEqual(len(self.store.feed(1, 'access.log', None, 200)['events']), 2)

    def test_switching_models_mid_request_cannot_start_an_automatic_block(self):
        self.put([access(), access()])
        model = FakeModel(attack=True)
        def change(events, config):
            output = model.analyze(events, config)
            save_settings(self.root, {'provider': 'jev', 'key': 'router-fixture', 'model': 'typesafe/jev-1.13'})
            return output
        self.model.analyze = change
        self.worker.process_once()
        self.assertEqual(self.panel.black, [])
        self.assertEqual(self.store.dashboard()['decisions'][0]['provider'], 'deepseek')

    def test_provider_keys_are_separate_preserved_and_never_returned(self):
        public = save_settings(self.root, {'provider': 'jev', 'key': 'router-fixture', 'model': 'typesafe/jev-1.13',
                                           'batchSize': 1000, 'concurrency': 4, 'interval': 2})
        self.assertEqual(settings(self.root)['key'], 'router-fixture')
        self.assertTrue(public['jevConfigured'])
        for key in ('router-fixture', 'deepseek-fixture', 'panel-fixture'):
            self.assertNotIn(key, json.dumps(public))
            self.assertNotIn(key, json.dumps(self.worker.public()))
        save_settings(self.root, {'provider': 'deepseek', 'key': '', 'model': 'deepseek-flash'})
        self.assertEqual(settings(self.root)['key'], 'deepseek-fixture')
        save_settings(self.root, {'provider': 'jev', 'key': ''})
        self.assertEqual(settings(self.root)['key'], 'router-fixture')

    def test_invalid_speed_and_provider_settings_do_not_overwrite_the_config(self):
        original = self.root.joinpath('.env').read_bytes()
        for body in ({'provider': 'other'}, {'concurrency': 99}, {'interval': 0}, {'batchSize': 0},
                     {'batchSize': True}, {'model': 'model\nPANEL_API_KEY=bad'}):
            with self.subTest(body=body), self.assertRaises(ValueError): save_settings(self.root, body)
            self.assertEqual(self.root.joinpath('.env').read_bytes(), original)

    def jev_config(self):
        save_settings(self.root, {'provider': 'jev', 'key': 'router-fixture', 'model': 'typesafe/jev-1.13'})
        return settings(self.root)

    def test_jev_uses_the_decisions_endpoint_and_typed_pattern_questions(self):
        config = self.jev_config(); events = [event(1), event(2)]
        body, _ = Jev.build(events, config)
        with patch('jev.request.build_opener') as factory:
            factory.return_value.open.return_value = Response(answer_for(body))
            verdicts = Jev().analyze(events, config)
            req = factory.return_value.open.call_args.args[0]
            sent = json.loads(req.data)
            self.assertEqual(req.full_url, ENDPOINT)
            self.assertEqual(req.get_header('Authorization'), 'Bearer router-fixture')
            self.assertNotIn('router-fixture', json.dumps(sent))
            self.assertNotIn('_requestFingerprint', json.dumps(sent))
            self.assertNotIn('messages', sent)
            self.assertEqual(sent['state']['patterns']['p0']['occurrences'], 2)
            self.assertEqual(sent['questions']['attack_p0']['type'], 'noul')
            self.assertEqual(sent['questions']['category_g0']['type'], 'choice')
            self.assertFalse(verdicts[0]['is_attack'])

    def test_jev_evidence_excludes_normal_patterns_even_for_the_same_ip(self):
        config = self.jev_config()
        events = [event(1, '/.env'), event(2, '/health'), event(3, '/health')]
        body, originals = Jev.build(events, config)
        output = Jev.decode(answer_for(body, {'attack_p0': .99}, 'scanner'), body, originals, events)
        self.assertTrue(output[0]['is_attack'])
        self.assertEqual(output[0]['evidence_ids'], [1])
        self.assertEqual(output[0]['confidence'], .99)

    def test_jev_single_attack_cannot_borrow_benign_rows_to_automatically_block(self):
        self.jev_config()
        self.worker.model = None
        self.put([access(path='/.env'), access(path='/health'), access(path='/health')])
        def respond(req, **kwargs):
            body = json.loads(req.data)
            return Response(answer_for(body, {'attack_p0': .99}, 'scanner'))
        with patch('jev.request.build_opener') as factory:
            factory.return_value.open.side_effect = respond
            self.worker.process_once()
        self.assertEqual(self.panel.black, [])
        self.assertEqual(self.store.dashboard()['decisions'][0]['state'], 'review')

    def test_jev_two_real_attack_rows_can_use_existing_verified_waf_flow(self):
        self.jev_config()
        self.worker.model = None
        self.put([access(), access()])
        def respond(req, **kwargs):
            body = json.loads(req.data)
            return Response(answer_for(body, {'attack_p0': .99}, 'scanner'))
        with patch('jev.request.build_opener') as factory:
            factory.return_value.open.side_effect = respond
            self.worker.process_once()
        self.assertEqual(len(self.panel.black), 1)
        self.assertEqual(self.store.dashboard()['decisions'][0]['state'], 'listed')

    def test_jev_missing_confidence_or_distribution_stays_for_review(self):
        config = self.jev_config(); events = [event(1), event(2)]
        body, originals = Jev.build(events, config)
        for field in ('confidence', 'probabilities'):
            output = answer_for(body, {'attack_p0': .99}, 'scanner')
            output['answers']['category_g0'].pop(field)
            verdict = Jev.decode(output, body, originals, events)[0]
            self.assertTrue(verdict['is_attack'])
            self.assertEqual(verdict['confidence'], 0)

    def test_jev_inconsistent_category_cannot_trigger_automatic_action(self):
        config = self.jev_config(); events = [event(1), event(2)]
        body, originals = Jev.build(events, config)
        verdict = Jev.decode(answer_for(body, {'attack_p0': .99}, 'none'), body, originals, events)[0]
        self.assertEqual(verdict['confidence'], 0)
        self.assertEqual(verdict['attack_type'], 'other')

    def test_invalid_or_missing_jev_answers_are_rejected_not_treated_as_normal(self):
        config = self.jev_config(); events = [event(1), event(2)]
        body, _ = Jev.build(events, config)
        mutations = [lambda v: v['answers'].pop('attack_p0'),
                     lambda v: v['answers']['attack_p0'].update(noul=1.5),
                     lambda v: v['answers']['attack_p0'].update(noul=True),
                     lambda v: v['answers']['attack_p0'].update(noul=float('nan')),
                     lambda v: v['answers']['category_g0'].update(choice='ban-everyone'),
                     lambda v: v['answers']['category_g0'].update(confidence='high')]
        for mutate in mutations:
            output = answer_for(body); mutate(output)
            with patch('jev.request.build_opener') as factory:
                factory.return_value.open.return_value = Response(output)
                with self.assertRaises(SecurityError): Jev().analyze(events, config)

    def test_jev_http_errors_do_not_expose_provider_text_or_credentials(self):
        config = self.jev_config(); events = [event(1)]
        for code in (401, 402, 429, 503):
            with patch('jev.request.build_opener') as factory:
                factory.return_value.open.side_effect = error.HTTPError('url', code, 'private-provider-detail', {}, None)
                with self.assertRaises(SecurityError) as raised: Jev().analyze(events, config)
                self.assertNotIn('private-provider-detail', str(raised.exception))
                self.assertNotIn('router-fixture', str(raised.exception))


if __name__ == '__main__': unittest.main()
