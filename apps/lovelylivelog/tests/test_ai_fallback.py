import json
from http.client import IncompleteRead
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib import error

from deep_analysis import DeepAnalysis
from security import (AiWorker, DeepSeek, SecurityError, model_configs, normalized_event,
                      public_settings, save_settings, settings, with_fallback)
from storage import Store
from test_deepseek_http import Response
from test_incremental_security import FakePanel, access


class AiFallbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict('os.environ', {}, clear=True)
        self.env.start()
        self.root.joinpath('.env').write_text(('AI_ANALYSIS_MODE=ai\nAUTO_BLOCK=true\n' + 'PANEL_API_KEY=panel-secret\nDEEPSEEK_API_KEY=primary-secret\n'), encoding='utf-8')
        self.store = Store(self.root / 'state.sqlite3')
        self.panel = FakePanel()
        self.worker = AiWorker(self.root, self.panel, self.store)
        self.events = [normalized_event({'id': i, 'website': 1, 'raw': access(path=path)})
                       for i, path in ((1, '/.env'), (2, '/wp-admin'))]

    def tearDown(self):
        self.worker.stop()
        self.store.close()
        self.env.stop()
        self.temp.cleanup()

    def configure_fallback(self, **changes):
        return save_settings(self.root, {'fallbackEnabled': True, 'fallbackProvider': 'openai',
            'fallbackKey': 'backup-secret', 'fallbackBaseUrl': 'https://backup.example/v1',
            'fallbackModel': 'backup-model', **changes})

    def put(self):
        self.store.append('fixture', {}, 1, 'access.log', [access(path='/.env'), access(path='/wp-admin')])

    @staticmethod
    def response(ids=('L1', 'L2'), finish='stop', **extra):
        verdict = {'decisions': [{'ip': '8.8.8.8', 'is_attack': True, 'confidence': .99,
            'attack_type': 'scanner', 'reason': '扫描敏感路径', 'evidence_ids': list(ids)}]}
        return Response({'choices': [{'finish_reason': finish, 'message': {'content': json.dumps(verdict)}}], **extra})

    def test_custom_api_uses_its_own_endpoint_key_and_model_without_deepseek_options(self):
        save_settings(self.root, {'provider': 'openai', 'baseUrl': 'https://primary.example/v1/chat/completions/',
                                 'key': 'custom-secret', 'model': 'vendor/model-v2'})
        self.put()
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.return_value = self.response()
            self.assertEqual(self.worker.process_once(), 2)
            req = factory.return_value.open.call_args.args[0]
        body = json.loads(req.data)
        self.assertEqual(req.full_url, 'https://primary.example/v1/chat/completions')
        self.assertEqual(req.get_header('Authorization'), 'Bearer custom-secret')
        self.assertEqual(body['model'], 'vendor/model-v2')
        self.assertNotIn('thinking', body)
        self.assertEqual(body['response_format'], {'type': 'json_object'})
        self.assertEqual(self.store.dashboard()['decisions'][0]['provider'], 'openai')

    def test_primary_and_fallback_keys_remain_separate_and_are_redacted(self):
        self.configure_fallback()
        save_settings(self.root, {'provider': 'openai', 'key': 'custom-secret', 'model': 'custom-model'})
        save_settings(self.root, {'provider': 'deepseek', 'key': '', 'fallbackKey': ''})
        config = settings(self.root)
        self.assertEqual(config['key'], 'primary-secret')
        self.assertEqual(config['openaiKey'], 'custom-secret')
        self.assertEqual(config['fallbackKey'], 'backup-secret')
        for public in (public_settings(config), self.worker.public()):
            for secret in ('primary-secret', 'backup-secret', 'custom-secret', 'panel-secret'):
                self.assertNotIn(secret, json.dumps(public))
            self.assertFalse(any(key == 'key' or key.endswith('Key') for key in public))

    def test_invalid_settings_do_not_replace_the_file(self):
        for body in ({'baseUrl': 'https://user:secret@example.com/v1'}, {'baseUrl': 'https://example.com/v1?key=secret'},
                     {'baseUrl': 'https://example.com:bad'}, {'baseUrl': 'http://public.example/v1'},
                     {'baseUrl': 'https://example.com/\nAI_ENABLED=false'}, {'baseUrl': []},
                     {'fallbackEnabled': 'true'}, {'fallbackProvider': 'unknown'},
                     {'fallbackModel': 'bad\nAUTO_BLOCK=true'}, {'fallbackKey': 'bad key'},
                     {'fallbackEnabled': True}, {'provider': 'openai', 'model': ''}):
            original = self.root.joinpath('.env').read_bytes()
            with self.subTest(body=body), self.assertRaises(ValueError):
                save_settings(self.root, body)
            self.assertEqual(self.root.joinpath('.env').read_bytes(), original)
        save_settings(self.root, {'provider': 'openai', 'model': 'local-model', 'baseUrl': 'http://127.0.0.1:11434/v1'})
        self.assertEqual(settings(self.root)['baseUrl'], 'http://127.0.0.1:11434/v1')

    def test_new_settings_honor_environment_overrides_and_dynamic_updates(self):
        with patch.dict('os.environ', {'AI_PROVIDER': 'openai', 'OPENAI_API_KEY': 'environment-secret',
                'OPENAI_MODEL': 'env-model', 'OPENAI_BASE_URL': 'https://env.example/v1',
                'AI_FALLBACK_ENABLED': 'true', 'AI_FALLBACK_API_KEY': 'env-backup-secret',
                'AI_FALLBACK_MODEL': 'env-backup-model'}):
            config = settings(self.root)
            self.assertEqual((config['provider'], config['model'], config['key']), ('openai', 'env-model', 'environment-secret'))
            self.assertEqual(config['fallbackKey'], 'env-backup-secret')
            public = save_settings(self.root, {'model': 'updated-model', 'fallbackModel': 'updated-backup'})
            self.assertEqual(settings(self.root)['model'], 'updated-model')
            self.assertEqual(public['fallbackModel'], 'updated-backup')
            self.assertNotIn('environment-secret', json.dumps(public))

    def test_enabled_fallback_requires_its_own_key_and_model(self):
        for body in ({'fallbackEnabled': True, 'fallbackModel': 'backup-model'},
                     {'fallbackEnabled': True, 'fallbackKey': 'backup-secret'}):
            with self.subTest(body=body), self.assertRaises(ValueError):
                save_settings(self.root, body)
        self.assertFalse(settings(self.root)['fallbackEnabled'])

    def test_primary_success_never_calls_fallback(self):
        self.configure_fallback()
        self.put()
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.return_value = self.response()
            self.assertEqual(self.worker.process_once(), 2)
            self.assertEqual(factory.return_value.open.call_count, 1)
        self.assertEqual(self.store.dashboard()['decisions'][0]['model'], 'deepseek-flash')
        self.assertIsNone(self.worker.last_fallback)

    def test_transport_and_invalid_output_failures_try_backup_once(self):
        self.configure_fallback()
        failures = [error.HTTPError('url', status, 'raw-provider-secret', {}, None) for status in (401, 402, 429, 503)]
        failures += [error.URLError('raw-provider-secret'), TimeoutError(), IncompleteRead(b'partial-response'),
                     Response({'choices': []}), Response({'choices': [{'finish_reason': 'stop', 'message': {'content': 'not-json'}}]}),
                     self.response(finish='length'), self.response(ids=('L1', 'L9'))]
        config = settings(self.root)
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), patch('security.request.build_opener') as factory:
                factory.return_value.open.side_effect = [failure, self.response()]
                result, used = with_fallback(config, lambda route: DeepSeek().analyze(self.events, route))
                requests = [call.args[0] for call in factory.return_value.open.call_args_list]
            self.assertTrue(result[0]['is_attack'])
            self.assertTrue(used['fallback'])
            self.assertEqual([req.get_header('Authorization') for req in requests], ['Bearer primary-secret', 'Bearer backup-secret'])
            self.assertEqual(requests[1].full_url, 'https://backup.example/v1/chat/completions')
            self.assertNotIn('thinking', json.loads(requests[1].data))

    def test_backup_result_is_persisted_with_actual_provider_model_and_usage(self):
        self.configure_fallback()
        self.put()
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.side_effect = [self.response(ids=('L9',), usage={'prompt_tokens': 50}),
                self.response(usage={'prompt_tokens': 70, 'completion_tokens': 10})]
            self.assertEqual(self.worker.process_once(), 2)
        decision = self.store.dashboard()['decisions'][0]
        self.assertEqual((decision['provider'], decision['model']), ('openai', 'backup-model'))
        self.assertEqual(decision['state'], 'listed')
        self.assertEqual(len(self.panel.black), 1)
        self.assertEqual(self.store.ai_usage_today()['requests'], 2)
        self.assertEqual(self.store.ai_usage_today()['prompt'], 120)
        self.assertEqual(self.worker.public()['lastFallback']['model'], 'backup-model')
        self.assertEqual(self.worker.public()['performance']['requests'], 2)

    def test_both_failures_leave_logs_pending_without_blacklisting(self):
        self.configure_fallback()
        self.put()
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.side_effect = [TimeoutError(), self.response(ids=('L9',))]
            with self.assertRaisesRegex(SecurityError, '主模型.*备用模型'):
                self.worker.process_once()
            self.assertEqual(factory.return_value.open.call_count, 2)
        dashboard = self.store.dashboard()
        self.assertEqual(dashboard['summary']['pending'], 2)
        self.assertEqual(dashboard['summary']['analyzed'], 0)
        self.assertEqual(dashboard['decisions'], [])
        self.assertEqual(self.panel.black, [])

    def test_disabled_fallback_keeps_existing_retry_behavior(self):
        self.configure_fallback(fallbackEnabled=False)
        self.put()
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.side_effect = error.HTTPError('url', 429, 'raw-provider-secret', {}, None)
            with self.assertRaisesRegex(SecurityError, '限流') as raised:
                self.worker.process_once()
            self.assertEqual(factory.return_value.open.call_count, 1)
        self.assertNotIn('raw-provider-secret', str(raised.exception))
        self.assertEqual(len(self.store.pending(10)), 2)

    def test_missing_primary_key_can_use_configured_backup(self):
        self.root.joinpath('.env').write_text('AI_ANALYSIS_MODE=ai\nAUTO_BLOCK=false\n', encoding='utf-8')
        self.configure_fallback()
        self.assertTrue(self.worker.public()['configured'])
        self.assertFalse(self.worker.public()['primaryConfigured'])
        self.put()
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.return_value = self.response()
            self.assertEqual(self.worker.process_once(), 2)
            self.assertEqual(factory.return_value.open.call_count, 1)
        self.assertEqual(self.store.dashboard()['decisions'][0]['model'], 'backup-model')

    def test_jev_failure_can_use_chat_backup(self):
        save_settings(self.root, {'provider': 'jev', 'key': 'jev-secret'})
        self.configure_fallback()
        self.put()
        with patch.object(self.worker.jev, 'analyze', side_effect=SecurityError('Jev 暂不可用')), \
                patch('security.request.build_opener') as factory:
            factory.return_value.open.return_value = self.response()
            self.assertEqual(self.worker.process_once(), 2)
        self.assertEqual(self.store.dashboard()['decisions'][0]['provider'], 'openai')

    def test_same_provider_backup_can_use_an_independent_model_and_key(self):
        self.configure_fallback(fallbackProvider='deepseek', fallbackBaseUrl='https://api.deepseek.com', fallbackModel='deepseek-pro')
        self.put()
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.side_effect = [TimeoutError(), self.response()]
            self.assertEqual(self.worker.process_once(), 2)
            req = factory.return_value.open.call_args.args[0]
        self.assertEqual(json.loads(req.data)['thinking'], {'type': 'disabled'})
        self.assertEqual(req.get_header('Authorization'), 'Bearer backup-secret')
        self.assertEqual(self.store.dashboard()['decisions'][0]['model'], 'deepseek-pro')

    def test_pause_during_primary_failure_prevents_starting_backup(self):
        self.configure_fallback()
        self.put()
        def pause(*args, **kwargs):
            save_settings(self.root, {'enabled': False})
            raise SecurityError('主模型超时')
        with patch.object(self.worker.deepseek, 'analyze', side_effect=pause), \
                patch.object(self.worker.openai, 'analyze') as backup:
            self.assertEqual(self.worker.process_once(), 0)
            backup.assert_not_called()
        self.assertEqual(len(self.store.pending(10)), 2)

    def test_config_change_during_backup_keeps_history_but_prevents_auto_block(self):
        self.configure_fallback()
        self.put()
        def answer(*args, **kwargs):
            save_settings(self.root, {'fallbackModel': 'replacement-model'})
            return self.response()
        with patch.object(self.worker.deepseek, 'analyze', side_effect=SecurityError('主模型超时')), \
                patch('security.request.build_opener') as factory:
            factory.return_value.open.side_effect = answer
            self.assertEqual(self.worker.process_once(), 2)
        self.assertEqual(self.store.dashboard()['decisions'][0]['model'], 'backup-model')
        self.assertEqual(self.panel.black, [])

    def test_endpoint_change_before_waf_write_prevents_auto_block(self):
        self.configure_fallback()
        self.put()
        self.panel.before_create = lambda: save_settings(self.root, {'fallbackBaseUrl': 'https://changed.example/v1'})
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.return_value = self.response()
            self.worker.process_once()
        self.assertEqual(self.panel.black, [])

    def test_deep_analysis_uses_custom_primary_and_backup_for_full_conversation(self):
        save_settings(self.root, {'provider': 'openai', 'key': 'custom-secret', 'model': 'custom-model',
                                 'baseUrl': 'https://primary.example/v1'})
        self.configure_fallback()
        self.put()
        deep = DeepAnalysis(self.root, self.store)
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.side_effect = [TimeoutError(),
                Response({'choices': [{'finish_reason': 'stop', 'message': {'content': '备用分析报告'}}]}),
                Response({'choices': [{'finish_reason': 'stop', 'message': {'content': '追问回答'}}]})]
            session = deep.start({'ip': '8.8.8.8'})
            session = deep.ask({'id': session['id'], 'question': '最早什么时候？'})
            requests = [call.args[0] for call in factory.return_value.open.call_args_list]
        self.assertEqual(session['messages'][0]['content'], '备用分析报告')
        self.assertEqual(session['messages'][-1]['content'], '追问回答')
        self.assertEqual([json.loads(req.data)['model'] for req in requests], ['custom-model', 'backup-model', 'custom-model'])
        self.assertNotIn('thinking', json.loads(requests[1].data))
        self.assertEqual(json.loads(requests[1].data)['messages'][:2], json.loads(requests[2].data)['messages'][:2])

    def test_jev_deep_analysis_retains_deepseek_then_can_use_backup(self):
        save_settings(self.root, {'provider': 'jev', 'key': 'jev-secret'})
        self.configure_fallback()
        routes = model_configs(settings(self.root), chat=True)
        self.assertEqual([(route['provider'], route['key']) for route in routes],
                         [('deepseek', 'primary-secret'), ('openai', 'backup-secret')])


if __name__ == '__main__':
    unittest.main()
