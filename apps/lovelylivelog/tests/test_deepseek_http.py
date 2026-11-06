import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib import error

from security import DeepSeek, NoRedirect, SecurityError
from storage import Store


class Response:
    def __init__(self, data): self.raw = json.dumps(data).encode()
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, *args): return self.raw


class DeepSeekHttpTests(unittest.TestCase):
    def setUp(self):
        self.config = {'model':'deepseek-flash','baseUrl':'https://api.deepseek.com','key':'test-only-key'}
        self.events = [{'id':1,'ip':'8.8.8.8','target':'/.env'},{'id':2,'ip':'8.8.8.8','target':'/wp-login'}]
        self.verdict = {'decisions':[{'ip':'8.8.8.8','is_attack':True,'confidence':.99,
                                     'attack_type':'scanner','reason':'测试判断','evidence_ids':[1,2]}]}

    def response(self, evidence_ids=('L1', 'L2')):
        output = {'decisions': [dict(self.verdict['decisions'][0], evidence_ids=list(evidence_ids))]}
        return Response({'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps(output)}}]})

    def test_http_request_uses_json_mode_and_returns_validated_decisions(self):
        with patch('security.request.build_opener') as factory:
            opener = factory.return_value
            opener.open.return_value = self.response()
            output = DeepSeek().analyze(self.events, self.config)
            req = opener.open.call_args.args[0]
            body = json.loads(req.data)
            self.assertEqual(req.full_url, 'https://api.deepseek.com/chat/completions')
            self.assertEqual(req.get_header('Authorization'), 'Bearer test-only-key')
            self.assertEqual(body['response_format'], {'type':'json_object'})
            self.assertEqual(body['thinking'], {'type':'disabled'})
            self.assertNotIn('test-only-key', json.dumps(body))
            logs = json.loads(body['messages'][1]['content'])['untrusted_access_logs']
            self.assertEqual([row[0] for row in logs['clients'][0]['rows']], ['L1', 'L2'])
            self.assertEqual(output, self.verdict['decisions'])

    def test_labels_restore_signed_agent_ids_and_aggregated_samples(self):
        self.events = [{'id': -1496540, 'website': 1, 'ip': '8.8.8.8', 'target': '/.env'},
                       {'id': -1496539, 'website': 1, 'ip': '8.8.8.8', 'target': '/.env'},
                       {'id': -1496538, 'website': 1, 'ip': '8.8.8.8', 'target': '/.env'}]
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.return_value = self.response(('L2', 'L1'))
            output = DeepSeek().analyze(self.events, self.config)
            body = json.loads(factory.return_value.open.call_args.args[0].data)
        logs = json.loads(body['messages'][1]['content'])['untrusted_access_logs']
        self.assertEqual([row[:2] for row in logs['clients'][0]['rows']], [['L1', 0], ['L2', 0]])
        self.assertEqual(output[0]['evidence_ids'], [-1496538, -1496540])
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'state.sqlite3')
            try:
                completed = store.complete_analysis(self.events, output, 'deepseek', self.config['model'])
                decision = store.decision(completed[0][0])
                self.assertEqual(json.loads(decision['evidence']), [-1496538, -1496540])
            finally:
                store.close()

    def test_invalid_or_duplicate_evidence_labels_are_rejected(self):
        for ids in ([0, 1], [1, 2], [-1496540], ['L3'], ['L1', 'L1'], [True], [{}]):
            with self.subTest(ids=ids), patch('security.request.build_opener') as factory:
                factory.return_value.open.return_value = self.response(ids)
                with self.assertRaisesRegex(SecurityError, '证据'):
                    DeepSeek().analyze(self.events, self.config)

    def test_label_from_another_ip_cannot_be_used_as_evidence(self):
        self.events.append({'id': 3, 'ip': '1.1.1.1', 'target': '/health'})
        output = {'decisions': [dict(self.verdict['decisions'][0], evidence_ids=['L1', 'L3']),
                                {'ip': '1.1.1.1', 'is_attack': False, 'confidence': .9,
                                 'attack_type': 'none', 'reason': 'normal', 'evidence_ids': []}]}
        result = {'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps(output)}}]}
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.return_value = Response(result)
            with self.assertRaisesRegex(SecurityError, '证据'):
                DeepSeek().analyze(self.events, self.config)

    def test_failure_messages_distinguish_length_empty_json_and_envelope(self):
        cases = [({'choices': [{'finish_reason': 'length', 'message': {'content': '{}'}}]}, '截断'),
                 ({'choices': [{'finish_reason': 'stop', 'message': {'content': ''}}]}, '为空'),
                 ({'choices': [{'finish_reason': 'stop', 'message': {'content': 'provider-secret'}}]}, 'JSON'),
                 ([], '结构'), ({'choices': [None]}, '结构'), ({'choices': []}, '结构')]
        for result, reason in cases:
            with self.subTest(reason=reason), patch('security.request.build_opener') as factory:
                factory.return_value.open.return_value = Response(result)
                with self.assertRaisesRegex(SecurityError, reason) as raised:
                    DeepSeek().analyze(self.events, self.config)
                self.assertNotIn('provider-secret', str(raised.exception))

    def test_usage_is_recorded_even_when_evidence_or_response_structure_is_invalid(self):
        usage = {'prompt_tokens': 100, 'completion_tokens': 40}
        invalid_evidence = dict(json.loads(self.response(('L3',)).raw), usage=usage)
        for result in (invalid_evidence, {'usage': usage}):
            billed = []
            with patch('security.request.build_opener') as factory:
                factory.return_value.open.return_value = Response(result)
                with self.assertRaises(SecurityError):
                    DeepSeek(lambda model, data: billed.append((model, data))).analyze(self.events, self.config)
            self.assertEqual(billed, [(self.config['model'], usage)])

    def test_empty_or_truncated_model_output_never_becomes_an_attack_decision(self):
        valid = {'decisions': [dict(self.verdict['decisions'][0], evidence_ids=['L1', 'L2'])]}
        for finish, content in [('stop',''), ('length',json.dumps(valid)), ('stop','not json')]:
            result = {'choices':[{'finish_reason':finish,'message':{'content':content}}]}
            with patch('security.request.build_opener') as factory:
                factory.return_value.open.return_value = Response(result)
                with self.assertRaises(SecurityError): DeepSeek().analyze(self.events, self.config)

    def test_api_failures_are_reported_without_raw_provider_errors(self):
        with patch('security.request.build_opener') as factory:
            factory.return_value.open.side_effect = error.HTTPError('url',401,'provider-secret',{},None)
            with self.assertRaisesRegex(SecurityError,'密钥无效') as raised:
                DeepSeek().analyze(self.events,self.config)
            self.assertNotIn('provider-secret',str(raised.exception))

    def test_redirect_does_not_forward_the_ai_key(self):
        with self.assertRaises(SecurityError):
            NoRedirect().redirect_request(None,None,302,'redirect',{},'https://other.example')


if __name__ == '__main__': unittest.main()
