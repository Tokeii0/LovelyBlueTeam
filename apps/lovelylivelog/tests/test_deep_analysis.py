from datetime import datetime
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from clean_rules import CleanRules
from deep_analysis import SYSTEM_PROMPT, DeepAnalysis, normalize_ip
from hub import Hub
from security import SecurityError
from storage import Store
from test_deepseek_http import Response

KV = 'remote_addr:{ip},time_local:[18/Oct/2026:{t} +0800],request:{req} HTTP/1.1,status:{st},upstream_status:{st}'


class FakeOpener:
    def __init__(self, answers):
        self.answers, self.requests = list(answers), []

    def open(self, req, timeout=None):
        self.requests.append(json.loads(req.data))
        content = self.answers.pop(0)
        return Response({'choices': [{'finish_reason': 'stop', 'message': {'content': content}}],
                         'usage': {'prompt_tokens': 900, 'prompt_cache_hit_tokens': 640, 'completion_tokens': 50}})


class DeepAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.root.joinpath('.env').write_text(('AI_ANALYSIS_MODE=ai\nAUTO_BLOCK=true\n' + 'DEEPSEEK_API_KEY=test-only-key\nIP_ALLOWLIST=8.8.7.3/32\n'), encoding='utf-8')
        self.env = patch.dict('os.environ', {}, clear=True); self.env.start()
        self.store = Store(self.root / 'state.sqlite3'); self.hub = Hub(self.store)
        self.hub.advertised_url = 'http://127.0.0.1:8788'
        self.agent = self.hub.register({'name': '示例采集节点', 'sources': [{'kind': 'access.log', 'path': 'D:/a.log'}]})['agentId']
        self.opener = FakeOpener(['## 结论\n扫描器，建议拉黑。', '最早 10:00 开始。'])
        self.deep = DeepAnalysis(self.root, self.store, CleanRules(self.store), lambda: {7: 'pacsimage.example.com'},
                                 opener=lambda: self.opener)
        self.store.append('s', {}, 7, 'access.log', [
            KV.format(ip='8.8.4.7', t='10:00:01', req='GET /.env', st=404),
            KV.format(ip='8.8.4.7', t='10:00:02', req='GET /.git/config', st=404),
            KV.format(ip='8.8.4.71', t='10:00:03', req='GET /other', st=200),  # a longer IP that contains the target
            KV.format(ip='8.8.11.1', t='10:00:04', req='GET /Dicom/CloudView?urltoken=abc', st=200)])
        self.store.append('e', {}, 7, 'error.log', [
            '2026/10/18 10:00:05 [error] open() "/x" failed, client: 8.8.4.7, server: a, request: "GET /x?token=secret HTTP/1.1"'])
        self.hub.ingest(self.agent, {'events': [{'eventId': 'a' * 32, 'kind': 'access.log', 'source': 'D:/a.log', 'collectedAt': 1,
                                                 'raw': KV.format(ip='8.8.4.7', t='11:00:00', req='POST /gateway', st=200)}]})

    def tearDown(self):
        self.store.close(); self.env.stop(); self.temp.cleanup()

    def test_digest_collects_only_this_ip_from_every_source(self):
        digest = self.deep.collect('8.8.4.7')
        overview = digest['overview']
        self.assertEqual(overview['requests'], 3)
        self.assertEqual(overview['sources'], {'pacsimage.example.com': 2, '示例采集节点': 1})
        self.assertEqual(overview['suspicious_requests'], 2)
        self.assertEqual([p['path'] for p in digest['patterns'][:2]], ['/.env', '/.git/config'])  # suspicious first
        self.assertEqual(len(digest['errors']), 1)
        self.assertNotIn('secret', json.dumps(digest, ensure_ascii=False))
        expected_first = datetime.fromtimestamp(datetime.fromisoformat('2026-10-18T10:00:01+08:00').timestamp())
        self.assertEqual(overview['first_seen'], expected_first.strftime('%Y-%m-%d %H:%M:%S'))

    def test_conversation_resends_the_same_prefix(self):
        session = self.deep.start({'ip': ' 8.8.4.7 '})
        self.assertEqual(session['ip'], '8.8.4.7')
        self.assertEqual([m['role'] for m in session['messages']], ['assistant'])  # the digest turn is hidden
        self.assertEqual(session['summary']['requests'], 3)
        session = self.deep.ask({'id': session['id'], 'question': '最早什么时候？'})
        self.assertEqual([m['content'] for m in session['messages']], ['## 结论\n扫描器，建议拉黑。', '最早什么时候？', '最早 10:00 开始。'])
        first, second = self.opener.requests
        self.assertEqual(first['messages'][0]['content'], SYSTEM_PROMPT)
        self.assertEqual(second['messages'][:2], first['messages'][:2])  # cacheable prefix
        self.assertEqual(second['messages'][2]['role'], 'assistant')
        self.assertEqual(self.store.ai_usage_today()['cacheHit'], 1280)
        self.assertEqual(self.deep.sessions()['sessions'][0]['ip'], '8.8.4.7')
        self.assertEqual(self.deep.delete(session['id'])['sessions'], [])

    def test_protection_and_block_state_are_reported(self):
        self.store.set_block('8.8.7.3', 'manual_x', True, 'listed')
        self.store.append('p', {}, 7, 'access.log', [KV.format(ip='8.8.7.3', t='12:00:00', req='POST /HuBei/Encrypt/YBService', st=200)])
        digest = self.deep.collect('8.8.7.3')
        self.assertEqual(digest['protection'], ['在程序保护名单中'])
        self.assertEqual(digest['block_state'], {'waf': 'listed'})
        self.assertEqual(self.deep.collect('10.20.31.150')['protection'], ['内网或非公网地址'])

    def test_errors(self):
        with self.assertRaisesRegex(ValueError, '有效'):
            normalize_ip('8.8.4.0/24')
        with self.assertRaisesRegex(ValueError, '没有'):
            self.deep.start({'ip': '9.9.9.9'})
        with self.assertRaisesRegex(ValueError, '问题'):
            self.deep.ask({'id': 1, 'question': ' '})
        self.root.joinpath('.env').write_text('AI_ANALYSIS_MODE=ai\nAUTO_BLOCK=false\n', encoding='utf-8')
        with self.assertRaisesRegex(SecurityError, '密钥'):
            self.deep.start({'ip': '8.8.4.7'})


if __name__ == '__main__':
    unittest.main()
