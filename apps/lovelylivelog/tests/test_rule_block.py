import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent.log_cleaner import Rule, compile_rules, explain
from clean_rules import CleanRules, RuleBlocker
from hub import Hub
from security import SecurityError
from storage import Store
from test_daily_clean import line


class FakeWaf:
    def __init__(self):
        self.added = []

    def add(self, ip, reason, allowed=None, origin='DeepSeek'):
        self.added.append((ip, reason, origin))
        if ip == '9.9.9.9':
            raise SecurityError('该 IP 命中 WAF 白名单，已停止自动加黑。', 409)
        return 'listed', '已验证加入 WAF 全局 IP 黑名单'


class Client:
    config = {'url': 'http://10.20.30.13:18479', 'prefix': '/api/v2'}


class RuleBlockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / '.env').write_text(('AI_ANALYSIS_MODE=ai\nAUTO_BLOCK=true\n' + 'IP_ALLOWLIST=8.8.6.173/32\nAI_ALLOW_PRIVATE_IPS=false\n'), encoding='utf-8')
        self.store = Store(self.root / 'state.sqlite3')
        self.rules = CleanRules(self.store)
        self.hub = Hub(self.store, None, self.rules)
        self.agent = self.hub.register({'name': 'nginx', 'platformUrl': 'http://127.0.0.1:1',
                                        'sources': [{'kind': 'access.log', 'path': 'C:/logs/access.log'}]})
        self.waf = FakeWaf()

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def upload(self, *raws):
        events = [{'eventId': uuid.uuid4().hex, 'kind': 'access.log', 'source': 'C:/logs/access.log', 'raw': raw,
                   'collectedAt': time.time()} for raw in raws]
        self.hub.ingest(self.agent['agentId'], {'events': events})

    def blocker(self):
        blocker = RuleBlocker(self.root, Client(), self.store, self.waf, self.rules)
        self.rules.blocker = blocker
        return blocker

    def test_block_rule_needs_path_or_ua(self):
        with self.assertRaisesRegex(ValueError, '必封规则需要'):
            Rule({'action': 'block', 'ip': '1.2.3.4'})
        Rule({'action': 'block', 'path': r'/\.env'})

    def test_agents_receive_block_rules_first_as_ai(self):
        self.rules.save({'name': '丢弃全部 404', 'action': 'drop', 'status': '404', 'includeSuspicious': True})
        self.rules.save({'name': '扔 .env', 'action': 'block', 'path': r'/\.env'})
        exported = self.rules.export()['rules']
        self.assertEqual([(r['name'], r['action']) for r in exported], [('扔 .env', 'ai'), ('丢弃全部 404', 'drop')])
        compile_rules(exported)  # v1.1.1 agents only understand drop / archive / ai

    def test_test_tool_shows_block(self):
        self.rules.save({'name': '扔 .env', 'action': 'block', 'path': r'/\.env'})
        result = self.rules.test({'lines': line('6.6.6.6', '16/Oct/2026:10:00:00', 'GET /.env HTTP/1.1', 404)})
        self.assertEqual(result['results'][0]['outcome'], '必封')

    def test_new_rows_matching_block_rule_are_blacklisted_once(self):
        self.rules.save({'name': '扔 .env', 'action': 'block', 'path': r'/\.env'})
        blocker = self.blocker()
        self.upload(line('6.6.6.6', '16/Oct/2026:10:00:00', 'GET /.env HTTP/1.1', 404),
                    line('6.6.6.6', '16/Oct/2026:10:00:01', 'GET /api/.env.bak HTTP/1.1', 404),
                    line('10.30.40.2', '16/Oct/2026:10:00:02', 'GET /.env HTTP/1.1', 404),
                    line('9.9.9.9', '16/Oct/2026:10:00:03', 'GET /.env HTTP/1.1', 404),
                    line('5.5.5.5', '16/Oct/2026:10:00:04', 'GET /home HTTP/1.1', 200),
                    json.dumps({'remote_addr': '7.7.7.7', 'time_local': '15/Oct/2026:03:00:00 +0800', 'request': 'GET /x HTTP/1.1',
                                'last_request': 'GET /.env HTTP/1.1', 'status': 404, 'count': 2, 'first_time': '15/Oct/2026:03:00:00 +0800',
                                'last_time': '15/Oct/2026:03:00:09 +0800', 'clean_date': '2026-10-15', 'clean_kind': 'suspicious',
                                'clean_ai': True}))
        blocker.scan()
        blocker.process()
        blocker.scan(); blocker.process()  # nothing new: no second write
        data = blocker.public()
        states = {r['ip']: r['state'] for r in data['rows']}
        self.assertEqual(states, {'6.6.6.6': 'listed', '7.7.7.7': 'listed', '10.30.40.2': 'protected', '9.9.9.9': 'protected'})
        self.assertEqual(sorted(ip for ip, _, _ in self.waf.added), ['6.6.6.6', '7.7.7.7', '9.9.9.9'])
        self.assertTrue(all(origin == 'CleanRule' for _, _, origin in self.waf.added))
        self.assertEqual(next(r for r in data['rows'] if r['ip'] == '6.6.6.6')['hits'], 2)
        self.assertEqual(self.rules.rules()[0]['hits'], 5)

    def test_existing_rows_need_rescan(self):
        self.upload(line('6.6.6.6', '16/Oct/2026:10:00:00', 'GET /.env HTTP/1.1', 404))
        blocker = self.blocker()
        self.rules.save({'name': '扔 .env', 'action': 'block', 'path': r'/\.env'})
        blocker.scan(); blocker.process()
        self.assertEqual(self.waf.added, [])  # rows stored before the blocker started are not scanned silently
        blocker.rescan()
        for _ in range(100):
            if not blocker.rescanning:
                break
            time.sleep(.02)
        blocker.process()
        self.assertEqual([ip for ip, _, _ in self.waf.added], ['6.6.6.6'])

    def test_rescan_requires_block_rule(self):
        with self.assertRaisesRegex(ValueError, '必封规则'):
            self.blocker().rescan()


if __name__ == '__main__':
    unittest.main()
