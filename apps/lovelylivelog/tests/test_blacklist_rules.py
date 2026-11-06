from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from blacklist import BlacklistService
from clean_rules import CleanRules, RuleBlocker
from hub import Hub
from security import Waf
from storage import Store
from test_incremental_security import FakePanel


def rule(ip, origin='', state='on'):
    name = str(uuid.uuid4())
    description = f'{origin} [{origin.lower()}_x] 原因 {ip}' if origin else f'1Panel 手工 {ip}'
    return {'name': name, 'type': 'ipv4', 'ipv4': ip, 'ipv6': '', 'ipStart': '', 'ipEnd': '', 'ipGroup': '',
            'state': state, 'description': description}


class BlacklistRulesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.env = patch.dict('os.environ', {}, clear=True); self.env.start()
        self.root.joinpath('.env').write_text('PANEL_API_KEY=panel-secret\n', encoding='utf-8')
        self.store = Store(self.root / 'state.sqlite3'); self.panel = FakePanel()
        self.service = BlacklistService(self.root, Waf(self.panel, self.store))
        self.panel.black = [rule('8.8.4.1', 'DeepSeek'), rule('8.8.4.2', 'SiteVisit'), rule('8.8.4.3'),
                            rule('8.8.4.4', 'Manual', 'off')]

    def tearDown(self):
        self.store.close(); self.env.stop(); self.temp.cleanup()

    def test_lists_every_rule_with_its_origin(self):
        data = self.service.rules()
        self.assertEqual(data['total'], 4)
        self.assertEqual([(r['target'], r['origin'], r['enabled']) for r in data['rules']],
                         [('8.8.4.1', 'DeepSeek', True), ('8.8.4.2', 'SiteVisit', True), ('8.8.4.3', 'Panel', True),
                          ('8.8.4.4', 'Manual', False)])
        self.assertEqual(data['rules'][0]['description'], '原因 8.8.4.1')
        self.assertEqual(data['rules'][2]['description'], '1Panel 手工 8.8.4.3')

    def test_remove_any_rule_and_remember_the_choice(self):
        names = [r['name'] for r in self.panel.black]
        result = self.service.remove_rules({'names': names[:1] + ['gone']})
        self.assertEqual((result['removed'], result['missing'], result['total']), (1, 1, 3))
        self.assertEqual(self.store.block('8.8.4.1')['state'], 'removed')  # may be blocked again automatically
        self.service.remove_rules({'names': [names[2]], 'protect': True})
        self.assertEqual(self.store.block('8.8.4.3')['state'], 'unblocked')  # never blocked again automatically
        self.assertEqual([r['ipv4'] for r in self.panel.black], ['8.8.4.2', '8.8.4.4'])
        for body in ({'names': []}, {'names': ['a', 'a']}, {'names': ['a'], 'protect': 'yes'}):
            with self.assertRaises(ValueError):
                self.service.remove_rules(body)

    def test_clear_all_needs_the_typed_confirmation(self):
        with self.assertRaisesRegex(ValueError, '清空'):
            self.service.clear_all({'confirm': '清除'})
        self.service.clear_all({'confirm': '清空'})
        for _ in range(100):
            if not self.service.clear_state['running']:
                break
            time.sleep(.05)
        self.assertEqual(self.panel.black, [])
        self.assertEqual({k: self.service.clear_state[k] for k in ('running', 'total', 'done', 'failed')},
                         {'running': False, 'total': 4, 'done': 4, 'failed': 0})

    def test_removed_clean_rule_ip_is_blocked_again_on_a_new_hit(self):
        rules = CleanRules(self.store)
        hub = Hub(self.store, None, rules)
        hub.advertised_url = 'http://127.0.0.1:1'
        agent = hub.register({'name': 'nginx', 'sources': [{'kind': 'access.log', 'path': 'C:/a.log'}]})['agentId']
        blocker = RuleBlocker(self.root, self.panel, self.store, self.service.waf, rules)
        rules.save({'name': '探测', 'action': 'block', 'path': r'^/\.env'})
        with self.store.db:
            self.store.db.execute("""INSERT INTO rule_block_ips(ip,rule_id,rule_name,hits,first_seen,last_seen,sample,origin,state,updated)
                VALUES('8.8.4.9',1,'探测',1,1,1,'GET /.env','x','removed',1)""")
        hub.ingest(agent, {'events': [{'eventId': uuid.uuid4().hex, 'kind': 'access.log', 'source': 'C:/a.log', 'collectedAt': 1,
                                       'raw': '8.8.4.9 - - [18/Oct/2026:10:00:00 +0800] "GET /.env HTTP/1.1" 404 0'}]})
        blocker.scan()
        state = self.store.db.execute("SELECT state FROM rule_block_ips WHERE ip='8.8.4.9'").fetchone()[0]
        self.assertEqual(state, 'pending')


if __name__ == '__main__':
    unittest.main()
