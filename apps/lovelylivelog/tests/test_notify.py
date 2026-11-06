from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from notify import LOG, DEFAULT_TEMPLATE, KeywordNotifier, NapCatClient, notify_settings, render, save_notify_settings
from security import SecurityError
from storage import Store

ACCESS = 'remote_addr:203.0.113.7,time_local:[17/Oct/2026:20:15:02 +0800],request:GET {} HTTP/1.1,status:{},upstream_status:200'


class FakeNapCat:
    sent, fail, mentioned = [], None, []
    group_members = {123456: [{'id': 10001, 'name': '张三', 'nickname': 'zs', 'role': 'admin'}],
                     654321: [{'id': 10001, 'name': '张三', 'nickname': 'zs', 'role': 'member'},
                              {'id': 10002, 'name': '李四', 'nickname': 'ls', 'role': 'member'}]}

    def __init__(self, config):
        self.config = config

    def send(self, group_id, text, mentions=(), mention_all=False):
        if FakeNapCat.fail:
            raise FakeNapCat.fail
        FakeNapCat.sent.append((group_id, text))
        FakeNapCat.mentioned.append((group_id, list(mentions), mention_all))
        return len(FakeNapCat.sent)

    def members(self, group_id):
        return FakeNapCat.group_members.get(group_id, []) + [{'id': 99999, 'name': '机器人', 'nickname': 'bot', 'role': 'owner'}]

    def login(self):
        return {'userId': 99999, 'nickname': '机器人'}


class NotifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / '.env').write_text('PANEL_URL=http://127.0.0.1\nNAPCAT_ENABLED=true\n', encoding='utf-8')
        self.store = Store(self.root / 'runtime' / 'state.sqlite3')
        self.agent = str(uuid.uuid4())
        with self.store.db:
            self.store.db.execute("INSERT INTO agents(id,name,token_hash,created) VALUES(?,?,?,?)", (self.agent, '示例采集节点', 'x', 1))
        self.add_agent('access.log', ACCESS.format('/before-start?union%20select', 200))  # history is never pushed
        FakeNapCat.sent, FakeNapCat.fail, FakeNapCat.mentioned = [], None, []
        self.notifier = KeywordNotifier(self.root, self.store, lambda: {5: 'www.example.com'}, factory=FakeNapCat)

    def tearDown(self):
        for handler in list(LOG.handlers):  # Release runtime/notify.log so Windows can delete the folder.
            LOG.removeHandler(handler)
            handler.close()
        self.store.db.close()
        self.temp.cleanup()

    def add_agent(self, kind, raw):
        with self.store.db:
            self.store.db.execute('''INSERT INTO agent_events(agent_id,event_id,kind,source,raw,collected,received)
                VALUES(?,?,?,?,?,?,?)''', (self.agent, uuid.uuid4().hex, kind, 'D:/nginx/logs/access.log', raw, time.time(), time.time()))

    def add_site(self, kind, raw, website=5):
        self.store.append(f'site-{website}-{kind}', {}, website, kind, [raw])

    def rule(self, **extra):
        body = {'name': 'SQL 注入', 'keywords': 'union select\n/etc/passwd', 'groups': [123456], 'cooldown': 60, **extra}
        return self.notifier.save(body)['rules'][-1]

    def round(self):
        self.notifier.scan()
        self.notifier.flush()
        self.notifier.deliver(notify_settings(self.root))

    def test_keyword_hit_is_pushed_with_parsed_fields(self):
        self.rule(template='{rule}|{source}|{keyword}|{ip}|{method}|{path}|{status}|{count}')
        self.add_agent('access.log', ACCESS.format('/api/list?id=1 UNION SELECT 1', 200))
        self.add_agent('access.log', ACCESS.format('/ok', 200))
        self.round()
        self.assertEqual(FakeNapCat.sent, [(123456, 'SQL 注入|示例采集节点|union select|203.0.113.7|GET|/api/list?id=1+UNION+SELECT+1|200|1')])
        public = self.notifier.public()
        self.assertEqual(public['rules'][0]['hits'], 1)
        self.assertTrue(public['log'][0]['ok'])

    def test_hits_within_cooldown_merge_into_one_message(self):
        self.rule(template='{count}', groups=[111111, 222222])
        self.add_agent('access.log', ACCESS.format('/etc/passwd', 404))
        self.round()
        for _ in range(3):
            self.add_agent('access.log', ACCESS.format('/etc/passwd', 404))
        self.round()
        self.assertEqual(FakeNapCat.sent, [(111111, '1'), (222222, '1')])  # still cooling down
        with self.store.db:
            self.store.db.execute('UPDATE notify_rules SET last_sent=last_sent-61')
        self.round()
        self.assertEqual(FakeNapCat.sent[2:], [(111111, '3'), (222222, '3')])

    def test_match_all_kinds_and_sources_filter(self):
        self.rule(keywords=['timeout', 'upstream'], matchAll=True, kinds=['error.log'], sources=['site:5'], template='{source}')
        self.add_site('error.log', 'upstream timed out (110: Connection timeout) while reading')
        self.add_site('error.log', 'only a timeout here')
        self.add_site('access.log', 'upstream timeout in an access line')
        self.add_agent('error.log', 'upstream timeout on the agent')
        self.round()
        self.assertEqual(FakeNapCat.sent, [(123456, 'www.example.com')])

    def test_disabled_push_skips_rows_instead_of_queueing(self):
        self.rule()
        save_notify_settings(self.root, {'enabled': False})
        self.add_agent('access.log', ACCESS.format('/etc/passwd', 404))
        self.notifier.scan(notify_settings(self.root)['enabled'])
        save_notify_settings(self.root, {'enabled': True})
        self.round()
        self.assertEqual(FakeNapCat.sent, [])
        self.assertEqual(self.notifier.public()['rules'][0]['hits'], 0)

    def test_failed_send_stays_queued_and_is_retried(self):
        self.rule(template='x')
        self.add_agent('access.log', ACCESS.format('/etc/passwd', 404))
        FakeNapCat.fail = SecurityError('无法连接 NapCat：连接被拒绝。', 503)
        self.round()
        public = self.notifier.public()
        self.assertEqual(public['queued'], 1)
        self.assertFalse(public['log'][0]['ok'])
        self.assertIn('稍后重试', public['log'][0]['detail'])
        FakeNapCat.fail = None
        with self.store.db:
            self.store.db.execute('UPDATE notify_outbox SET retry_at=0')
        self.round()
        self.assertEqual(FakeNapCat.sent, [(123456, 'x')])
        self.assertEqual(self.notifier.public()['queued'], 0)

    def test_rule_validation(self):
        for body, message in [({'name': '', 'keywords': 'a', 'groups': [123456]}, '名称'),
                              ({'name': 'a', 'keywords': ' \n ', 'groups': [123456]}, '关键词'),
                              ({'name': 'a', 'keywords': 'a', 'groups': []}, '群聊'),
                              ({'name': 'a', 'keywords': 'a', 'groups': [123456], 'kinds': ['x.log']}, '日志类型'),
                              ({'name': 'a', 'keywords': 'a', 'groups': [123456], 'sources': ['site:x']}, '来源'),
                              ({'name': 'a', 'keywords': 'a', 'groups': [123456], 'cooldown': -1}, '合并间隔')]:
            with self.assertRaisesRegex(ValueError, message):
                self.notifier.save(body)
        rule = self.rule(template='')
        self.assertEqual(rule['template'], DEFAULT_TEMPLATE)
        self.assertEqual(rule['keywords'], ['union select', '/etc/passwd'])

    def test_settings_keep_token_and_hide_it(self):
        save_notify_settings(self.root, {'url': 'http://127.0.0.1:3000/', 'token': 'secret-token'})
        save_notify_settings(self.root, {'url': 'http://127.0.0.1:3001', 'token': ''})
        self.assertEqual(notify_settings(self.root)['token'], 'secret-token')
        public = self.notifier.public()['settings']
        self.assertEqual(public, {'enabled': True, 'url': 'http://127.0.0.1:3001', 'tokenSet': True})
        with self.assertRaisesRegex(ValueError, 'NapCat 地址'):
            save_notify_settings(self.root, {'url': 'ftp://x'})

    def test_alerts_mention_the_chosen_members(self):
        rule = self.rule(template='x', groups=[123456, 654321], mentions=[10001, 10002, 10001], mentionAll=True)
        self.assertEqual((rule['mentions'], rule['mentionAll']), ([10001, 10002], True))
        self.add_agent('access.log', ACCESS.format('/etc/passwd', 404))
        self.round()
        self.assertEqual(FakeNapCat.mentioned, [(123456, [10001, 10002], True), (654321, [10001, 10002], True)])
        for mentions in ([1], ['10001'], list(range(10000, 10021))):
            with self.assertRaisesRegex(ValueError, '@ 成员'):
                self.rule(mentions=mentions)

    def test_members_of_all_target_groups(self):
        members = self.notifier.members({'groups': [123456, 654321]})['members']
        self.assertEqual([(m['id'], m['groups']) for m in members], [(10001, [123456, 654321]), (10002, [654321])])
        with self.assertRaises(ValueError):
            self.notifier.members({'groups': []})

    def test_render_keeps_unknown_braces_and_limits_length(self):
        self.assertEqual(render('{ip} {unknown}', {'ip': '1.2.3.4'}), '1.2.3.4 {unknown}')
        self.assertEqual(len(render('{raw}', {'raw': 'x' * 5000})), 3000)


class NapCatHttpTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        test = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                test.requests.append((self.path, self.headers.get('Authorization'), body))
                if self.headers.get('Authorization') != 'Bearer good':
                    return self.reply(403, {'message': 'token verify failed!'})
                if self.path == '/get_group_list':
                    return self.reply(200, {'status': 'ok', 'retcode': 0, 'data': [{'group_id': 123456, 'group_name': '运维群', 'member_count': 8}]})
                if self.path == '/get_group_member_list':
                    # NapCat answers the first request for a group with an empty list while it loads.
                    calls = sum(1 for p, _, b in test.requests if p == self.path and b == body)
                    members = [] if calls == 1 else [
                        {'user_id': 3, 'nickname': 'c', 'card': '', 'role': 'member'},
                        {'user_id': 1, 'nickname': 'a', 'card': '运维 王五', 'role': 'admin'},
                        {'user_id': 2, 'nickname': 'bot', 'role': 'member', 'is_robot': True}]
                    return self.reply(200, {'status': 'ok', 'retcode': 0, 'data': members})
                if self.path == '/send_group_msg' and body['group_id'] == 999999:
                    return self.reply(200, {'status': 'failed', 'retcode': 1200, 'message': '不在群内'})
                self.reply(200, {'status': 'ok', 'retcode': 0, 'data': {'message_id': 42}})

            def reply(self, code, data):
                raw = json.dumps(data).encode()
                self.send_response(code)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'

    def tearDown(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def test_onebot_requests(self):
        client = NapCatClient({'url': self.url, 'token': 'good'})
        self.assertEqual(client.groups(), [{'id': 123456, 'name': '运维群', 'members': 8}])
        self.assertEqual(client.send(123456, '你好'), 42)
        self.assertEqual(self.requests[-1], ('/send_group_msg', 'Bearer good',
                                             {'group_id': 123456, 'message': [{'type': 'text', 'data': {'text': '你好'}}]}))
        with self.assertRaisesRegex(SecurityError, '不在群内'):
            client.send(999999, 'x')
        client.send(123456, '告警', [10001, 10002], True)
        self.assertEqual(self.requests[-1][2]['message'], [
            {'type': 'at', 'data': {'qq': 'all'}}, {'type': 'at', 'data': {'qq': '10001'}},
            {'type': 'at', 'data': {'qq': '10002'}}, {'type': 'text', 'data': {'text': '\n告警'}}])

    def test_member_list_waits_for_lazy_loading(self):
        with patch('notify.time.sleep'):
            members = NapCatClient({'url': self.url, 'token': 'good'}).members(123456)
        self.assertEqual([(m['id'], m['name'], m['role']) for m in members], [(1, '运维 王五', 'admin'), (3, 'c', 'member')])

    def test_bad_token_and_unreachable(self):
        with self.assertRaisesRegex(SecurityError, 'token 不正确'):
            NapCatClient({'url': self.url, 'token': 'bad'}).groups()
        self.server.shutdown()
        self.server.server_close()
        self.server = None
        with self.assertRaises(SecurityError) as raised:
            NapCatClient({'url': self.url, 'token': 'good'}, timeout=2).groups()
        self.assertEqual(raised.exception.status, 503)


if __name__ == '__main__':
    unittest.main()
