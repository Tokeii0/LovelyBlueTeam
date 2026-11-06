from datetime import date
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib import request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from af_firewall import LOG, MARK, AfClient, AfSync, af_settings, canonical, save_af_settings
from agent.log_cleaner import DailyCleaner, Rule, compile_rules, explain
from clean_rules import CleanRules
from hub import Hub, IngestServer
from security import SecurityError
from storage import Store
from test_daily_clean import DAY, line


class RuleEngineTests(unittest.TestCase):
    def test_conditions_must_all_match(self):
        rule = Rule({'action': 'drop', 'ip': '10.0.0.0/8', 'method': 'get', 'status': '2xx, 404', 'path': '^/health'})
        self.assertTrue(rule.matches('10.1.2.3', 'GET', '/health?x=1', 200))
        self.assertFalse(rule.matches('11.1.2.3', 'GET', '/health', 200))
        self.assertFalse(rule.matches('10.1.2.3', 'POST', '/health', 200))
        self.assertFalse(rule.matches('10.1.2.3', 'GET', '/health', 500))

    def test_invalid_rules_explain_themselves(self):
        for data, message in [({'action': 'drop'}, '至少填写'), ({'action': 'drop', 'status': '4x'}, '状态码'),
                              ({'action': 'drop', 'path': '('}, '正则'), ({'action': 'x', 'path': 'a'}, '动作'),
                              ({'action': 'drop', 'ip': 'abc'}, 'CIDR')]:
            with self.assertRaisesRegex(ValueError, message):
                Rule(data)

    def clean(self, rules, options=None):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'a.log'
            path.write_text('\n'.join(DAY + [line('3.3.3.3', '15/Oct/2026:06:00:00', 'GET /logo.png HTTP/1.1')]), encoding='utf-8')
            cleaner = DailyCleaner(date(2026, 10, 15), rules=compile_rules(rules), **(options or {}))
            cleaner.feed(path)
            rows = [json.loads(r) for r in cleaner.rows()]
            return rows, cleaner.report(len(rows))

    def test_drop_archive_and_force_ai(self):
        rows, report = self.clean([
            {'id': 1, 'action': 'drop', 'ip': '1.1.1.1', 'path': '^/gateway'},
            {'id': 2, 'action': 'archive', 'ip': '7.7.7.7'},
            {'id': 3, 'action': 'ai', 'path': r'\.png$'}])
        self.assertFalse(any(r['remote_addr'] == '1.1.1.1' and '/gateway' in r['request'] for r in rows))
        rare = next(r for r in rows if r['remote_addr'] == '7.7.7.7')
        self.assertFalse(rare['clean_ai'])
        self.assertEqual(rare['clean_rule'], 'archive')
        logo = next(r for r in rows if r['remote_addr'] == '3.3.3.3')  # kept despite the static filter
        self.assertTrue(logo['clean_ai'])
        self.assertEqual(report['ruleHits'], {'1': 3, '2': 1, '3': 2})  # OPTIONS /gateway matches too

    def test_drop_rule_skips_suspicious_unless_opted_in(self):
        rows, _ = self.clean([{'id': 1, 'action': 'drop', 'ip': '6.6.6.6'}])
        self.assertEqual({r['clean_kind'] for r in rows if r['remote_addr'] == '6.6.6.6'}, {'suspicious'})
        rows, _ = self.clean([{'id': 1, 'action': 'drop', 'ip': '6.6.6.6', 'includeSuspicious': True}])
        self.assertFalse(any(r['remote_addr'] == '6.6.6.6' for r in rows))

    def test_builtin_switches(self):
        rows, report = self.clean([], {'drop_static': False, 'drop_preflight': False})
        self.assertEqual(report['droppedStatic'] + report['droppedPreflight'], 0)
        self.assertTrue(any('/logo.png' in r['request'] for r in rows))

    def test_explain(self):
        rules = compile_rules([{'id': 4, 'name': '健康检查', 'action': 'drop', 'path': '^/home$'}])
        self.assertEqual(explain(DAY[7], rules)['outcome'], '丢弃')
        self.assertEqual(explain(DAY[5], rules)['outcome'], '送 AI')
        self.assertEqual(explain('nonsense')['outcome'], '无法解析')


class CleanRulesStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'state.sqlite3')
        self.rules = CleanRules(self.store)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_crud_order_export_and_hits(self):
        first = self.rules.save({'name': '健康检查', 'action': 'drop', 'path': '^/health'})['rules'][0]
        self.rules.save({'name': '后台', 'action': 'ai', 'path': '^/admin'})
        self.rules.save({'name': '关闭的', 'action': 'archive', 'ip': '1.2.3.4', 'enabled': False})
        order = [r['name'] for r in self.rules.move(first['id'], 1)['rules']]
        self.assertEqual(order, ['后台', '健康检查', '关闭的'])
        exported = self.rules.export()
        self.assertEqual([r['name'] for r in exported['rules']], ['后台', '健康检查'])
        self.rules.save({**first, 'name': '健康检查 v2'})
        self.assertNotEqual(self.rules.export()['version'], exported['version'])
        self.rules.add_hits({str(first['id']): 5, 'x': 3})
        self.assertEqual(next(r for r in self.rules.rules() if r['id'] == first['id'])['hits'], 5)
        self.rules.delete(first['id'])
        self.assertEqual(len(self.rules.rules()), 2)
        with self.assertRaisesRegex(ValueError, '名称'):
            self.rules.save({'name': '', 'action': 'drop', 'path': 'a'})

    def test_options_and_test_tool(self):
        self.assertEqual(self.rules.set_options({'dropStatic': False, 'widespreadIps': 9})['options']['widespreadIps'], 9)
        with self.assertRaises(ValueError):
            self.rules.set_options({'widespreadIps': 1})
        result = self.rules.test({'lines': DAY[3] + '\n' + DAY[5]})['results']
        self.assertEqual([r['kind'] for r in result], ['normal', 'suspicious'])  # static kept when dropStatic is off

    def test_platform_side_archive_rule(self):
        self.rules.save({'name': '内部', 'action': 'archive', 'ip': '8.8.8.8'})
        event = {'ip': '8.8.8.8', 'method': 'GET', 'target': '/a', 'status': 200, 'userAgent': ''}
        self.assertEqual(self.rules.ai_action(event).action, 'archive')
        self.assertIsNone(self.rules.ai_action({**event, 'target': '/../etc/passwd'}))

    def test_agents_download_rules_and_report_hits(self):
        rule = self.rules.save({'name': '健康检查', 'action': 'drop', 'path': '^/health'})['rules'][0]
        hub = Hub(self.store, None, self.rules)
        config = hub.register({'name': 'nginx', 'platformUrl': 'http://127.0.0.1:1',
                               'sources': [{'kind': 'access.log', 'path': 'C:/logs/access_{date}.log', 'mode': 'daily'}]})
        server = IngestServer(('127.0.0.1', 0), hub)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f'http://127.0.0.1:{server.server_port}/v1/clean-rules'
            with self.assertRaises(Exception):
                request.urlopen(url, timeout=5)
            req = request.Request(url, headers={'X-Agent-ID': config['agentId'], 'Authorization': 'Bearer ' + config['token']})
            with request.urlopen(req, timeout=5) as response:
                data = json.load(response)
            self.assertEqual(data['rules'][0]['path'], '^/health')
            report = json.dumps({'type': 'daily_clean_report', 'ruleHits': {str(rule['id']): 7}}, separators=(',', ':'))
            event = {'eventId': uuid.uuid4().hex, 'kind': 'custom.log', 'source': 's', 'raw': report, 'collectedAt': 1}
            hub.ingest(config['agentId'], {'events': [event]})
            hub.ingest(config['agentId'], {'events': [event]})  # retried batch must not double count
            self.assertEqual(self.rules.rules()[0]['hits'], 7)
        finally:
            server.shutdown(); server.server_close()


class FakeAf:
    """In-memory AF following the documented whiteblacklist behaviour."""

    def __init__(self, items=()):
        self.items = list(items)
        self.calls = []

    def __call__(self, config):
        self.config = config
        return self

    def login(self):
        self.calls.append('login'); return {'role': 'ADMINISTRATOR'}

    def logout(self):
        self.calls.append('logout')

    def blacklist(self):
        return [dict(i) for i in self.items]

    def add(self, entries):
        self.calls.append(('add', len(entries)))
        # The real AF rejects the whole batch with code 22 for these characters.
        if any(set(e.get('description', '')) & set('`~!#$%^&*+=\\|;:"\',/<>?') for e in entries):
            raise SecurityError('AF 返回错误 22：描述信息不能包含特殊字符')
        known = {canonical(i['url']) for i in self.items}
        self.items.extend(e for e in entries if canonical(e['url']) not in known)

    def delete(self, url):
        self.calls.append(('delete', url))
        self.items = [i for i in self.items if i['url'] != url]


class FakeBlacklist:
    def __init__(self, targets):
        self.targets = targets

    def snapshot(self):
        return {'targets': list(self.targets)}


class AfSyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / '.env').write_text(('AI_ANALYSIS_MODE=ai\nAUTO_BLOCK=true\n' + 'PANEL_URL=http://10.20.30.13:18479\nIP_ALLOWLIST=8.8.6.173/32\n'
                                        'AF_URL=https://192.0.2.1\nAF_USERNAME=api\nAF_PASSWORD=secret\n'), encoding='utf-8')
        self.store = Store(self.root / 'state.sqlite3')

    def tearDown(self):
        for handler in list(LOG.handlers):  # Release runtime/af.log so Windows can delete the folder.
            LOG.removeHandler(handler)
            handler.close()
        self.store.close()
        self.temp.cleanup()

    def test_log_records_requests_without_secrets(self):
        _, result = self.sync(['1.2.3.4'], FakeAf())
        sync = AfSync(self.root, self.store, FakeBlacklist([]), FakeAf())
        text = sync.read_log()
        self.assertIn('sync ok', text)
        self.assertNotIn('secret', text)

    def sync(self, targets, af):
        sync = AfSync(self.root, self.store, FakeBlacklist(targets), af)
        return sync, sync.sync(manual=True)

    def test_adds_missing_skips_protected_and_keeps_foreign_entries(self):
        af = FakeAf([{'url': '5.5.5.5', 'description': '人工添加'}])
        _, result = self.sync(['1.2.3.4', '5.5.5.5', '9.9.9.0/24', '8.8.8.1-8.8.8.9', '10.30.40.1', '8.8.6.173', '10.20.30.13'], af)
        urls = {i['url'] for i in af.items}
        self.assertEqual(urls, {'5.5.5.5', '1.2.3.4', '9.9.9.0/24', '8.8.8.1-8.8.8.9'})
        self.assertTrue(all(i['description'].startswith(MARK) for i in af.items if i['url'] != '5.5.5.5'))
        status = result['status']
        self.assertEqual((status['added'], status['skipped'], status['existing'], status['missing']), (3, 3, 1, 0))
        self.assertTrue(status['ok'])
        self.assertEqual(af.calls[0], 'login'); self.assertEqual(af.calls[-1], 'logout')
        self.assertNotIn('secret', json.dumps(result))

    def test_requested_sync_runs_before_interval_but_respects_disabled_setting(self):
        sync = AfSync(self.root, self.store, FakeBlacklist([]), FakeAf())
        sync.record({'at': time.time()}, [])
        for enabled in (False, True):
            sync.stop_event.clear()
            sync.request_sync()
            with patch('af_firewall.af_settings', return_value={'enabled': enabled, 'interval': 86400}), \
                    patch.object(sync, 'sync') as call, \
                    patch.object(sync.wake_event, 'wait', side_effect=lambda _: sync.stop_event.set()):
                sync.run()
                self.assertEqual(call.call_count, int(enabled))

    def test_removes_only_own_stale_entries(self):
        af = FakeAf([{'url': '1.1.1.1', 'description': MARK + ' old'}, {'url': '2.2.2.2', 'description': '人工'},
                     {'url': '3.3.3.3', 'description': MARK + ' old'}])
        _, result = self.sync(['3.3.3.3'], af)
        self.assertEqual({i['url'] for i in af.items}, {'2.2.2.2', '3.3.3.3'})
        self.assertEqual(result['status']['removed'], 1)

    def test_empty_source_never_mass_removes(self):
        af = FakeAf([{'url': '1.1.1.1', 'description': MARK}])
        _, result = self.sync([], af)
        self.assertEqual(len(af.items), 1)
        self.assertEqual(result['log'][0]['action'], 'held')

    def test_incomplete_waf_list_stops_before_touching_af(self):
        class Broken:
            def snapshot(self):
                raise SecurityError('存在无法完整展开的黑名单规则', 503)
        af = FakeAf()
        sync = AfSync(self.root, self.store, Broken(), af)
        with self.assertRaises(SecurityError):
            sync.sync()
        self.assertEqual(af.calls, [])
        self.assertIn('无法完整展开', sync.status()['error'])

    def test_settings_keep_password_and_validate_url(self):
        save_af_settings(self.root, {'url': 'https://192.0.2.9:4430/', 'password': '', 'enabled': True, 'interval': 120})
        config = af_settings(self.root)
        self.assertEqual((config['url'], config['password'], config['enabled']), ('https://192.0.2.9:4430', 'secret', True))
        for bad in ({'url': 'http://192.0.2.9'}, {'url': 'https://a/api'}, {'interval': 5}, {'namespace': 'a b'}):
            with self.assertRaises(ValueError):
                save_af_settings(self.root, bad)


class AfClientTests(unittest.TestCase):
    """Wire format against the AF 8.0.107 API document."""

    def client(self, replies):
        sent = []

        def opener(req, timeout):
            sent.append(req)
            body = replies.pop(0)
            return io.BytesIO(json.dumps(body).encode())

        client = AfClient({'url': 'https://192.0.2.1', 'username': 'api', 'password': 'pw', 'namespace': 'public',
                           'verifyTls': False})
        client.opener = type('O', (), {'open': staticmethod(lambda req, timeout: _Response(opener(req, timeout)))})
        return client, sent

    def test_login_add_list_delete(self):
        client, sent = self.client([
            {'code': 0, 'data': {'loginResult': {'token': 'TOKEN'}, 'role': 'ADMINISTRATOR'}, 'message': '成功'},
            {'code': 0, 'data': [{'url': '1.2.3.4'}], 'message': '成功'},
            {'code': 0, 'data': {'totalItems': 1, 'items': [{'url': '1.2.3.4', 'description': MARK}]}},
            {'code': 0, 'data': {}, 'message': '成功'}])
        client.login()
        client.add([{'url': '1.2.3.4', 'type': 'BLACK'}])
        self.assertEqual(client.blacklist()[0]['url'], '1.2.3.4')
        client.delete('9.9.9.0/24')
        self.assertEqual(sent[0].full_url, 'https://192.0.2.1/api/v1/namespaces/public/login')
        self.assertEqual(json.loads(sent[0].data), {'name': 'api', 'password': 'pw'})
        self.assertEqual(sent[1].full_url, 'https://192.0.2.1/api/batch/v1/namespaces/public/whiteblacklist?override=SKIP')
        self.assertEqual(sent[1].get_header('Cookie'), 'token=TOKEN')
        self.assertIn('type=BLACK', sent[2].full_url)
        self.assertEqual((sent[3].get_method(), sent[3].full_url),
                         ('DELETE', 'https://192.0.2.1/api/v1/namespaces/public/whiteblacklist/9.9.9.0%2F24'))

    def test_error_codes_top_level_and_nested(self):
        client, _ = self.client([{'code': 1, 'data': '', 'message': 'fail'}])
        with self.assertRaisesRegex(SecurityError, '账号或密码'):
            client.login()
        client, _ = self.client([{'code': 0, 'message': 'success', 'data': {'code': 13, 'message': 'denied', 'data': ''}}])
        with self.assertRaisesRegex(SecurityError, 'WEB API 权限'):
            client.blacklist()

    def test_requires_https_and_credentials(self):
        with self.assertRaises(ValueError):
            AfClient({'url': 'http://192.0.2.1', 'username': 'a', 'password': 'b', 'namespace': 'public', 'verifyTls': True})
        with self.assertRaises(SecurityError):
            AfClient({'url': 'https://192.0.2.1', 'username': '', 'password': '', 'namespace': 'public', 'verifyTls': True})


class _Response:
    status = 200

    def __init__(self, stream):
        self.stream = stream

    def read(self, size=-1):
        return self.stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


if __name__ == '__main__':
    unittest.main()
