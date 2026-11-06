import json
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from urllib import error, request
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server import LogServer
from syslog_server import SyslogService, parse_message
from security import SecurityError, Waf
from storage import Store
from test_incremental_security import FakePanel


# AF fwlog key/value layout; synthetic addresses and attack names.
IPS = '<134>2026-10-22T10:00:00+08:00 firewall fwlog: 日志类型:IPS防护日志, 策略名称:业务, 漏洞名称:测试漏洞, 源IP:8.8.8.8, 源端口:40000, 目的IP:10.0.0.8, 目的端口:80, 严重等级:高, 动作:拒绝'
WAF = IPS.replace('IPS防护日志', 'Web应用防护日志').replace('测试漏洞', 'SQL注入')


class ParseTests(unittest.TestCase):
    def test_chinese_fields_and_encoding(self):
        for encoding in ('utf-8', 'gb18030'):
            event = parse_message(IPS.encode(encoding))
            self.assertEqual(event['kind'], 'ips')
            self.assertEqual((event['src_ip'], event['dst_ip']), ('8.8.8.8', '10.0.0.8'))
            self.assertEqual((event['title'], event['level'], event['action']), ('测试漏洞', '高', '拒绝'))
            self.assertEqual(event['occurred'], '2026-10-22T10:00:00+08:00')
            self.assertEqual(event['text'], IPS)
            self.assertEqual(event['encoding'], encoding)
        self.assertEqual(parse_message(WAF.encode())['kind'], 'waf')

    def test_json_syslog_with_ipv6_and_colons_inside_url(self):
        raw = '<134>Oct 22 10:00:00 fw fwlog: ' + json.dumps({
            'log_type': 'waf', 'src_ip': '2001:4860::1', 'dst_ip': '10.0.0.8',
            'url': 'http://example/a:b', 'hole_name': '<script>alert(1)</script>'})
        event = parse_message(raw.encode())
        self.assertEqual(event['src_ip'], '2001:4860::1')
        self.assertEqual(event['fields']['url'], 'http://example/a:b')
        self.assertEqual(event['occurred'], 'Oct 22 10:00:00')
        self.assertEqual(event['title'], '<script>alert(1)</script>')

    def test_unknown_not_misclassified_from_payload(self):
        for raw in [b'<134>URL /ips/waf', b'{"log_type":"web","url":"/waf"}', b'\xff\xfe\x80']:
            self.assertIn(parse_message(raw)['kind'], ('unknown', 'other'))
        self.assertEqual(parse_message(b'{"log_type":"ips","hole_name":"\\ud800"}')['title'], '?')
        self.assertEqual(parse_message(('{"a":' + '[' * 2000 + '1' + ']' * 2000 + '}').encode())['kind'], 'unknown')

    def test_automatic_target_cannot_come_from_url_or_ambiguous_fields(self):
        for raw in [
            '日志类型:IPS防护日志, URL:/x, 源IP:8.8.8.8',
            '日志类型:IPS防护日志, 源IP:8.8.8.8, 源IP:9.9.9.9',
            '{"log_type":"ips","src_ip":"8.8.8.8","src_ip":"9.9.9.9"}',
            '{"log_type":"ips","src_ip":"8.8.8.8","源IP":"9.9.9.9"}',
            'URL:/x, 日志类型:IPS防护日志, 源IP:8.8.8.8',
        ]:
            with self.subTest(raw=raw):
                self.assertEqual(parse_message(raw.encode())['block_ip'], '')
        forged = 'log_type=ips src_ip=8.8.8.8 URL=/x, 源IP:9.9.9.9'
        self.assertEqual(parse_message(forged.encode())['block_ip'], '8.8.8.8')


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict('os.environ', {}, clear=True)
        self.env.start()
        self.service = SyslogService(self.root)

    def tearDown(self):
        self.service.stop()
        self.env.stop()
        self.temp.cleanup()

    def listen(self, sender='127.0.0.1'):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.service.save_settings({'enabled': True, 'bind': '127.0.0.1', 'port': port, 'sender': sender})
        self.assertTrue(self.service.public()['listening'])
        return port

    def send(self, *messages):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for message in messages:
                sock.sendto(message, ('127.0.0.1', self.service.config['port']))

    def wait_for(self, predicate):
        end = time.monotonic() + 4
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(.02)
        self.fail('Receiver did not reach the expected state')

    def test_udp_persistence_filtering_duplicates_and_restart(self):
        self.listen()
        self.send(IPS.encode(), WAF.encode(), IPS.encode(), b'unrecognized raw')
        self.wait_for(lambda: self.service.public()['total'] == 4)
        self.assertEqual(self.service.feed({})['total'], 3)
        self.assertEqual(self.service.feed({'kind': 'unknown'})['total'], 1)
        self.assertEqual(self.service.feed({'src_ip': '8.8.8.8', 'query': 'SQL'})['total'], 1)
        self.assertEqual(self.service.feed({'query': '%'})['total'], 0)
        self.service.stop()
        reloaded = SyslogService(self.root)
        self.assertEqual(reloaded.public()['total'], 4)
        self.assertTrue(reloaded.config['enabled'])
        db = sqlite3.connect(self.service.path)
        try:
            self.assertEqual(db.execute('SELECT raw FROM syslog_events ORDER BY id LIMIT 1').fetchone()[0], IPS.encode())
        finally:
            db.close()

    def test_sender_allowlist_and_port_conflict(self):
        self.listen(sender='127.0.0.2')
        self.send(IPS.encode())
        self.wait_for(lambda: self.service.public()['rejected'] == 1)
        self.assertEqual(self.service.public()['total'], 0)
        other = SyslogService(self.root)
        try:
            other.start()
            self.assertFalse(other.public()['listening'])
            self.assertIn('无法监听', other.public()['error'])
        finally:
            other.stop()

    def test_stable_pagination_and_raw_detail(self):
        self.listen()
        for _ in range(6):
            self.send(*([IPS.encode()] * 10))
            time.sleep(.02)
        self.wait_for(lambda: self.service.public()['total'] == 60)
        first = self.service.feed({})
        self.send(WAF.encode())
        self.wait_for(lambda: self.service.public()['total'] == 61)
        second = self.service.feed({'page': 2, 'through': first['through']})
        self.assertEqual((second['total'], len(second['events'])), (60, 10))
        self.assertFalse({e['id'] for e in first['events']} & {e['id'] for e in second['events']})
        detail = self.service.detail(first['events'][0]['id'])
        self.assertEqual(detail['text'], IPS)
        self.assertEqual(detail['fields']['动作'], '拒绝')
        self.assertNotIn('raw', detail)

    def test_stop_drains_received_queue(self):
        self.listen()
        for _ in range(210):
            self.service.inbox.put_nowait((time.time(), '127.0.0.1', WAF.encode()))
        self.service.stop()
        self.assertEqual(self.service.public()['total'], 210)
        self.assertEqual(self.service.inbox.qsize(), 0)

    def test_malformed_inputs_and_time_range(self):
        for body in [{'kind': 'no'}, {'page': True}, {'through': -1}, {'src_ip': 'not-ip'},
                     {'query': '%' * 201}, {'start': 'bad'},
                     {'start': '2026-10-22T10:00', 'end': '2026-10-21T10:00'}]:
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.service.feed(body)
        for body in [{'enabled': 'true'}, {'enabled': True, 'port': 5514, 'bind': '0.0.0.0', 'sender': '0.0.0.0'},
                     {'enabled': True, 'port': 0, 'bind': '0.0.0.0', 'sender': '127.0.0.1'}]:
            with self.assertRaises(ValueError):
                self.service.save_settings(body)

    def test_local_http_routes_and_cross_site_rejection(self):
        server = LogServer(('127.0.0.1', 0), object(), syslog=self.service)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f'http://127.0.0.1:{server.server_port}'
        try:
            with request.urlopen(url + '/api/syslog/status') as response:
                self.assertFalse(json.load(response)['listening'])
            req = request.Request(url + '/api/syslog/search', data=b'{}', headers={'Content-Type': 'application/json'})
            with request.urlopen(req) as response:
                self.assertEqual(json.load(response)['total'], 0)
            req.add_header('Origin', 'https://evil.example')
            with self.assertRaises(error.HTTPError) as caught:
                request.urlopen(req)
            self.assertEqual(caught.exception.code, 403)
        finally:
            server.shutdown(); server.server_close(); thread.join()


class AutoBlockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict('os.environ', {}, clear=True)
        self.env.start()
        (self.root / '.env').write_text(('AI_ANALYSIS_MODE=ai\n' + 'AI_ENABLED=false\nAUTO_BLOCK=false\nAI_ALLOW_PRIVATE_IPS=true\n'
                                      'IP_ALLOWLIST=9.9.9.9\n'), encoding='utf-8')
        self.store = Store(self.root / 'main.sqlite3')
        self.panel = FakePanel()
        self.waf = Waf(self.panel, self.store)
        self.sync = Mock()
        self.service = SyslogService(self.root, self.waf, self.sync)
        self.service.config.update(enabled=True, autoBlock=True, sender='10.30.40.2')

    def tearDown(self):
        self.service.stop()
        self.store.close()
        self.env.stop()
        self.temp.cleanup()

    def put(self, ip='8.8.8.8', kind='ips', peer='10.30.40.2', action='允许'):
        raw = json.dumps({'log_type': kind, 'src_ip': ip, 'dst_ip': '1.1.1.1',
                          'hole_name': '测试攻击', 'net_action': action}).encode()
        event = parse_message(raw)
        with sqlite3.connect(self.service.path) as db:
            db.execute('''INSERT INTO syslog_events
                (received,peer,raw,text,encoding,kind,occurred,src_ip,dst_ip,level,action,title,fields)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                       (time.time(), peer, raw, *(event[k] for k in
                        ('text', 'encoding', 'kind', 'occurred', 'src_ip', 'dst_ip', 'level', 'action', 'title')),
                        json.dumps(event['fields'])))
        db.close()

    def blocks(self):
        db = self.service.reader()
        try:
            return {r['ip']: dict(r) for r in db.execute('SELECT * FROM syslog_blocks')}
        finally:
            db.close()

    def test_waf_and_ips_block_source_only_without_ai_and_dedupe(self):
        self.put(); self.put(kind='waf', action='拒绝')
        self.service.block_once()
        self.assertEqual([r['ipv4'] for r in self.panel.black], ['8.8.8.8'])
        self.assertTrue(self.panel.black[0]['description'].startswith('AFSyslog [afsyslog_'))
        self.assertEqual(self.blocks()['8.8.8.8']['hits'], 2)
        self.sync.request_sync.assert_called_once()
        # Re-open the archive / checkpoint; a repeated hit does not write a second rule.
        self.service = SyslogService(self.root, self.waf, self.sync)
        self.service.config.update(enabled=True, autoBlock=True, sender='10.30.40.2')
        self.put()
        self.service.block_once()
        self.assertEqual(len(self.panel.black), 1)
        self.assertEqual(self.blocks()['8.8.8.8']['hits'], 3)
        self.assertEqual(self.service.feed({})['events'][0]['blocking']['state'], 'listed')

    def test_private_reserved_mapped_allowlist_and_device_are_never_blocked(self):
        for ip in ['10.0.0.1', '172.16.0.1', '192.168.1.1', '127.0.0.1', '100.64.0.1',
                   '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '::ffff:10.0.0.2', '9.9.9.9']:
            self.put(ip)
        self.service.block_once()
        self.assertEqual(self.panel.black, [])
        self.assertEqual({r['state'] for r in self.blocks().values()}, {'protected'})

    def test_other_types_wrong_sender_and_missing_source_do_not_trigger(self):
        for kind in ['web', 'utm', 'dos', 'mail']:
            self.put(kind=kind)
        self.put(peer='10.0.0.99')
        self.put(ip='')
        self.service.block_once()
        self.assertEqual(self.blocks(), {})
        self.assertEqual(self.panel.black, [])

    def test_whitelist_and_manual_unblock_protection(self):
        self.panel.white = [{'name': 'trusted', 'type': 'ipv4', 'ipv4': '8.8.8.8', 'state': 'on'}]
        self.store.set_block('1.0.0.1', 'old', True, 'unblocked')
        self.put(); self.put('1.0.0.1')
        self.service.block_once()
        self.assertEqual(self.panel.black, [])
        self.assertEqual({r['state'] for r in self.blocks().values()}, {'protected'})

    def test_failed_action_retries_without_losing_or_replaying_logs(self):
        self.put()
        with patch.object(self.waf, 'add', side_effect=SecurityError('临时失败')):
            self.service.block_once()
        item = self.blocks()['8.8.8.8']
        self.assertEqual((item['state'], item['attempts'], item['hits']), ('failed', 1, 1))
        self.service.block_once()
        self.assertEqual(self.panel.black, [])
        with patch('syslog_server.time.time', return_value=item['retry_at'] + 1):
            self.service.block_once()
        self.assertEqual(self.blocks()['8.8.8.8']['state'], 'listed')
        self.assertEqual(len(self.panel.black), 1)

    def test_pause_and_change_during_remote_prechecks_prevent_write(self):
        self.put()
        self.service.config['autoBlock'] = False
        self.service.block_once()
        self.assertEqual(self.blocks(), {})
        self.service.config['autoBlock'] = True
        self.panel.before_create = lambda: self.service.config.update(autoBlock=False)
        self.service.block_once()
        self.assertEqual(self.panel.black, [])
        self.assertEqual(self.blocks()['8.8.8.8']['state'], 'pending')
        self.service.config['autoBlock'] = True
        self.service.block_once()
        self.assertEqual(len(self.panel.black), 1)

    def test_udp_to_background_blocker_and_manual_unblock_stays_protected(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.service.save_settings({'enabled': True, 'autoBlock': True, 'bind': '127.0.0.1',
                                    'port': port, 'sender': '127.0.0.1'})
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(IPS.encode(), ('127.0.0.1', port))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.blocks().get('8.8.8.8', {}).get('state') == 'listed':
                break
            time.sleep(.02)
        self.assertEqual(self.blocks()['8.8.8.8']['state'], 'listed')
        self.waf.remove('8.8.8.8')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(IPS.encode(), ('127.0.0.1', port))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.blocks().get('8.8.8.8', {}).get('state') == 'protected':
                break
            time.sleep(.02)
        self.assertEqual(self.blocks()['8.8.8.8']['state'], 'protected')
        self.assertEqual(self.panel.black, [])


if __name__ == '__main__':
    unittest.main()
