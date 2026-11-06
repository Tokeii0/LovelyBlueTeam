from datetime import date, datetime
import os
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.agent import Agent, load_config
from agent.log_cleaner import DailyCleaner, candidate_files, day_files, parse_line
from analysis_batches import compact_events
from hub import ai_state
from security import normalized_event


def line(ip, when, request, status=200):
    return (f'remote_addr:{ip},time_local:[{when} +0800],request:{request},status:{status},'
            f'upstream_status:{status},upstream_addr:10.20.30.4:19101,request_time:0.015,upstream_response_time:0.015')


DAY = [
    line('1.1.1.1', '14/Oct/2026:23:59:59', 'GET /gateway HTTP/1.1'),
    line('1.1.1.1', '15/Oct/2026:01:00:00', 'POST /gateway?sys_track_code=a1 HTTP/1.1'),
    line('1.1.1.1', '15/Oct/2026:02:00:00', 'POST /gateway?sys_track_code=b2 HTTP/1.1'),
    line('1.1.1.1', '15/Oct/2026:02:00:01', 'GET /img/FunLineIcon-1.png HTTP/1.1'),
    line('1.1.1.1', '15/Oct/2026:02:00:02', 'OPTIONS /gateway HTTP/1.1', 204),
    line('6.6.6.6', '15/Oct/2026:03:00:00', 'GET /app/actuator/env HTTP/1.1', 404),
    line('6.6.6.6', '15/Oct/2026:03:00:01', "GET /render.html?app_id=test%27%22%3E%3Csvg/onload%3Dalert(1)%3E HTTP/1.1"),
    line('6.6.6.6', '15/Oct/2026:03:00:02', 'GET /home HTTP/1.1'),
    line('7.7.7.7', '15/Oct/2026:04:00:00', 'GET /rare/missing.json HTTP/1.1', 404),
    '\x03\x00 garbage that is not a log line [15/Oct/2026:01:00:00 +0800]',
    line('1.1.1.1', '16/Oct/2026:00:00:01', 'GET /gateway HTTP/1.1'),
] + [line(f'2.2.2.{n}', '15/Oct/2026:05:00:00', 'GET /page/bootstrap.json HTTP/1.1', 404) for n in range(6)]


class CleanerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def clean(self, lines, day=date(2026, 10, 15)):
        path = self.dir / 'access_2026-10-15.log'
        path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        cleaner = DailyCleaner(day)
        cleaner.feed(path)
        rows = [json.loads(r) for r in cleaner.rows()]
        return rows, cleaner.report(len(rows))

    def test_key_value_line_with_commas_and_injected_status(self):
        item = parse_line('remote_addr:1.2.3.4,time_local:[15/Oct/2026:09:17:23 +0800],request:GET /a,status:200,x HTTP/1.1,'
                          'status:200,upstream_status:502, 200,upstream_addr:10.0.0.1:1, 10.0.0.1:2,request_time:1.005,'
                          'upstream_response_time:1.001, 0.004')
        self.assertEqual((item['ip'], item['method'], item['target'], item['status'], item['requestTime']),
                         ('1.2.3.4', 'GET', '/a,status:200,x', 200, 1.005))

    def test_only_target_day_is_kept_and_noise_dropped(self):
        rows, report = self.clean(DAY)
        self.assertEqual(report['otherDay'], 2)
        self.assertEqual(report['malformed'], 1)
        self.assertEqual((report['droppedStatic'], report['droppedPreflight']), (1, 1))
        self.assertTrue(all(r['clean_date'] == '2026-10-15' for r in rows))
        self.assertFalse(any('16/Oct' in r['time_local'] or '14/Oct' in r['time_local'] for r in rows))

    def test_successful_calls_aggregate_by_path_with_real_count(self):
        rows, _ = self.clean(DAY)
        gateway = [r for r in rows if r['remote_addr'] == '1.1.1.1' and r['request'].startswith('POST')]
        self.assertEqual(len(gateway), 1)
        self.assertEqual(gateway[0]['count'], 2)
        self.assertIn('a1', gateway[0]['request'])
        self.assertIn('b2', gateway[0]['last_request'])
        self.assertFalse(gateway[0]['clean_ai'])

    def test_attacks_go_to_ai_verbatim_with_context(self):
        rows, report = self.clean(DAY)
        attacker = {r['request']: r for r in rows if r['remote_addr'] == '6.6.6.6'}
        self.assertEqual({r['clean_kind'] for r in attacker.values()}, {'suspicious', 'normal'})
        self.assertTrue(all(r['clean_ai'] for r in attacker.values()))  # /home is context for the model
        self.assertIn('%3Csvg/onload', next(k for k in attacker if 'render' in k))
        rare = next(r for r in rows if r['remote_addr'] == '7.7.7.7')
        self.assertTrue(rare['clean_ai'])
        widespread = [r for r in rows if r['remote_addr'].startswith('2.2.2.')]
        self.assertEqual(len(widespread), 6)
        self.assertFalse(any(r['clean_ai'] for r in widespread))
        self.assertEqual(report['aiIps'], 2)

    def test_row_cap_keeps_ai_rows_first(self):
        path = self.dir / 'big.log'
        path.write_text('\n'.join(DAY), encoding='utf-8')
        cleaner = DailyCleaner(date(2026, 10, 15), max_rows=3)
        cleaner.feed(path)
        rows = [json.loads(r) for r in cleaner.rows()]
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(r['clean_ai'] for r in rows))
        self.assertTrue(all(len(r) < 16384 for r in cleaner.rows()))

    def test_lines_in_a_file_nginx_never_reopened_are_found(self):
        # nginx kept writing 10-14's file for three more days; 10-16's own file is empty.
        days = [('14', 300), ('15', 400), ('16', 500), ('17', 300)]
        stuck = self.dir / 'access_2026-10-14.log'
        stuck.write_text('\n'.join(line(f'1.1.{d}.{n % 200}', f'{d}/Oct/2026:{n * 86399 // count // 3600:02d}:'
                                         f'{n * 86399 // count // 60 % 60:02d}:{n * 86399 // count % 60:02d}',
                                         f'GET /p{n % 7} HTTP/1.1')
                                    for d, count in days for n in range(count)) + '\n', encoding='utf-8')
        (self.dir / 'access_2026-10-16.log').write_text('', encoding='utf-8')
        old = self.dir / 'access_2026-10-01.log'
        old.write_text(line('9.9.9.9', '16/Oct/2026:10:00:00', 'GET /x HTTP/1.1') + '\n', encoding='utf-8')
        os.utime(old, (0, datetime(2026, 10, 2).timestamp()))  # untouched since 10-02: cannot hold 10-16
        files = day_files(str(self.dir / 'access_{date}.log'), date(2026, 10, 16))
        self.assertEqual([Path(f).name for f in files], ['access_2026-10-14.log', 'access_2026-10-16.log'])
        results = []
        for seek in (False, True):
            with patch('agent.log_cleaner.SEEK_ABOVE', 1024):
                cleaner = DailyCleaner(date(2026, 10, 16), seek=seek)
                for name in files:
                    cleaner.feed(Path(name))
            results.append((cleaner.stats['targetDay'], cleaner.rows(), cleaner.files[0]))
        self.assertEqual(results[0][0], 500)
        self.assertEqual(results[0][:2], results[1][:2])
        self.assertGreater(results[1][2]['skippedBytes'], 0)
        self.assertTrue(results[1][2]['stoppedEarly'])

    def test_candidate_files_cover_neighbouring_days(self):
        self.assertEqual(candidate_files('D:/logs/access_{date}.log', date(2026, 10, 15)),
                         ['D:/logs/access_2026-10-15.log', 'D:/logs/access_2026-10-14.log', 'D:/logs/access_2026-10-16.log'])


class AgentDailyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config_path = self.root / 'config.json'
        self.config_path.write_text(json.dumps({
            'agentId': str(uuid.uuid4()), 'token': 'test-token-1234567890123456789', 'platformUrl': 'http://127.0.0.1:9',
            'initialLines': 0, 'sources': [{'path': str(self.root / 'access_{date}.log'), 'kind': 'access.log', 'mode': 'daily'}]}))
        self.agent = Agent(load_config(self.config_path), self.root / 'state')
        self.agent.clean_in_background = False

    def tearDown(self):
        self.agent.close()
        self.temp.cleanup()

    def queued(self):
        return [event for _, event in self.agent.pending()]

    def test_config_requires_date_placeholder(self):
        data = json.loads(self.config_path.read_text())
        data['sources'][0]['path'] = str(self.root / 'access.log')
        self.config_path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            load_config(self.config_path)

    def test_yesterday_is_cleaned_once_after_run_time(self):
        source = self.agent.config['sources'][0]
        self.assertEqual(self.agent.collect_daily(source, datetime(2026, 10, 16, 0, 10))['status'], 'waiting')
        self.assertEqual(self.agent.collect_daily(source, datetime(2026, 10, 16, 15, 0))['status'], 'missing')
        self.agent.daily_retry.clear()
        # Lines of 10-15 written before rotation into the 10-14 file are picked up too.
        (self.root / 'access_2026-10-14.log').write_text(line('9.9.9.9', '15/Oct/2026:00:30:00', 'GET /x.php HTTP/1.1', 404) + '\n')
        (self.root / 'access_2026-10-15.log').write_text('\n'.join(DAY) + '\n')
        status = self.agent.collect_daily(source, datetime(2026, 10, 16, 15, 0))
        self.assertEqual((status['status'], status['day']), ('ok', '2026-10-15'))
        events = self.queued()
        report = json.loads(next(e['raw'] for e in events if e['kind'] == 'custom.log'))
        self.assertEqual(report['type'], 'daily_clean_report')
        rows = [json.loads(e['raw']) for e in events if e['kind'] == 'access.log']
        self.assertIn('9.9.9.9', {r['remote_addr'] for r in rows})
        self.assertEqual(len(rows), report['rowsEmitted'])
        self.agent.collect_daily(source, datetime(2026, 10, 16, 15, 5))
        self.assertEqual(len(self.queued()), len(events))

    def test_background_cleaning_keeps_the_loop_responsive(self):
        (self.root / 'access_2026-10-15.log').write_text('\n'.join(DAY) + '\n')
        self.agent.clean_in_background = True
        source = self.agent.config['sources'][0]
        first = self.agent.collect_daily(source, datetime(2026, 10, 16, 15, 0))
        self.assertIn(first['status'], ('cleaning', 'ok'))
        for _ in range(200):
            status = self.agent.collect_daily(source, datetime(2026, 10, 16, 15, 0))
            if status['status'] == 'ok':
                break
            self.assertEqual(status['status'], 'cleaning')
            import time; time.sleep(0.02)
        self.assertEqual(status['status'], 'ok')
        self.assertTrue(self.queued())

    def test_cleaning_the_same_day_again_reuses_event_ids(self):
        (self.root / 'access_2026-10-15.log').write_text('\n'.join(DAY) + '\n')
        source = self.agent.config['sources'][0]
        self.agent.collect_daily(source, datetime(2026, 10, 16, 15, 0))
        first = sorted(e['eventId'] for e in self.queued())
        # A fresh state folder (package extracted again) must not create new rows on the platform.
        other = Agent(load_config(self.config_path), self.root / 'state2')
        other.clean_in_background = False
        try:
            other.collect_daily(other.config['sources'][0], datetime(2026, 10, 16, 15, 0))
            self.assertEqual(sorted(e['eventId'] for _, e in other.pending()), first)
        finally:
            other.close()
        self.assertEqual(len(set(first)), len(first))

    def test_manual_day_overrides_schedule(self):
        (self.root / 'access_2026-10-15.log').write_text('\n'.join(DAY) + '\n')
        self.agent.day_override = date(2026, 10, 15)
        status = self.agent.collect_daily(self.agent.config['sources'][0], datetime(2026, 10, 20, 0, 0))
        self.assertEqual((status['status'], status['day']), ('ok', '2026-10-15'))


class PlatformCleanedRowTests(unittest.TestCase):
    def event(self, raw, event_id=-1):
        return {'id': event_id, 'website': 0, 'raw': raw, 'source_type': 'agent', 'agent_id': 'a',
                'source_file': 'D:/logs/access_2026-10-15.log', 'server_name': 'nginx', 'collected': 1}

    def test_key_value_tail_lines_are_analysable(self):
        result = normalized_event(self.event(line('1.2.3.4', '15/Oct/2026:01:10:22', 'GET /a?token=s HTTP/1.1', 404)))
        self.assertEqual((result['ip'], result['method'], result['status']), ('1.2.3.4', 'GET', 404))
        self.assertIn('REDACTED', result['target'])

    def test_cleaned_row_keeps_count_and_is_review_only(self):
        row = {'remote_addr': '6.6.6.6', 'time_local': '15/Oct/2026:03:00:00 +0800', 'request': 'GET /a/actuator/env HTTP/1.1',
               'status': 404, 'count': 18, 'first_time': '15/Oct/2026:03:00:00 +0800', 'last_time': '15/Oct/2026:09:00:00 +0800',
               'last_request': 'GET /a/actuator/env?password=x HTTP/1.1', 'clean_date': '2026-10-15',
               'clean_kind': 'suspicious', 'clean_ai': True}
        raw = json.dumps(row)
        self.assertEqual(ai_state('access.log', raw), 'pending')
        self.assertEqual(ai_state('access.log', json.dumps({**row, 'clean_ai': False})), 'filtered')
        result = normalized_event(self.event(raw))
        self.assertTrue(result['_historical'])
        self.assertIn('REDACTED', result['lastTarget'])
        compact = compact_events([result])
        self.assertEqual(compact[0]['occurrences'], 18)
        self.assertEqual(compact[0]['lastRecordedAt'] - compact[0]['firstRecordedAt'], 6 * 3600)
        self.assertIsNone(normalized_event(self.event(json.dumps({**row, 'count': 0}))))


if __name__ == '__main__':
    unittest.main()
