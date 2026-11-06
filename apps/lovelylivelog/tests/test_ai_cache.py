import copy
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ai_cache import NormalDecisionCache, normal_cache_candidate


CONFIG = {'provider': 'deepseek', 'model': 'test-model', 'baseUrl': 'https://api.example/v1'}
NORMAL = {'ip': '8.8.8.8', 'is_attack': False, 'confidence': .98, 'attack_type': 'none',
          'reason': '正常业务访问', 'evidence_ids': []}


def event(**changes):
    return {'id': 1, 'website': 0, 'ip': '8.8.8.8', 'method': 'POST', 'target': '/gateway', 'status': 200,
            'userAgent': 'client', 'recordedAt': 1000., '_sourceKey': 'agent:test|post.log',
            '_requestFingerprint': 'a' * 64, '_post_body': True, 'truncated': False,
            'requestBody': {'operation': 'query', 'token': '[REDACTED]'},
            'bodyMeta': {'state': 'decoded', 'unresolved': 0, 'truncated': False}, **changes}


def candidate(**changes):
    return normal_cache_candidate([event(**changes)], CONFIG, 'prompt-v1')


class CandidateTests(unittest.TestCase):
    def test_only_complete_low_volume_one_ip_one_pattern_is_eligible(self):
        self.assertIsNotNone(candidate())
        self.assertIsNotNone(candidate(bodyMeta={'state': 'decrypted', 'unresolved': 0, 'truncated': False}))
        for changes in ({'truncated': True}, {'_historical': True}, {'_daily': True}, {'status': 403},
                        {'timeReliable': False}, {'_requestFingerprint': ''}, {'_count': 4}, {'recordedAt': None},
                        {'bodyMeta': {'state': 'encrypted', 'unresolved': 0, 'truncated': False}},
                        {'bodyMeta': {'state': 'decoded', 'unresolved': 1, 'truncated': False}},
                        {'bodyMeta': {'state': 'decoded', 'unresolved': 0, 'truncated': True}}):
            with self.subTest(changes=changes):
                self.assertIsNone(candidate(**changes))
        for second in (event(ip='1.1.1.1'), event(_requestFingerprint='b' * 64),
                       event(_sourceKey='agent:other|post.log')):
            self.assertIsNone(normal_cache_candidate([event(), second], CONFIG, 'prompt-v1'))

    def test_original_fingerprint_and_all_model_context_change_key(self):
        first = candidate().key
        for changes in ({'_requestFingerprint': 'b' * 64}, {'ip': '1.1.1.1'}, {'target': '/other'},
                        {'userAgent': 'other'}, {'status': 201}, {'_sourceKey': 'agent:other|post.log'},
                        {'requestBody': {'operation': 'other'}}):
            self.assertNotEqual(first, candidate(**changes).key)
        for changes in ({'provider': 'openai'}, {'model': 'other'}, {'baseUrl': 'https://other.example/v1'},
                        {'key': 'test-only-different-credential'}):
            self.assertNotEqual(first, normal_cache_candidate([event()], {**CONFIG, **changes}, 'prompt-v1').key)
        self.assertNotEqual(first, normal_cache_candidate([event()], CONFIG, 'prompt-v2').key)
        self.assertEqual(first, candidate(id=999, recordedAt=1100).key)

    def test_occurrences_and_time_span_are_not_ignored(self):
        base = candidate().key
        one = normal_cache_candidate([event(), event(id=2, recordedAt=1001)], CONFIG, 'prompt-v1')
        faster = normal_cache_candidate([event(), event(id=2, recordedAt=1000.1)], CONFIG, 'prompt-v1')
        self.assertNotEqual(base, one.key)
        self.assertNotEqual(one.key, faster.key)


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.entries = {}
        self.now = 1000.
        self.cache = NormalDecisionCache(lambda key: copy.deepcopy(self.entries.get(key)),
                                        lambda key, value: self.entries.__setitem__(key, copy.deepcopy(value)),
                                        clock=lambda: self.now)

    def seed(self, value=NORMAL):
        lease = self.cache.acquire(candidate())
        self.assertEqual(lease.state, 'owner')
        self.cache.finish(lease, value)

    def test_exact_normal_reuse_rebinds_to_current_events_without_stale_ids(self):
        self.seed({**NORMAL, 'evidence_ids': [123]})
        self.now += 10
        lease = self.cache.acquire(candidate(id=456, recordedAt=1010))
        self.assertEqual(lease.state, 'hit')
        self.assertEqual(lease.verdict['evidence_ids'], [])
        self.assertEqual(lease.verdict['ip'], '8.8.8.8')

    def test_attack_and_failure_never_populate_cache_and_release_owner(self):
        for value in ({**NORMAL, 'is_attack': True, 'attack_type': 'scanner'}, None):
            self.seed(value)
            self.assertEqual(self.entries, {})
        with self.assertRaisesRegex(RuntimeError, 'test failure'):
            self.cache.get_or_analyze(candidate(), lambda: (_ for _ in ()).throw(RuntimeError('test failure')))
        lease = self.cache.acquire(candidate(), timeout=0)
        self.assertEqual(lease.state, 'owner')
        self.cache.abort(lease)

    def test_cache_expires_and_rapid_repeats_require_model(self):
        self.seed()
        lease = self.cache.acquire(candidate(recordedAt=1001))
        self.assertEqual(lease.state, 'owner')
        self.cache.abort(lease)
        self.now += 301
        lease = self.cache.acquire(candidate(recordedAt=1301))
        self.assertEqual(lease.state, 'owner')
        self.cache.abort(lease)

    def test_per_ip_budget_survives_refresh_and_applies_across_patterns(self):
        self.seed()
        for at in (1010, 1020, 1030):
            self.now = at
            self.assertEqual(self.cache.acquire(candidate(recordedAt=at)).state, 'hit')
        self.now = 1040
        lease = self.cache.acquire(candidate(recordedAt=1040))
        self.assertEqual(lease.state, 'owner')
        self.cache.finish(lease, NORMAL)
        lease = self.cache.acquire(candidate(recordedAt=1050))
        self.assertEqual(lease.state, 'owner')
        self.cache.abort(lease)
        other = candidate(_requestFingerprint='b' * 64, recordedAt=1040)
        self.cache.finish(self.cache.acquire(other), NORMAL)
        lease = self.cache.acquire(candidate(_requestFingerprint='b' * 64, recordedAt=1050))
        self.assertEqual(lease.state, 'owner')
        self.cache.abort(lease)

    def test_malformed_or_future_dated_entries_are_misses(self):
        self.seed()
        for changes in ({'created': 'bad'}, {'expires': None}, {'event_at': float('nan')}, {'created': 2000}):
            stored = copy.deepcopy(self.entries[candidate().key])
            self.entries[candidate().key].update(changes)
            lease = self.cache.acquire(candidate(recordedAt=1010))
            self.assertEqual(lease.state, 'owner')
            self.cache.abort(lease)
            self.entries[candidate().key] = stored

    def test_failed_persistence_releases_single_flight(self):
        owner = self.cache.acquire(candidate())
        def fail(key, value):
            raise OSError('test storage unavailable')
        self.cache.write = fail
        with self.assertRaises(OSError):
            self.cache.finish(owner, NORMAL)
        retry = self.cache.acquire(candidate(), timeout=0)
        self.assertEqual(retry.state, 'owner')
        self.cache.abort(retry)

    def test_single_flight_waiter_reuses_owner_result(self):
        owner = self.cache.acquire(candidate())
        started = threading.Event()
        def wait():
            started.set()
            return self.cache.acquire(candidate(recordedAt=1010), timeout=1)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(wait)
            self.assertTrue(started.wait(1))
            self.assertFalse(future.done())
            self.cache.finish(owner, NORMAL)
            self.assertEqual(future.result(1).state, 'hit')

    def test_wait_timeout_never_owns_or_calls_model(self):
        owner = self.cache.acquire(candidate())
        called = []
        with self.assertRaises(TimeoutError):
            self.cache.get_or_analyze(candidate(), lambda: called.append(True), timeout=0)
        self.assertEqual(called, [])
        self.cache.abort(owner)

    def test_sqlite_persistence_reuses_after_cache_object_restart(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'cache.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE cache (key TEXT PRIMARY KEY, value TEXT)')
                def read(key):
                    row = db.execute('SELECT value FROM cache WHERE key=?', (key,)).fetchone()
                    return json.loads(row[0]) if row else None
                def write(key, value):
                    db.execute('INSERT OR REPLACE INTO cache VALUES(?,?)', (key, json.dumps(value)))
                    db.commit()
                first = NormalDecisionCache(read, write, clock=lambda: 1000)
                first.finish(first.acquire(candidate()), NORMAL)
                restarted = NormalDecisionCache(read, write, clock=lambda: 1010)
                lease = restarted.acquire(candidate(recordedAt=1010))
                self.assertEqual(lease.state, 'hit')
                self.assertNotIn('requestBody', db.execute('SELECT value FROM cache').fetchone()[0])


if __name__ == '__main__':
    unittest.main()
