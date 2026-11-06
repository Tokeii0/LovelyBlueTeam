from contextlib import closing
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hub import Hub
from storage import Store


def event(raw, kind='access.log'):
    return {'eventId': uuid.uuid4().hex, 'raw': raw, 'source': 'D:/nginx/logs/access.log', 'kind': kind,
            'collectedAt': 1700000000}


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.sqlite3'); self.hub = Hub(self.store)
        self.hub.advertised_url = 'http://127.0.0.1:8788'
        self.agent = self.hub.register({'name': 'nginx', 'sources': [{'kind': 'access.log', 'path': 'D:/nginx/logs/access.log'}]})['agentId']

    def tearDown(self):
        self.store.close(); self.temp.cleanup()

    def brute_force(self):
        rows = {}
        for table, source in (('events', 'CAST(website AS TEXT)'), ('agent_events', 'agent_id')):
            for src, kind, state, n in self.store.db.execute(
                    f'SELECT {source},kind,ai_state,COUNT(*) FROM {table} GROUP BY 1,2,3'):
                rows[(table, src, kind, state)] = n
        return rows

    def counters(self):
        return {tuple(r[:4]): r[4] for r in self.store.db.execute('SELECT * FROM log_counts WHERE n<>0')}

    def test_nothing_is_pruned(self):
        self.store.append('site', {}, 5, 'access.log', [f'line {i}' for i in range(100050)])
        with self.store.db:
            self.store.db.executemany('''INSERT INTO agent_events(agent_id,event_id,kind,source,raw,collected,received)
                VALUES(?,?,?,?,?,?,?)''', [(self.agent, uuid.uuid4().hex, 'access.log', 's', f'r{i}', 1, 1) for i in range(100050)])
        self.store.append('site', {}, 5, 'access.log', ['one more'])
        self.hub.ingest(self.agent, {'events': [event('one more')]})
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 100051)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM agent_events').fetchone()[0], 100051)
        self.assertEqual(self.hub.overview()['total'], 100051)
        self.assertEqual(self.hub.feed()['total'], 100051)

    def test_counters_follow_inserts_state_changes_and_deletes(self):
        self.store.append('a', {}, 5, 'access.log', ['a1', 'a2', 'a3'])
        self.store.append('e', {}, 5, 'error.log', ['e1'])
        self.store.append('b', {}, 6, 'access.log', ['b1'])
        self.hub.ingest(self.agent, {'events': [event('x1'), event('x2'), event('err', 'error.log')]})
        ids = [r[0] for r in self.store.db.execute("SELECT id FROM events WHERE website=5 AND kind='access.log'")]
        agent_ids = [-r[0] for r in self.store.db.execute("SELECT id FROM agent_events WHERE kind='access.log'")]
        self.store.mark(ids[:2] + agent_ids[:1], 'analyzed')
        self.store.set_ai_excluded(6, True, 'site 6')
        with self.store.db:
            self.store.db.execute('DELETE FROM events WHERE id=?', (ids[2],))
        self.assertEqual(self.counters(), self.brute_force())
        summary = self.store.ai_summary()
        self.assertEqual((summary['analyzed'], summary['pending'], summary['excluded']), (3, 1, 1))
        agent = self.store.ai_summary('agent', self.agent)
        self.assertEqual((agent['analyzed'], agent['pending']), (1, 1))
        self.assertIsNotNone(agent['oldestPendingReceived'])

    def test_website_feed_reports_the_stored_total(self):
        self.store.append('a', {}, 5, 'access.log', [f'a{i}' for i in range(700)])
        self.store.append('e', {}, 5, 'error.log', ['e1', 'e2'])
        self.store.append('b', {}, 6, 'access.log', ['b1'])
        feed = self.store.feed(5, 'access.log', None, 500)
        self.assertEqual((len(feed['events']), feed['total']), (500, 700))
        self.assertEqual(self.store.feed(5, 'error.log', None, 500)['total'], 2)
        self.assertEqual(self.store.stored_total(7, 'access.log'), 0)

    def test_existing_database_is_counted_on_upgrade(self):
        self.store.append('a', {}, 5, 'access.log', ['a1', 'a2'])
        self.hub.ingest(self.agent, {'events': [event('x1')]})
        path = self.root / 'state.sqlite3'
        self.store.close()
        with closing(sqlite3.connect(path)) as db:  # A database from before the counters existed.
            db.executescript('DROP TABLE log_counts; DROP TRIGGER events_count_insert; DROP TRIGGER agent_events_count_insert;')
        self.store = Store(path); self.hub = Hub(self.store)
        self.assertEqual(self.counters(), self.brute_force())

    def test_feed_total_keeps_the_page_snapshot(self):
        self.hub.ingest(self.agent, {'events': [event(f'GET /a/{i} 200') for i in range(150)] + [event('boom', 'error.log')]})
        first = self.hub.feed()
        self.assertEqual((first['total'], first['pages']), (151, 2))
        self.hub.ingest(self.agent, {'events': [event('GET /later 200') for _ in range(30)]})
        older = self.hub.feed(page=2, through=first['through'])
        self.assertEqual(older['total'], 151)
        self.assertEqual(len(older['events']), 51)
        self.assertEqual(self.hub.feed(kind='error.log')['total'], 1)
        self.assertEqual(self.hub.feed(query='/later')['total'], 30)
        self.assertEqual(self.hub.feed(agent_id=self.agent)['total'], 181)


if __name__ == '__main__':
    unittest.main()
