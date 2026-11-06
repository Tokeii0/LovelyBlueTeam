from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from storage import Store

LINE = '203.0.113.7 - - [14/Oct/2026:10:00:00 +0800] "GET /vpn HTTP/1.1" 200 1'


class SiteAiExclusionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / 'state.sqlite3')

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def states(self, website):
        return [row[0] for row in self.store.db.execute('SELECT ai_state FROM events WHERE website=? ORDER BY id', (website,))]

    def test_excluded_site_is_collected_but_never_queued(self):
        self.store.append('a', {}, 10, 'access.log', [LINE, LINE])
        self.store.append('b', {}, 11, 'access.log', [LINE])
        self.store.set_ai_excluded(10, True, 'vpn.example.com')
        # Queued records leave the queue; other websites are untouched.
        self.assertEqual(self.states(10), ['excluded', 'excluded'])
        self.store.append('a', {}, 10, 'access.log', [LINE])
        self.store.append('a', {}, 10, 'error.log', [LINE])
        self.assertEqual(self.states(10), ['excluded', 'excluded', 'excluded', 'ignored'])
        self.assertEqual({row['website'] for row in self.store.pending(100)}, {11})
        self.assertEqual(self.store.excluded_sites(), {10})
        self.assertEqual(self.store.ai_summary('panel')['excluded'], 3)
        # Logs remain visible in the feed.
        self.assertEqual(len(self.store.feed(10, 'access.log', None, 100)['events']), 3)

    def test_resuming_analyses_only_new_records(self):
        self.store.set_ai_excluded(10, True)
        self.store.append('a', {}, 10, 'access.log', [LINE])
        self.store.set_ai_excluded(10, False)
        self.store.append('a', {}, 10, 'access.log', [LINE])
        self.assertEqual(self.states(10), ['excluded', 'pending'])
        self.assertEqual(self.store.excluded_sites(), set())

    def test_invalid_arguments_are_rejected(self):
        for website, excluded in ((0, True), ('10', True), (10, 'yes'), (True, True)):
            with self.assertRaises(ValueError):
                self.store.set_ai_excluded(website, excluded)


if __name__ == '__main__':
    unittest.main()
