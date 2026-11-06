import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'apps/lovelylivelog'))
from security import settings
from site_rule import SiteVisitRule
from storage import Store


class PublicDefaultsTests(unittest.TestCase):
    def test_missing_settings_cannot_enable_ai_or_automatic_block(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            config = settings(Path(directory))
            self.assertEqual(config['analysisMode'], 'local')
            self.assertFalse(config['autoBlock'])

    def test_example_has_no_credentials_or_enabled_defense(self):
        config = json.loads((ROOT/'apps/lovelylog/config.example.json').read_text(encoding='utf-8'))
        self.assertEqual(config['analysis_mode'], 'local')
        self.assertFalse(config['defense']['enabled'])
        self.assertEqual(config['crypto_profiles'], [])
        self.assertEqual(config['defense']['agent_token'], '')

    def test_decoy_domain_is_configured_and_change_gets_a_new_scope(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            root = Path(directory)
            root.joinpath('.env').write_text('SITE_RULE_DOMAIN=decoy.example.com\n', encoding='utf-8')
            store = Store(root/'test.sqlite3')
            class Panel:
                config = {'url': 'http://127.0.0.1:1', 'prefix': '/api/v2'}
            try:
                first = SiteVisitRule(root, Panel(), store, None)
                self.assertEqual(first.domain, 'decoy.example.com')
                root.joinpath('.env').write_text('SITE_RULE_DOMAIN=another.example.com\n', encoding='utf-8')
                second = SiteVisitRule(root, Panel(), store, None)
                self.assertNotEqual(first.source, second.source)
            finally:
                store.close()


if __name__ == '__main__':
    unittest.main()
