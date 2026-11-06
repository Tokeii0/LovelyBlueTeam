import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release_scan', ROOT/'scripts/release_scan.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ReleaseGateTests(unittest.TestCase):
    def test_private_files_and_provider_tokens_fail_without_echoing_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'.env').write_text('local configuration', encoding='utf-8')
            secret = 'sk-' + 'A' * 35
            (root/'readme.md').write_text(secret, encoding='utf-8')
            _, findings = gate.scan(root)
            self.assertEqual({f['rule'] for f in findings}, {'private-config', 'provider-token'})
            self.assertNotIn(secret, str(findings))

    def test_binary_and_private_reference_fail_but_examples_are_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'.env.example').write_text('PANEL_API_KEY=\n', encoding='utf-8')
            (root/'sample.exe').write_bytes(b'MZ')
            (root/'case.md').write_text('example private marker', encoding='utf-8')
            _, findings = gate.scan(root, ['private marker'])
            self.assertEqual({f['rule'] for f in findings}, {'unapproved-file-type', 'private-reference'})

    def test_token_in_tests_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'tests').mkdir()
            (root/'tests/test_fixture.py').write_text('sk-' + 'B' * 35, encoding='utf-8')
            self.assertTrue(gate.scan(root)[1])

    def test_honeypot_collectors_and_runtime_exports_cannot_be_packaged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root/'honeypots/vpn'
            project.mkdir(parents=True)
            for name in ('secret_config.go', 'host_logs.go', 'config.json', 'uds-channels-demo.json'):
                (project/name).write_text('placeholder', encoding='utf-8')
            findings = gate.scan(root)[1]
            self.assertEqual(len(findings), 4)
            self.assertEqual({row['rule'] for row in findings}, {'excluded-honeypot-artifact'})

    def test_container_source_allowed_but_binary_payload_still_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'Dockerfile').write_text('FROM scratch\n', encoding='utf-8')
            (root/'.dockerignore').write_text('*.exe\n', encoding='utf-8')
            self.assertFalse(gate.scan(root)[1])
            (root/'Dockerfile').write_bytes(b'FROM scratch\x00')
            self.assertEqual(gate.scan(root)[1][0]['rule'], 'binary-content')


if __name__ == '__main__':
    unittest.main()
