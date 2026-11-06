from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HoneypotDefaults(unittest.TestCase):
    def test_public_code_has_no_host_collection_entrypoints(self):
        forbidden = ('ReadProcessMemory', 'os.Hostname(', 'os.UserHomeDir(',
                     'getDisplayMedia(', 'localQQNumbers(', 'localWxids(', 'collectHost(')
        for path in (ROOT/'honeypots').rglob('*'):
            if path.suffix not in {'.go', '.js'} or path.name.endswith('_test.go'):
                continue
            source = path.read_text(encoding='utf-8')
            for marker in forbidden:
                self.assertNotIn(marker, source, path.relative_to(ROOT))

    def test_portals_and_container_ports_default_to_loopback(self):
        for file, port in [('vpn/main.go', 8801), ('uds-agent/cmd/portal/main.go', 8802)]:
            source = (ROOT/'honeypots'/file).read_text(encoding='utf-8')
            self.assertIn(f'127.0.0.1:{port}', source)
        compose = (ROOT/'honeypots/deploy/compose.yml').read_text(encoding='utf-8')
        for port in (8801, 8802):
            self.assertIn(f'"127.0.0.1:{port}:8080"', compose)


if __name__ == '__main__':
    unittest.main()
