import ipaddress
import json
from pathlib import Path
import struct
import sys
import tempfile
import threading
import unittest
from urllib import request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from geoip import GeoIP
from server import LogServer
from storage import Store

REGIONS = [('1.2.3.0', '1.2.3.255', '中国|湖北省|武汉市|电信|CN'), ('1.2.4.0', '1.2.4.255', '中国|0|0|阿里|CN'),
           ('8.8.8.0', '8.8.8.255', 'United States|California|0|Google LLC|US')]


def build_xdb(path):
    """A minimal ip2region 3.0 IPv4 xdb holding REGIONS."""
    header = bytearray(256)
    struct.pack_into('<HHIIIHH', header, 0, 3, 1, 0, 0, 0, 4, 4)
    vector = bytearray(256 * 256 * 8)
    body, base = bytearray(), 256 + len(vector)
    pointers = []
    for _, _, region in REGIONS:
        pointers.append(base + len(body)); body += region.encode('utf-8')
    groups = {}
    for (first, last, region), pointer in zip(REGIONS, pointers):
        a, b = ipaddress.ip_address(first), ipaddress.ip_address(last)
        groups.setdefault(a.packed[:2], []).append(struct.pack('<IIHI', int(a), int(b), len(region.encode()), pointer))
    for key, segments in groups.items():
        start = base + len(body)
        body += b''.join(segments)
        struct.pack_into('<II', vector, (key[0] * 256 + key[1]) * 8, start, start + (len(segments) - 1) * 14)
    path.write_bytes(bytes(header) + bytes(vector) + bytes(body))


class GeoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        build_xdb(self.root / 'ip2region_v4.xdb')
        self.geo = GeoIP(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_lookup_labels(self):
        self.assertTrue(self.geo.available)
        self.assertEqual(self.geo.lookup('1.2.3.4'), '湖北省 武汉市 电信')  # 中国 and CN are dropped
        self.assertEqual(self.geo.lookup('1.2.4.9'), '阿里')
        self.assertEqual(self.geo.lookup('8.8.8.8'), 'United States California Google LLC')
        self.assertEqual(self.geo.lookup('9.9.9.9'), '')
        self.assertEqual(self.geo.lookup('10.20.31.150'), '内网')
        self.assertEqual(self.geo.lookup('127.0.0.1'), '本机')
        self.assertEqual(self.geo.lookup('::ffff:1.2.3.4'), '湖北省 武汉市 电信')
        self.assertEqual(self.geo.lookup('not-an-ip'), '')

    def test_missing_file_and_validation(self):
        missing = GeoIP(self.root / 'nowhere')
        self.assertFalse(missing.available)
        self.assertIn('未找到', missing.error)
        self.assertEqual(missing.lookup('1.2.3.4'), '')
        self.assertEqual(missing.lookup('192.168.1.1'), '内网')
        with self.assertRaises(ValueError):
            self.geo.lookup_many(['1.1.1.1'] * 1001)

    def test_api(self):
        store = Store(self.root / 'state.sqlite3')

        class Panel:
            config = {'url': 'http://127.0.0.1:1', 'prefix': '/api/v2'}
        server = LogServer(('127.0.0.1', 0), Panel(), store, geo=self.geo)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            req = request.Request(f'http://127.0.0.1:{server.server_port}/api/geo', data=json.dumps({'ips': ['1.2.3.4', '8.8.8.8']}).encode(),
                                  headers={'Content-Type': 'application/json'})
            with request.urlopen(req, timeout=5) as response:
                data = json.load(response)
            self.assertEqual(data['geo'], {'1.2.3.4': '湖北省 武汉市 电信', '8.8.8.8': 'United States California Google LLC'})
        finally:
            server.shutdown(); server.server_close(); store.close()


if __name__ == '__main__':
    unittest.main()
