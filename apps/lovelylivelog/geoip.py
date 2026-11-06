"""Offline IP location from an ip2region xdb file (https://github.com/lionsoul2014/ip2region, Apache-2.0).

data/ip2region_v4.xdb is read into memory once (about 11 MB). Layout: a 256-byte header, a
256 x 256 vector index of (start, end) segment pointers keyed by the first two IP bytes, then
14-byte segments (start IP, end IP as little-endian uint32, region length uint16, region pointer
uint32) searched by bisection. Nothing is sent to an online service.
"""
import ipaddress
from pathlib import Path
import struct
import threading

HEADER, VECTOR_COLS, VECTOR_SIZE, SEGMENT = 256, 256, 8, 14
CACHE_LIMIT = 50000


class GeoIP:
    def __init__(self, directory):
        self.path = Path(directory) / 'ip2region_v4.xdb'
        self.data, self.error = None, ''
        self.cache, self.lock = {}, threading.Lock()
        try:
            data = self.path.read_bytes()
            structure, = struct.unpack_from('<H', data, 0)
            ip_version, = struct.unpack_from('<H', data, 16)
            if structure not in (2, 3) or (structure == 3 and ip_version != 4):
                raise ValueError(f'不支持的 xdb 文件（结构 {structure}，IP 版本 {ip_version}）')
            self.data = data
        except FileNotFoundError:
            self.error = f'未找到 {self.path.name}，请放到 data 目录后重启平台'
        except (OSError, ValueError, struct.error) as exc:
            self.error = f'GeoIP 数据无法读取：{exc}'

    @property
    def available(self):
        return self.data is not None

    def region(self, packed):
        data = self.data
        index = HEADER + (packed[0] * VECTOR_COLS + packed[1]) * VECTOR_SIZE
        start_ptr, end_ptr = struct.unpack_from('<II', data, index)
        if not start_ptr or not end_ptr:
            return ''
        value = int.from_bytes(packed, 'big')
        low, high = 0, (end_ptr - start_ptr) // SEGMENT
        while low <= high:
            mid = (low + high) >> 1
            first, last, length, pointer = struct.unpack_from('<IIHI', data, start_ptr + mid * SEGMENT)
            if value < first:
                high = mid - 1
            elif value > last:
                low = mid + 1
            else:
                return data[pointer:pointer + length].decode('utf-8', 'replace') if length else ''
        return ''

    @staticmethod
    def label(region):
        """'中国|湖北省|武汉市|电信|CN' -> '湖北省 武汉市 电信'; empty fields and '0' are dropped."""
        parts = [p.strip() for p in region.split('|')]
        if parts and len(parts[-1]) == 2 and parts[-1].isascii() and parts[-1].isupper():
            parts.pop()  # ISO country code duplicates the country name
        if len(parts) > 1 and parts[0] == '中国' and any(p and p != '0' for p in parts[1:]):
            parts.pop(0)  # Most visitors are domestic; the province says enough.
        result = []
        for part in parts:
            if part and part != '0' and part not in result:
                result.append(part)
        return ' '.join(result)

    def lookup(self, ip):
        try:
            address = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return ''
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if address.is_loopback:
            return '本机'
        if address.is_private:
            return '内网'
        if not address.is_global:
            return '保留地址'
        if address.version != 4 or not self.data:
            return ''
        key = address.packed
        with self.lock:
            if key in self.cache:
                return self.cache[key]
        label = self.label(self.region(key))
        with self.lock:
            if len(self.cache) >= CACHE_LIMIT:
                self.cache.clear()
            self.cache[key] = label
        return label

    def lookup_many(self, ips):
        if not isinstance(ips, list) or len(ips) > 1000 or any(not isinstance(ip, str) or len(ip) > 64 for ip in ips):
            raise ValueError('一次最多查询 1000 个 IP。')
        return {'geo': {ip: self.lookup(ip) for ip in dict.fromkeys(ips)}, 'available': self.available, 'error': self.error}
