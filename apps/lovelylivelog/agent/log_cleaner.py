"""Clean one calendar day of Nginx access logs into aggregated, AI-ready rows.

Nginx on Windows keeps writing to a renamed file until it reopens its logs, so a
dated file such as access_2026-10-15.log can hold the end of the previous day and
the start of the next one. The cleaner therefore filters by each line's own
time_local rather than trusting the file name.
"""
from collections import Counter
from datetime import date, datetime, timedelta
import glob
import heapq
import ipaddress
import json
import os
import re
from urllib.parse import parse_qsl, unquote, urlsplit


MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
# remote_addr:IP,time_local:[...],request:METHOD URI HTTP/1.1,status:200,upstream_status:...
# The request is attacker-controlled and may itself contain ",status:", so the
# greedy match binds to the last status / upstream_status pair on the line.
KEY_VALUE = re.compile(r'^remote_addr:(?P<ip>[^,]*),time_local:\[(?P<time>[^\]]*)\],request:(?P<request>.*)'
                       r',status:(?P<status>\d{3}),upstream_status:(?P<rest>.*)$', re.S)
COMBINED = re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"\r\n]*)"\s+(?P<status>\d{3})'
                      r'\s+(?:\d+|-)(?:\s+"[^"\r\n]*"\s+"(?P<ua>[^"\r\n]*)")?')
REQUEST_TIME = re.compile(r'(?:^|,)request_time:(\d+(?:\.\d+)?)')
REQUEST_LINE = re.compile(r'^([A-Z]{1,16})\s+(\S.*?)(?:\s+HTTP/\d(?:\.\d)?)?$')
STATIC = re.compile(r'\.(?:png|jpe?g|gif|bmp|webp|svg|ico|css|js|map|woff2?|ttf|eot|otf|mp3|mp4|webm)$', re.I)
SUSPICIOUS = re.compile(
    r'\.\./|\.\.\\|%2e|%00|\x00|<\s*script|javascript:|[\s"\x27/<>;]on[a-z]+\s*=|\bunion\b.+\bselect\b|\bselect\b.+\bfrom\b|'
    r'\b(?:sleep|benchmark|extractvalue|updatexml|load_file)\s*\(|information_schema|xp_cmdshell|\bor\s+\d+=\d+|'
    r"'\s*(?:or|and)\s|\$\{|jndi:|/etc/(?:passwd|shadow)|win\.ini|<\?php|\bcmd(?:\.exe)?=|\b(?:wget|curl|powershell)\b|"
    r'\.(?:php\d?|asp|aspx|cgi|env|git|svn|bak|sql|ini|log|config)(?:$|[/?])|/(?:wp-|phpmyadmin|actuator|cgi-bin|'
    r'\.well-known/security|console|manager/html|jmx-console|solr|druid|swagger|api-docs|nacos)', re.I)
BENIGN_VALUE = re.compile(r'^[\w.\-~*@:]{0,128}$')
DEFAULT_MAX_ROWS = 50000
# The platform accepts rows up to 16 KB; payloads beyond this are marked truncated.
REQUEST_LIMIT = 4000
# An error path returned to this many different clients is a broken page resource, not a probe.
WIDESPREAD_IPS = 5
# Successful requests kept as context for each client that is sent to AI.
CONTEXT_ROWS = 3


# 'block' (必封) is acted on by the platform; while cleaning it keeps the line like 'ai'.
RULE_ACTIONS = ('drop', 'archive', 'ai', 'block')
DEFAULT_OPTIONS = {'dropStatic': True, 'dropPreflight': True, 'widespreadIps': WIDESPREAD_IPS, 'contextRows': CONTEXT_ROWS}


def clean_options(value=None):
    """Validated built-in cleaning switches, falling back to the defaults."""
    options = dict(DEFAULT_OPTIONS)
    for key, current in (value or {}).items():
        if key not in options:
            continue
        if type(options[key]) is bool and type(current) is not bool:
            raise ValueError('内置清洗开关必须是布尔值。')
        if key == 'widespreadIps' and (type(current) is not int or not 2 <= current <= 1000):
            raise ValueError('“多客户端错误”阈值应为 2–1000 个 IP。')
        if key == 'contextRows' and (type(current) is not int or not 0 <= current <= 20):
            raise ValueError('AI 上下文行数应为 0–20。')
        options[key] = current
    return options


def status_ranges(spec):
    """'404, 5xx, 400-403' -> [(404, 404), (500, 599), (400, 403)]."""
    ranges = []
    for token in re.split(r'[,\s]+', spec.strip()):
        if not token:
            continue
        if re.fullmatch(r'[1-5]xx', token, re.I):
            low = int(token[0]) * 100
            ranges.append((low, low + 99))
        elif re.fullmatch(r'\d{3}', token):
            ranges.append((int(token), int(token)))
        elif re.fullmatch(r'\d{3}-\d{3}', token) and int(token[:3]) <= int(token[4:]):
            ranges.append((int(token[:3]), int(token[4:])))
        else:
            raise ValueError(f'状态码条件“{token}”无效，示例：404, 5xx, 400-403。')
    return ranges


def regex(pattern, label):
    if len(pattern) > 500:
        raise ValueError(f'{label}正则不能超过 500 个字符。')
    try:
        return re.compile(pattern, re.I)
    except re.error as exc:
        raise ValueError(f'{label}正则无效：{exc}') from None


class Rule:
    """One user cleaning rule; every filled condition must match."""

    def __init__(self, data):
        self.id = data.get('id', 0)
        self.name = str(data.get('name') or '')
        self.action = data.get('action')
        if self.action not in RULE_ACTIONS:
            raise ValueError('规则动作应为 丢弃、仅存档、强制送 AI 或 必封。')
        self.include_suspicious = data.get('includeSuspicious') is True
        ips, methods = str(data.get('ip') or '').strip(), str(data.get('method') or '').strip()
        statuses, path, ua = str(data.get('status') or '').strip(), str(data.get('path') or ''), str(data.get('ua') or '')
        try:
            self.networks = [ipaddress.ip_network(v, strict=False) for v in re.split(r'[,\s]+', ips) if v]
        except ValueError:
            raise ValueError('IP 条件应为逗号分隔的 IP 或 CIDR。') from None
        self.methods = {v.upper() for v in re.split(r'[,\s]+', methods) if v}
        if any(not re.fullmatch(r'[A-Z]{1,16}', m) for m in self.methods):
            raise ValueError('请求方法应为 GET、POST 等，逗号分隔。')
        self.statuses = status_ranges(statuses)
        self.path = regex(path, '路径') if path else None
        self.ua = regex(ua, 'User-Agent ') if ua else None
        if not (self.networks or self.methods or self.statuses or self.path or self.ua):
            raise ValueError('至少填写一个匹配条件。')
        if self.action == 'block' and not (self.path or self.ua):
            # Blocking on IP / status alone would blacklist ordinary visitors in bulk.
            raise ValueError('必封规则需要填写路径正则或 User-Agent 正则，例如路径 /\\.env。')

    def matches(self, ip, method, target, status, ua=''):
        if self.methods and method.upper() not in self.methods:
            return False
        if self.statuses and not any(low <= status <= high for low, high in self.statuses):
            return False
        if self.path and not self.path.search(target):
            return False
        if self.ua and not self.ua.search(ua or ''):
            return False
        if self.networks:
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                return False
            if not any(address in network for network in self.networks):
                return False
        return True


def compile_rules(items):
    return [Rule(item) for item in items or [] if item.get('enabled', True)]


def is_suspicious(method, target):
    return (not method or len(target) > 2048 or bool(SUSPICIOUS.search(target)) or
            bool(SUSPICIOUS.search(decoded(target))))


def first_rule(rules, ip, method, target, status, ua, suspicious):
    """First matching rule; drop / archive skip suspicious requests unless the rule opts in."""
    for rule in rules:
        if suspicious and rule.action not in ('ai', 'block') and not rule.include_suspicious:
            continue
        if rule.matches(ip, method, target, status, ua):
            return rule
    return None


# Wall-clock time of a line: [15/Oct/2026:01:10:22 or 2026-10-15T01:10:22 (JSON logs).
LINE_TIME = re.compile(rb'(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})|(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})')
MONTH_NUMBER = {name.encode(): number for number, name in enumerate(MONTHS, 1)}
# Nginx writes lines in time order; the margin covers clock steps and slow requests.
DAY_MARGIN = timedelta(minutes=10)
SEEK_ABOVE = 8 * 1024 * 1024


def line_time(raw):
    match = LINE_TIME.search(raw)
    if not match:
        return None
    try:
        if match.group(1):
            return datetime(int(match[3]), MONTH_NUMBER[match[2]], int(match[1]), int(match[4]), int(match[5]), int(match[6]))
        return datetime(*(int(match[i]) for i in range(7, 13)))
    except (KeyError, ValueError):
        return None


def seek_offset(stream, size, target):
    """Byte offset shortly before the first line at or after `target` (binary search on time order)."""
    low, high = 0, size
    while high - low > 64 * 1024:
        middle = (low + high) // 2
        stream.seek(middle)
        stream.readline()  # Skip the partial line.
        moment = None
        for _ in range(50):
            raw = stream.readline()
            if not raw:
                break
            moment = line_time(raw)
            if moment:
                break
        if moment is None or moment >= target:
            high = middle
        else:
            low = middle
    return low


def day_files(template, day):
    """Every log that may hold lines of `day`, chosen by modification time rather than by name.

    Nginx on Windows keeps writing to a renamed file until it reopens its logs, so the
    lines of one day can sit at the end of an older dated file, or in the live access.log."""
    names = set(glob.glob(template.replace('{date}', '*')))
    live = re.sub(r'[_.-]?\{date\}', '', template)
    if os.path.isfile(live):
        names.add(live)
    since = datetime.combine(day, datetime.min.time()).timestamp() - 3600
    return sorted(name for name in names if os.path.isfile(name) and os.path.getmtime(name) >= since)


def day_markers(day):
    return (f'[{day.day:02d}/{MONTHS[day.month - 1]}/{day.year}:'.encode('ascii'), day.isoformat().encode('ascii') + b'T')


def parse_time(value):
    try:
        return datetime.strptime(value, '%d/%b/%Y:%H:%M:%S %z')
    except ValueError:
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return None


def parse_line(text):
    """Return ip, time, request, status for key:value, combined or JSON access lines."""
    match = KEY_VALUE.match(text)
    if match:
        timing = REQUEST_TIME.search(match['rest'])
        item = {'ip': match['ip'].strip(), 'time': match['time'], 'request': match['request'],
                'status': int(match['status']), 'ua': '', 'requestTime': float(timing.group(1)) if timing else None}
    else:
        match = COMBINED.match(text)
        if match:
            item = {'ip': match['ip'], 'time': match['time'], 'request': match['request'],
                    'status': int(match['status']), 'ua': match['ua'] or '', 'requestTime': None}
        else:
            try:
                data = json.loads(text)
                item = {'ip': str(data.get('remote_addr') or data.get('client_ip') or ''),
                        'time': str(data.get('time_local') or data.get('time_iso8601') or ''),
                        'request': str(data.get('request') or ''), 'status': int(data.get('status') or 0),
                        'ua': str(data.get('http_user_agent') or ''), 'requestTime': None}
            except (ValueError, TypeError, AttributeError):
                return None
    moment = parse_time(item['time'])
    if not item['ip'] or not item['request'] or moment is None:
        return None
    line = REQUEST_LINE.match(item['request'])
    item['method'], item['target'] = line.groups() if line else ('', item['request'])
    item['moment'] = moment
    return item


def decoded(target):
    text = target
    for _ in range(2):
        text = unquote(text)
    return text


class DailyCleaner:
    """Stream files once, keep only the target day, drop noise, aggregate requests."""

    def __init__(self, day, encoding='utf-8', drop_static=True, drop_paths=(), max_rows=DEFAULT_MAX_ROWS,
                 widespread_ips=WIDESPREAD_IPS, context_rows=CONTEXT_ROWS, rules=(), drop_preflight=True, seek=True):
        self.day = day
        self.seek = seek
        start = datetime.combine(day, datetime.min.time())
        self.window = (start - DAY_MARGIN, start + timedelta(days=1) + DAY_MARGIN)
        self.encoding = encoding
        self.drop_static = drop_static
        self.drop_preflight = drop_preflight
        # Legacy config dropPaths behave like drop rules placed after the user's rules.
        self.rules = list(rules) + [Rule({'action': 'drop', 'path': p}) for p in drop_paths]
        self.rule_hits = Counter()
        self.bytes_read = 0  # Read by the agent's main thread to report progress.
        self.max_rows = max_rows
        self.widespread_ips = widespread_ips
        self.context_rows = context_rows
        self.markers = day_markers(day)
        self.groups = {}
        self.files = []
        self.stats = {'lines': 0, 'otherDay': 0, 'malformed': 0, 'targetDay': 0,
                      'droppedStatic': 0, 'droppedPreflight': 0, 'droppedRule': 0, 'kept': 0}
        self.malformed_samples = []

    def classify(self, item):
        """Return (kind, grouping shape, forced AI choice, matched rule)."""
        target = item['target']
        try:
            parts = urlsplit(target)
        except ValueError:
            parts = None
        suspicious = parts is None or is_suspicious(item['method'], target)
        rule = first_rule(self.rules, item['ip'], item['method'], target, item['status'], item['ua'], suspicious)
        force = ('ai' if rule.action == 'block' else rule.action) if rule else None
        if force == 'drop':
            return 'rule', None, None, rule
        if suspicious:
            return 'suspicious', target, force, rule
        path = parts.path or target
        # A user rule that keeps a request overrides the built-in noise filters.
        if not rule and self.drop_static and STATIC.search(path):
            return 'static', None, None, None
        if not rule and self.drop_preflight and item['method'] == 'OPTIONS' and item['status'] < 400:
            return 'preflight', None, None, None
        if item['status'] < 400:
            # Ordinary successful business calls: the query carries per-call ids.
            return 'normal', path, force, rule
        try:
            query = parse_qsl(parts.query, keep_blank_values=True)
        except ValueError:
            return 'suspicious', target, force, rule
        # Keep unusual query values verbatim so payloads are never merged away.
        shape = '&'.join(k + '=' + ('*' if BENIGN_VALUE.match(v) else v) for k, v in query)
        return 'error', path + ('?' + shape if shape else ''), force, rule

    def add(self, item):
        kind, shape, force, rule = self.classify(item)
        if rule:
            self.rule_hits[rule.id] += 1
        if kind in ('static', 'preflight', 'rule'):
            self.stats['dropped' + {'static': 'Static', 'preflight': 'Preflight', 'rule': 'Rule'}[kind]] += 1
            return
        self.stats['kept'] += 1
        key = (item['ip'], item['method'], shape, item['status'], force)
        group = self.groups.get(key)
        stamp = item['moment'].timestamp()
        if group is None:
            self.groups[key] = {'ip': item['ip'], 'method': item['method'], 'status': item['status'],
                                'path': shape.split('?', 1)[0],
                                'kind': kind, 'force': force, 'count': 1, 'first': stamp, 'last': stamp,
                                'firstTime': item['time'], 'lastTime': item['time'],
                                'request': item['request'], 'lastRequest': item['request'],
                                'ua': item['ua'][:300], 'maxRequestTime': item['requestTime']}
            return
        group['count'] += 1
        if stamp < group['first']:
            group.update(first=stamp, firstTime=item['time'], request=item['request'])
        if stamp >= group['last']:
            group.update(last=stamp, lastTime=item['time'], lastRequest=item['request'])
        if item['requestTime'] is not None and (group['maxRequestTime'] is None or item['requestTime'] > group['maxRequestTime']):
            group['maxRequestTime'] = item['requestTime']

    def feed(self, path):
        lines = beyond = 0
        kept_before = self.stats['targetDay']
        size = os.path.getsize(path)
        with open(path, 'rb') as stream:
            if self.seek and size > SEEK_ABOVE:
                offset = seek_offset(stream, size, self.window[0])
                stream.seek(offset)
                if offset:
                    stream.readline()
            skipped = stream.tell()
            self.bytes_read += skipped
            stopped = False
            for raw in stream:
                lines += 1
                self.bytes_read += len(raw)
                if self.markers[0] not in raw and self.markers[1] not in raw:
                    self.stats['otherDay'] += 1
                    if self.seek:
                        moment = line_time(raw)
                        beyond = beyond + 1 if moment and moment >= self.window[1] else 0
                        if beyond >= 200:
                            # Well past the day: the rest of a still-growing file is later days.
                            stopped = True
                            self.bytes_read += size - stream.tell()
                            break
                    continue
                beyond = 0
                text = raw.rstrip(b'\r\n').decode(self.encoding, errors='replace')
                item = parse_line(text)
                if item is None:
                    self.stats['malformed'] += 1
                    if len(self.malformed_samples) < 5:
                        self.malformed_samples.append(text[:300])
                    continue
                if item['moment'].date() != self.day:
                    self.stats['otherDay'] += 1
                    continue
                self.stats['targetDay'] += 1
                self.add(item)
        self.stats['lines'] += lines
        self.files.append({'path': str(path), 'lines': lines, 'targetDay': self.stats['targetDay'] - kept_before,
                           'size': size, 'skippedBytes': skipped, 'stoppedEarly': stopped})

    def select_for_ai(self):
        """Mark the groups worth a model judgement; everything else is kept for search only."""
        spread = {}
        for group in self.groups.values():
            if group['kind'] == 'error':
                spread.setdefault((group['method'], group['path'], group['status']), set()).add(group['ip'])
        flagged = set()
        for group in self.groups.values():
            if group['force'] in ('ai', 'archive'):
                group['ai'] = group['force'] == 'ai'
            elif group['kind'] == 'suspicious':
                group['ai'] = True
            elif group['kind'] == 'error':
                # 499 is the client hanging up; a 404 many clients hit is a missing page asset.
                group['ai'] = (group['status'] != 499 and
                               len(spread[(group['method'], group['path'], group['status'])]) < self.widespread_ips)
            else:
                group['ai'] = False
            if group['ai']:
                flagged.add(group['ip'])
        normal = {}
        for group in self.groups.values():
            if group['kind'] == 'normal' and not group['force'] and group['ip'] in flagged:
                normal.setdefault(group['ip'], []).append(group)
        for groups in normal.values():
            for group in heapq.nlargest(self.context_rows, groups, key=lambda g: g['count']):
                group['ai'] = True

    def rows(self):
        """Aggregated rows, most relevant first, bounded so one day cannot flood the platform."""
        self.select_for_ai()
        rank = {'suspicious': 0, 'error': 1, 'normal': 2}
        groups = list(self.groups.values())
        if len(groups) > self.max_rows:
            groups = heapq.nsmallest(self.max_rows, groups, key=lambda g: (not g['ai'], rank[g['kind']], -g['count']))
        groups.sort(key=lambda g: g['first'])
        result = []
        for group in groups:
            row = {'remote_addr': group['ip'], 'time_local': group['firstTime'], 'request': group['request'][:REQUEST_LIMIT],
                   'status': group['status'], 'count': group['count'], 'first_time': group['firstTime'],
                   'last_time': group['lastTime'], 'clean_date': self.day.isoformat(), 'clean_kind': group['kind'],
                   'clean_ai': group['ai']}
            if group['force']:
                row['clean_rule'] = group['force']
            if group['lastRequest'] != group['request']:
                row['last_request'] = group['lastRequest'][:REQUEST_LIMIT]
            if max(len(group['request']), len(group['lastRequest'])) > REQUEST_LIMIT:
                row['request_truncated'] = True
            if group['ua']:
                row['http_user_agent'] = group['ua']
            if group['maxRequestTime'] is not None:
                row['max_request_time'] = group['maxRequestTime']
            result.append(json.dumps(row, ensure_ascii=False, separators=(',', ':')))
        return result

    def report(self, emitted):
        kinds = {}
        ips = {}
        ai_rows, ai_ips = 0, set()
        for group in self.groups.values():
            if group.get('ai'):
                ai_rows += 1
                ai_ips.add(group['ip'])
            kinds[group['kind']] = kinds.get(group['kind'], 0) + 1
            ips[group['ip']] = ips.get(group['ip'], 0) + group['count']
        top = sorted(ips.items(), key=lambda item: -item[1])[:10]
        return {'type': 'daily_clean_report', 'date': self.day.isoformat(), 'files': self.files, **self.stats,
                'groups': len(self.groups), 'groupKinds': kinds, 'rowsEmitted': emitted,
                'rowsTruncated': max(0, len(self.groups) - emitted), 'distinctIps': len(ips),
                'aiRows': ai_rows, 'aiIps': len(ai_ips),
                'ruleHits': {str(k): v for k, v in self.rule_hits.items() if k},
                'topIps': [{'ip': ip, 'count': count} for ip, count in top],
                'malformedSamples': self.malformed_samples}


def explain(text, rules=(), options=None):
    """Describe how one pasted log line would be cleaned; used by the rule test tool."""
    options = clean_options(options)
    item = parse_line(text.strip())
    if item is None:
        return {'parsed': False, 'outcome': '无法解析', 'detail': '不是可识别的访问日志格式，按日清洗时计为格式错误。'}
    cleaner = DailyCleaner(item['moment'].date(), drop_static=options['dropStatic'], rules=rules,
                           drop_preflight=options['dropPreflight'])
    kind, _, force, rule = cleaner.classify(item)
    result = {'parsed': True, 'ip': item['ip'], 'time': item['time'], 'method': item['method'], 'target': item['target'][:500],
              'status': item['status'], 'kind': kind, 'rule': {'id': rule.id, 'name': rule.name, 'action': rule.action} if rule else None}
    if kind in ('static', 'preflight', 'rule'):
        result['outcome'] = '丢弃'
        result['detail'] = {'static': '内置规则：静态资源', 'preflight': '内置规则：OPTIONS 预检',
                            'rule': f'自定义规则：{rule.name if rule else ""}'}[kind]
    elif rule and rule.action == 'block':
        result.update(outcome='必封', detail=f'必封规则：{rule.name}，来源 IP 直接加入 WAF 全局黑名单（保护名单除外）')
    elif force == 'ai':
        result.update(outcome='送 AI', detail=f'自定义规则强制送 AI：{rule.name}')
    elif force == 'archive':
        result.update(outcome='仅存档', detail=f'自定义规则：{rule.name}')
    elif kind == 'suspicious':
        result.update(outcome='送 AI', detail='内置识别为可疑请求，原样保留' +
                      ('（丢弃 / 存档规则默认不作用于可疑请求）' if rules else ''))
    elif kind == 'error':
        result.update(outcome='视情况送 AI', detail=f'错误请求：少于 {options["widespreadIps"]} 个客户端出现时送 AI，499 除外')
    else:
        result.update(outcome='仅存档', detail='正常请求按 IP + 路径聚合；所属 IP 送 AI 时作为上下文')
    return result


def target_day(days_ago, today=None):
    return (today or date.today()) - timedelta(days=days_ago)


def candidate_files(template, day, date_format='%Y-%m-%d', neighbors=1):
    """Dated files that can hold the target day's lines: the day itself and its neighbours."""
    names = []
    for offset in [0] + [d for n in range(1, neighbors + 1) for d in (-n, n)]:
        name = template.replace('{date}', (day + timedelta(days=offset)).strftime(date_format))
        if name not in names:
            names.append(name)
    return names


def main():
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description='Clean one day of Nginx access logs (date-1 by default)')
    parser.add_argument('files', nargs='+', help='Log files; may contain other days, they are filtered out')
    parser.add_argument('--date', help='Target day YYYY-MM-DD (default: yesterday)')
    parser.add_argument('--out', help='Write cleaned JSON lines here')
    parser.add_argument('--report', help='Write the cleaning report JSON here')
    parser.add_argument('--encoding', default='utf-8')
    parser.add_argument('--keep-static', action='store_true')
    parser.add_argument('--max-rows', type=int, default=DEFAULT_MAX_ROWS)
    args = parser.parse_args()
    day = date.fromisoformat(args.date) if args.date else target_day(1)
    cleaner = DailyCleaner(day, args.encoding, not args.keep_static, max_rows=args.max_rows)
    for name in args.files:
        cleaner.feed(Path(name))
    rows = cleaner.rows()
    report = cleaner.report(len(rows))
    if args.out:
        Path(args.out).write_text('\n'.join(rows) + '\n', encoding='utf-8')
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.report:
        Path(args.report).write_text(text, encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
