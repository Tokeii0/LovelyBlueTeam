"""Bounded, offline request-pattern screening for manual review.

Matches indicate a rule hit, not a verified compromise or an instruction to block.
The detector never executes request content and never calls a model or a network API.
"""
import json
import re
from urllib.parse import parse_qsl, unquote_plus

from post_body import SENSITIVE, redact


MAX_FIELD_CHARACTERS = 64 * 1024
MAX_SCAN_CHARACTERS = 128 * 1024
MAX_DEPTH, MAX_NODES, MAX_FINDINGS = 20, 2048, 64

# Exportable rule descriptions. XSS is intentionally absent: business XML/HTML is
# not sufficient evidence of an attack. Expressions are fixed, never user supplied.
RULES = [
    {'id': 'SQL_UNION_SELECT', 'name': 'UNION SELECT 注入特征', 'category': 'sql_injection',
     'expression': r'\bunion(?:\s+all|\s+distinct)?\s+select\b'},
    {'id': 'SQL_BOOLEAN', 'name': '引号后布尔条件注入特征', 'category': 'sql_injection',
     'expression': r'''(?P<marker>['"]\s*(?:or|and))\s+(?:[0-9]{1,10}\s*=\s*[0-9]{1,10}|['"][^'"\r\n]{0,32}['"]\s*=\s*['"][^'"\r\n]{0,32}['"])'''},
    {'id': 'SQL_TIME_DELAY', 'name': 'SQL 上下文延时函数', 'category': 'sql_injection',
     'expression': r'''(?:['";]|\b(?:and|or|select)\b)[^\r\n]{0,64}(?P<marker>\b(?:sleep|pg_sleep|benchmark)\s*\()'''},
    {'id': 'SQL_WAITFOR', 'name': 'WAITFOR DELAY 注入特征', 'category': 'sql_injection',
     'expression': r'''\bwaitfor\s+delay\s*['"][0-9:]{3,12}['"]'''},
    {'id': 'SQL_STACKED_DDL', 'name': '分号追加破坏性 SQL', 'category': 'sql_injection',
     'expression': r';\s*(?:drop|truncate)\s+(?:table|database)\b'},
    {'id': 'SQL_FILE_IO', 'name': 'SQL 文件读写特征', 'category': 'sql_injection',
     'expression': r'''\b(?:load_file\s*\(|into\s+(?:outfile|dumpfile)\s*['"])'''},
    {'id': 'RCE_JNDI', 'name': 'JNDI 外部查找载荷', 'category': 'rce',
     'expression': r'\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|http|https)\s*:'},
    {'id': 'RCE_JAVA_EXEC', 'name': 'Java 进程执行载荷', 'category': 'rce',
     'expression': r'\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|ProcessBuilder\s*\(|System\s*\.\s*Diagnostics\s*\.\s*Process\s*\.\s*Start\s*\()'},
    {'id': 'RCE_OGNL_TEMPLATE', 'name': 'OGNL 或模板命令执行组件', 'category': 'rce',
     'expression': r'(?:@java\.lang\.Runtime@|#_memberAccess\b|\bfreemarker\.template\.utility\.Execute\b)'},
    {'id': 'RCE_DESERIALIZATION_GADGET', 'name': '已知反序列化危险类', 'category': 'rce',
     'expression': r'\b(?:org\.apache\.commons\.collections(?:4)?\.functors\.(?:InvokerTransformer|ChainedTransformer)|com\.sun\.org\.apache\.xalan\.internal\.xsltc\.trax\.TemplatesImpl|com\.sun\.rowset\.JdbcRowSetImpl|System\.Windows\.Data\.ObjectDataProvider)\b'},
    {'id': 'RCE_PHP_WEBSHELL', 'name': 'PHP WebShell 执行特征', 'category': 'rce',
     'expression': r'\b(?:(?:eval|assert)\s*\(\s*(?:base64_decode\s*\(|\$_(?:POST|GET|REQUEST)\b)|(?:system|passthru|shell_exec)\s*\(\s*\$_(?:POST|GET|REQUEST)\b)'},
    {'id': 'RCE_JSP_CODE', 'name': 'JSP 脚本或 Java 动态类载入特征', 'category': 'rce',
     'expression': r'<%(?:@|=)|\bdefineClass\s*\(', 'marker': '<%@ / <%= / defineClass('},
    {'id': 'RCE_PHP_TAG', 'name': '请求中包含 PHP 脚本标签', 'category': 'rce',
     'expression': r'<\?php\b', 'marker': '<?php'},
    {'id': 'RCE_BACKDOOR_EXEC', 'name': '后门风格命令执行方法字段', 'category': 'rce', 'scope': 'method_field',
     'expression': r'\AexecCommand\Z', 'marker': 'method/methodName = execCommand'},
    {'id': 'RCE_SHELL', 'name': 'Shell 路径或命令执行选项', 'category': 'rce',
     'expression': r'/bin/(?:ba)?sh\b|\b(?:ba)?sh\s+-(?:c|i)\b', 'marker': '/bin/sh / bash -c / bash -i'},
    {'id': 'RCE_JAVA_CLASS', 'name': '解码器识别到 Java 类文件', 'category': 'rce', 'scope': 'body_format',
     'expression': r'\Ajava-class\Z', 'marker': 'bodyMeta.format = java-class'},
    {'id': 'RCE_COMMAND', 'name': '命令解释器或 SQL 系统命令', 'category': 'rce',
     'expression': r'\b(?:cmd(?:\.exe)?\s+/c\b|powershell(?:\.exe)?[^\r\n]{0,96}\s-(?:enc|encodedcommand)\b|xp_cmdshell\b|sp_oacreate\b)'},
    {'id': 'RCE_DOWNLOAD_PIPE', 'name': '下载内容管道交给 Shell', 'category': 'rce',
     'expression': r'\b(?:curl|wget)\s+[^\r\n]{0,160}\|\s*(?:/bin/)?(?:ba)?sh\b'},
    {'id': 'PATH_TRAVERSAL', 'name': '父目录穿越路径', 'category': 'path_traversal',
     'expression': r'''(?:^|[\\/=:\s"'])\.\.[\\/]'''},
    {'id': 'SENSITIVE_FILE_PROBE', 'name': '敏感文件或配置探测', 'category': 'scanner', 'scope': 'target',
     'expression': r'(?:^|[\\/])(?:\.env(?:\.[a-z0-9_-]{1,24})?|\.git[\\/](?:HEAD|config)|\.svn[\\/]entries|WEB-INF[\\/]web\.xml|etc[\\/](?:passwd|shadow)|actuator[\\/](?:env|heapdump))(?=$|[\\/?#&\s])'},
    {'id': 'YQ_TRACK_FORMAT', 'name': 'YQ 跟踪号长度或格式异常', 'category': 'other', 'scope': 'sys_track_code',
     'expression': r'(?-i:\A(?=\s*YQ)(?!YQ_[0-9]{16}_[0-9]{2}\Z))'},
]
_COMPILED = [(rule, re.compile(rule['expression'], re.I)) for rule in RULES]
_JSON_ESCAPE = re.compile(r'\\(?:u[0-9a-fA-F]{4}|["\\/bfnrt])')
_SQL_COMMENT = re.compile(r'/\*[^\r\n]{0,256}?\*/')
_URL_CREDENTIALS = re.compile(r'(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@')
_PRIORITY = {'rce': 5, 'sql_injection': 4, 'path_traversal': 3, 'scanner': 2, 'other': 1}
_READABLE_STATES = {'plain', 'decoded', 'decrypted', 'restored', 'empty'}


class _Inspection:
    def __init__(self, event):
        self.event, self.remaining, self.nodes = event, MAX_SCAN_CHARACTERS, 0
        self.findings, self.warnings, self.limited = {}, [], False

    def warn(self, message, limited=False):
        if message not in self.warnings:
            self.warnings.append(message)
        self.limited = self.limited or limited

    def consume(self, text):
        if len(text) > MAX_FIELD_CHARACTERS:
            self.warn('单字段过长，仅检测前 64 KiB 字符', True)
            text = text[:MAX_FIELD_CHARACTERS]
        if len(text) > self.remaining:
            self.warn('请求检测达到 128 KiB 字符预算，部分内容未检测', True)
            text = text[:self.remaining]
        self.remaining -= len(text)
        return text

    def scan(self, value, field, key='', private=False):
        current, seen = value, set()
        for round_number in range(4):  # Original plus at most three URL/JSON-escape decoding rounds.
            if current in seen:
                break
            seen.add(current)
            current = self.consume(current)
            if not current:
                break
            variants = [current]
            uncommented = _SQL_COMMENT.sub(' ', current)
            if uncommented != current:
                variants.append(self.consume(uncommented))
            for text in variants:
                for rule, expression in _COMPILED:
                    if rule['id'] in self.findings:
                        continue
                    scope = rule.get('scope')
                    if scope == 'target' and field != 'target' or scope == 'sys_track_code' and key != 'sys_track_code':
                        continue
                    if scope == 'method_field' and (field != 'requestBody' or key.lower() not in ('method', 'methodname')):
                        continue
                    if scope == 'body_format' and field != 'bodyMeta.format':
                        continue
                    match = expression.search(text)
                    if match:
                        # Only the matching marker is retained, never surrounding business text.
                        snippet = (rule.get('marker') or match.groupdict().get('marker') or match.group(0))[:160]
                        if rule['id'] == 'YQ_TRACK_FORMAT':
                            snippet = 'YQ 跟踪号不符合 YQ_16位数字_2位数字，原值省略'
                        elif rule['id'] == 'RCE_DOWNLOAD_PIPE':
                            snippet = 'curl/wget ... | sh'
                        elif rule['id'] == 'RCE_COMMAND' and match.group(0).lower().startswith('powershell'):
                            snippet = 'PowerShell -EncodedCommand'
                        snippet = redact({'token': snippet})['token'] if private else redact(snippet)
                        snippet = _URL_CREDENTIALS.sub(r'\1[REDACTED]@', snippet)
                        snippet = snippet.encode('utf-8', errors='replace').decode('utf-8')[:160]
                        self.findings[rule['id']] = {
                            'ruleId': rule['id'], 'ruleName': rule['name'], 'category': rule['category'],
                            'eventId': self.event['id'], 'field': field, 'snippet': snippet, 'decodeRound': round_number}
            if not self.remaining:
                self.warn('请求检测达到 128 KiB 字符预算，部分内容未检测', True)
                break
            if round_number == 3:
                break
            decoded = unquote_plus(current)
            decoded = _JSON_ESCAPE.sub(lambda m: json.loads('"' + m.group(0) + '"'), decoded)
            if decoded == current:
                break
            current = decoded

    def walk(self, value, key='', private=False, depth=0):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            self.warn('JSON 深度或字段数达到检测上限，部分内容未检测', True)
            return
        if not self.remaining:
            self.warn('请求检测达到 128 KiB 字符预算，部分内容未检测', True)
            return
        self.nodes += 1
        if isinstance(value, dict):
            for child_key, child in value.items():
                if self.nodes >= MAX_NODES or not self.remaining:
                    self.warn('JSON 字段数或字符预算达到上限，部分内容未检测', True)
                    break
                name = str(child_key)
                self.walk(child, name, private or bool(SENSITIVE.search(name)), depth + 1)
        elif isinstance(value, list):
            for child in value:
                if self.nodes >= MAX_NODES or not self.remaining:
                    self.warn('JSON 字段数或字符预算达到上限，部分内容未检测', True)
                    break
                self.walk(child, key, private, depth + 1)
        elif isinstance(value, str):
            # Nested JSON strings are common in the business gateway; parse only bounded JSON.
            if len(value) <= MAX_FIELD_CHARACTERS and value.lstrip().startswith(('{', '[', '"')):
                try:
                    decoded = json.loads(value)
                except (ValueError, RecursionError):
                    pass
                else:
                    if isinstance(decoded, (dict, list, str)) and decoded != value:
                        self.walk(decoded, key, private, depth + 1)
                        return
            self.scan(value, 'requestBody', key, private)

    def form(self, value, field):
        try:
            pairs = parse_qsl(value[:MAX_FIELD_CHARACTERS], keep_blank_values=True, max_num_fields=256)
        except ValueError:
            self.warn('参数数量达到检测上限，部分参数未单独解析', True)
            return
        for key, item in pairs:
            if not self.remaining:
                self.warn('请求检测达到 128 KiB 字符预算，部分内容未检测', True)
                break
            self.scan(item, field, key, bool(SENSITIVE.search(key)))

    def run(self):
        target = self.event.get('_localTarget', self.event.get('target', ''))
        if isinstance(target, str):
            self.scan(target, 'target')
            query = target.partition('?')[2].split(' ', 1)[0]
            if query:
                self.form(query, 'target')
        body_present = '_localRequestBody' in self.event or 'requestBody' in self.event
        if body_present:
            meta = self.event.get('bodyMeta') or {}
            if meta.get('state') not in _READABLE_STATES or meta.get('unresolved', 0):
                self.warn('正文未完整解密或解密状态未确认，未命中不代表安全')
            if meta.get('truncated'):
                self.warn('收到的正文已截断，未命中不代表安全', True)
            if isinstance(meta.get('format'), str):
                self.scan(meta['format'], 'bodyMeta.format')
            body = self.event.get('_localRequestBody', self.event.get('requestBody'))
            self.walk(body)
            if isinstance(body, str) and 'application/x-www-form-urlencoded' in str(meta.get('contentType', '')).lower():
                self.form(body, 'requestBody')
        agent = self.event.get('userAgent')
        if isinstance(agent, str):
            self.scan(agent, 'userAgent')
        if self.event.get('truncated'):
            self.warn('请求元数据或正文已截断，未命中不代表安全', True)
        return self


class LocalDetector:
    def analyze(self, events, config=None):
        grouped = {}
        for event in events:
            grouped.setdefault(event['ip'], []).append(event)
        decisions = []
        for ip, records in grouped.items():
            findings, warnings, evidence_ids, rule_ids = [], [], [], []
            scanned, limited_events, incomplete_events, finding_count = 0, 0, 0, 0
            for event in records:
                inspection = _Inspection(event).run()
                scanned += MAX_SCAN_CHARACTERS - inspection.remaining
                limited_events += inspection.limited
                incomplete_events += bool(inspection.warnings)
                warnings.extend(w for w in inspection.warnings if w not in warnings)
                if inspection.findings and event['id'] not in evidence_ids:
                    evidence_ids.append(event['id'])
                for finding in inspection.findings.values():
                    finding_count += 1
                    if finding['ruleId'] not in rule_ids:
                        rule_ids.append(finding['ruleId'])
                    if len(findings) < MAX_FINDINGS:
                        findings.append(finding)
            if finding_count > MAX_FINDINGS:
                warnings.append('命中明细仅展示前 64 条，全部命中日志 ID 已保留')
            rules = [{k: rule[k] for k in ('id', 'name', 'category')} for rule in RULES if rule['id'] in rule_ids]
            matched = bool(rule_ids)
            category = max((r['category'] for r in rules), key=lambda c: _PRIORITY[c]) if matched else 'none'
            reason = '未命中本地规则，未确认安全'
            if matched:
                names = '、'.join(r['name'] for r in rules)
                reason = f"本地规则命中：{names}；片段：{findings[0]['snippet']}。需人工核验后决定封禁。"
            if warnings:
                reason += '；检测不完整，详见检测提示'
            decisions.append({
                'ip': ip, 'is_attack': matched, 'confidence': 1.0, 'attack_type': category,
                'reason': reason[:1200], 'evidence_ids': evidence_ids, 'local': True,
                'modelFacts': {'local': True, 'localRuleMatch': matched,
                               'confidenceMeaning': '规则匹配确定性，不表示攻击概率',
                               'ruleIds': rule_ids, 'rules': rules, 'findings': findings, 'warnings': warnings,
                               'coverage': {'events': len(records), 'scannedCharacters': scanned,
                                            'limitedEvents': limited_events, 'incompleteEvents': incomplete_events}}})
        return decisions
