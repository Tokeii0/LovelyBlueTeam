import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib import request, error

from server import LogServer
from site_rule import DOMAIN, SiteVisitRule, visitor_ip
from storage import Store
from security import Waf, SecurityError
from test_incremental_security import FakePanel, access


class RulePanel(FakePanel):
    def __init__(self):
        super().__init__()
        self.domain, self.website, self.access_enabled = DOMAIN, 1, True
    def websites(self): return [{'id':self.website,'name':self.domain}]
    def metadata(self, website): return {'accessLog':self.access_enabled}


class SiteRuleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.env = patch.dict('os.environ',{},clear=True); self.env.start()
        self.root.joinpath('.env').write_text(('AI_ANALYSIS_MODE=ai\n' + 'AI_ENABLED=false\nAUTO_BLOCK=false\nIP_ALLOWLIST=8.8.6.173/32,10.20.30.13/32\n'),encoding='utf-8')
        self.store = Store(self.root/'state.sqlite3'); self.panel = RulePanel()
        self.rule = SiteVisitRule(self.root,self.panel,self.store,Waf(self.panel,self.store))
    def tearDown(self):
        self.rule.stop()
        if self.rule.thread: self.rule.thread.join(2)
        self.store.close(); self.env.stop(); self.temp.cleanup()
    def put(self, lines, website=1, kind='access.log'):
        self.store.append(f'{website}:{kind}',{},website,kind,lines)
    def iprow(self, ip): return next(row for row in self.rule.public()['results'] if row['ip']==ip)

    def test_one_visit_blocks_without_ai_or_status_threshold(self):
        self.rule.configure(True); self.put([access('8.8.8.8','/normal').replace('404','200')])
        self.assertEqual(self.rule.process_once(),1)
        self.assertEqual(len(self.panel.black),1)
        self.assertEqual(self.panel.black[0]['scope'],'ipBlack')
        self.assertTrue(self.panel.black[0]['name'].startswith('sitevisit_'))
        self.assertIn(DOMAIN,self.panel.black[0]['description'])
        self.assertEqual(self.rule.public()['lastIps'],1)
        self.assertEqual(self.iprow('8.8.8.8')['state'],'listed')
        self.assertEqual(self.store.dashboard()['history']['allTotal'],0)

    def test_enabling_baseline_excludes_old_logs_other_sites_and_error_logs(self):
        self.put([access('1.1.1.1')]); self.rule.configure(True)
        self.put([access('8.8.8.8')],website=7)
        self.put([access('9.9.9.9')],kind='error.log')
        self.put([access('4.4.4.4')])
        self.rule.process_once()
        self.assertEqual([r['ipv4'] for r in self.panel.black],['4.4.4.4'])
        self.assertEqual(self.rule.public()['lastRows'],1)

    def test_counts_duplicate_visits_and_deduplicates_ips_ipv4_mapped(self):
        self.rule.configure(True)
        self.put([access('8.8.8.8')]*5+[access('::ffff:8.8.8.8')])
        self.rule.process_once(); self.rule.process_once()
        self.assertEqual(self.iprow('8.8.8.8')['count'],6)
        self.assertEqual(len([p for p,b in self.panel.calls if p.endswith('/create')]),1)
        self.put([access('8.8.8.8')]*2); self.rule.process_once()
        self.assertEqual(self.iprow('8.8.8.8')['count'],8)
        self.assertEqual(self.iprow('8.8.8.8')['state'],'existing')

    def test_restart_retains_cursor_and_failed_queue_retries_without_new_visits(self):
        self.rule.configure(True); self.put([access('8.8.8.8')])
        with patch.object(self.rule.waf,'add',side_effect=SecurityError('模拟写入失败')):
            self.rule.process_once()
        item = self.iprow('8.8.8.8'); self.assertEqual(item['state'],'failed')
        new = SiteVisitRule(self.root,self.panel,self.store,Waf(self.panel,self.store))
        with patch('site_rule.time.time',return_value=item['retry_at']+1):
            self.assertEqual(new.process_once(),1)
        self.assertEqual(new.public()['pending'],0)
        self.assertEqual(self.iprow('8.8.8.8')['count'],1)

    def test_explicit_protection_white_list_and_private_visitor_policy(self):
        self.panel.white=[{'name':'trusted','type':'ipv4','ipv4':'8.8.8.8/32','state':'on'}]
        self.rule.configure(True)
        self.put([access(ip) for ip in ('8.8.6.173','10.20.30.13','127.0.0.1','8.8.8.8','10.40.50.60')])
        self.rule.process_once()
        self.assertEqual([r['ipv4'] for r in self.panel.black],['10.40.50.60'])
        self.assertEqual(self.rule.public()['protected'],4)

    def test_manual_remove_and_protect_is_respected(self):
        self.store.set_block('8.8.8.8','managed',True,'unblocked')
        self.rule.configure(True); self.put([access('8.8.8.8')]); self.rule.process_once()
        self.assertEqual(self.panel.black,[])
        self.assertEqual(self.iprow('8.8.8.8')['state'],'protected')

    def test_paused_rules_do_not_replay_paused_requests(self):
        self.rule.configure(True); self.put([access('8.8.8.8')])
        self.rule.configure(False); self.assertEqual(self.rule.process_once(),0)
        self.put([access('1.1.1.1')]); self.rule.configure(True)
        self.rule.process_once(); self.assertEqual(self.panel.black,[])
        self.put([access('9.9.9.9')]); self.rule.process_once()
        self.assertEqual([r['ipv4'] for r in self.panel.black],['9.9.9.9'])

    def test_disabling_during_checks_stops_the_write(self):
        self.rule.configure(True); self.put([access('8.8.8.8')])
        self.panel.before_create=lambda:self.rule.configure(False)
        self.rule.process_once()
        self.assertEqual(self.panel.black,[])
        self.assertEqual(self.iprow('8.8.8.8')['state'],'paused')

    def test_website_rename_or_id_reuse_stops_processing(self):
        self.rule.configure(True); self.put([access('8.8.8.8')])
        self.panel.domain='pacsimage.example.com'; self.rule.process_once()
        self.assertEqual(self.panel.black,[]); self.assertIn('归属',self.rule.public()['lastError'])
        self.panel.domain=DOMAIN; self.panel.website=7; self.rule.process_once()
        self.assertEqual(self.panel.black,[]); self.assertIn('编号',self.rule.public()['lastError'])

    def test_invalid_ip_is_visible_and_client_json_ignores_forwarded_headers(self):
        self.rule.configure(True)
        self.put(['not an ip',json.dumps({'remote_addr':'8.8.8.8','http_x_forwarded_for':'1.1.1.1'})])
        self.rule.process_once()
        self.assertEqual(self.rule.public()['unparsed'],1)
        self.assertEqual([r['ipv4'] for r in self.panel.black],['8.8.8.8'])
        self.assertIsNone(visitor_ip('{}'))

    def test_waf_write_timeout_is_verified_and_does_not_duplicate(self):
        self.panel.timeout_after_create=True
        self.rule.configure(True); self.put([access('8.8.8.8')]); self.rule.process_once()
        self.assertEqual(self.iprow('8.8.8.8')['state'],'listed')
        self.put([access('8.8.8.8')]); self.rule.process_once()
        self.assertEqual(len(self.panel.black),1)

    def test_panel_generated_uuid_name_is_verified_and_removable(self):
        import uuid
        original=self.panel.call
        def call(path,body=None):
            if path.endswith('/create'):
                body={**body,'name':str(uuid.uuid4())}
            return original(path,body)
        with patch.object(self.panel,'call',side_effect=call):
            self.rule.configure(True); self.put([access('8.8.8.8')]); self.rule.process_once()
            self.assertEqual(self.iprow('8.8.8.8')['state'],'listed')
            self.assertEqual(self.store.block('8.8.8.8')['name'],self.panel.black[0]['name'])
            self.assertTrue(self.store.block('8.8.8.8')['managed'])
            self.rule.waf.remove('8.8.8.8')
            self.assertEqual(self.panel.black,[])

    def test_uuid_named_rule_timeout_is_recognized_from_sitevisit_marker(self):
        original=self.panel.call
        def call(path,body=None):
            if path.endswith('/create'):
                self.panel.black.append({**body,'name':'panel-generated-uuid'})
                raise SecurityError('timeout after write')
            return original(path,body)
        with patch.object(self.panel,'call',side_effect=call):
            self.rule.configure(True); self.put([access('8.8.8.8')]); self.rule.process_once()
        self.assertEqual(self.iprow('8.8.8.8')['state'],'listed')
        self.assertEqual(len(self.panel.black),1)

    def test_saved_deadline_prevents_running_before_first_minute(self):
        self.rule.configure(True); self.put([access('8.8.8.8')]); self.rule.start()
        self.rule.stop_event.wait(.1)
        self.assertEqual(self.panel.black,[])
        self.assertGreater(self.rule.public()['nextCheckAt'],time.time()+50)

    def test_configuration_validation_and_source_guard_on_local_api(self):
        with self.assertRaises(ValueError): self.rule.configure('yes')
        server=LogServer(('127.0.0.1',0),self.panel,self.store,rule=self.rule)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        base=f'http://127.0.0.1:{server.server_port}'
        try:
            body=json.dumps({'enabled':True}).encode()
            with self.assertRaises(error.HTTPError) as raised:
                request.urlopen(request.Request(base+'/api/site-rule',data=body,headers={'Content-Type':'application/json','Origin':'https://other.test'}))
            self.assertEqual(raised.exception.code,403)
            with request.urlopen(request.Request(base+'/api/site-rule',data=body,headers={'Content-Type':'application/json'})) as res:
                self.assertTrue(json.load(res)['enabled'])
            with request.urlopen(base+'/api/site-rule') as res:
                self.assertEqual(json.load(res)['domain'],DOMAIN)
        finally:server.shutdown(); server.server_close()


if __name__=='__main__':unittest.main()
