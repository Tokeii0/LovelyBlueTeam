from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib import error, request
import uuid

from blacklist import BlacklistService
from hub import Hub, IngestServer
from jev import Jev
from security import AiWorker, SecurityError, Waf, normalized_event
from server import LogServer, PanelError
from storage import Store
from test_analysis_speed_jev import answer_for
from test_incremental_security import FakeModel, FakePanel, access


class ServerAiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.env = patch.dict('os.environ', {}, clear=True); self.env.start()
        self.root.joinpath('.env').write_text(('AI_ANALYSIS_MODE=ai\n' + 'DEEPSEEK_API_KEY=fixture-key\nAI_ENABLED=true\nAUTO_BLOCK=true\nAI_CONCURRENCY=2\nIP_ALLOWLIST=8.8.6.173/32\n'), encoding='utf-8')
        self.store = Store(self.root/'state.sqlite3'); self.hub = Hub(self.store)
        self.panel = FakePanel(); self.model = FakeModel()
        self.worker = AiWorker(self.root, self.panel, self.store, self.model)
        self.agent = self.register('OA 测试')

    def tearDown(self):
        self.worker.stop(); self.store.close(); self.env.stop(); self.temp.cleanup()

    def register(self, name):
        return self.hub.register({'name':name,'platformUrl':'http://127.0.0.1:9',
            'sources':[{'path':'D:/logs/access.log','kind':'access.log'}]})

    def put(self, lines, agent=None, kind='access.log', source='D:/logs/access.log'):
        events=[{'eventId':uuid.uuid4().hex,'source':source,'kind':kind,'raw':raw,'collectedAt':time.time()} for raw in lines]
        body={'events':events}
        self.hub.ingest((agent or self.agent)['agentId'],body)
        return body

    def test_recent_agent_attack_is_verified_in_waf_with_server_evidence(self):
        self.put([access(),access(path='/wp-admin')]); self.worker.process_once()
        result=self.store.dashboard(source='agent',agent_id=self.agent['agentId'])
        decision=result['decisions'][0]
        self.assertEqual(result['summary']['analyzed'],2)
        self.assertEqual(result['summary']['listed'],1)
        self.assertEqual(decision['source_name'],'OA 测试')
        self.assertEqual(decision['source_file'],'D:/logs/access.log')
        self.assertEqual(decision['state'],'listed')
        self.assertFalse(decision['historical'])
        self.assertEqual({e['agent_id'] for e in decision['evidence']},{self.agent['agentId']})
        self.assertTrue(all(e['id']<0 for e in decision['evidence']))
        self.assertEqual(self.panel.black[0]['ipv4'],'8.8.8.8')

    def test_panel_and_agent_evidence_ids_do_not_collide_or_combine_for_a_ban(self):
        self.store.append('test',{},1,'access.log',[access()]); self.put([access()])
        self.assertEqual({e['id'] for e in self.store.pending(500)},{1,-1})
        self.worker.process_once()
        self.assertEqual(self.panel.black,[])
        self.assertEqual(self.store.dashboard(source='panel')['summary']['analyzed'],1)
        agent=self.store.dashboard(source='agent')['decisions'][0]
        self.assertEqual(agent['evidence'][0]['id'],-1)
        self.assertEqual(self.store.dashboard()['history']['allTotal'],2)

    def test_different_servers_do_not_borrow_each_others_single_evidence(self):
        self.put([access()]); other=self.register('另一台服务器'); self.put([access()],other)
        self.worker.process_once()
        self.assertEqual(self.panel.black,[])
        self.assertEqual(len(self.model.calls),2)
        self.assertEqual(self.store.dashboard(source='agent',agent_id=other['agentId'])['history']['allTotal'],1)

    def test_old_agent_access_gets_review_history_but_old_panel_access_expires(self):
        old=access(time_text='01/Jan/2020:00:00:00 +0000')
        self.put([old,old]); self.store.append('old',{},1,'access.log',[old])
        self.worker.process_once()
        item=self.store.dashboard(source='agent')['decisions'][0]
        self.assertTrue(item['historical']); self.assertEqual(item['state'],'review')
        self.assertIn('历史',item['detail']); self.assertEqual(self.panel.black,[])
        self.assertEqual(self.store.dashboard(source='panel')['summary']['expired'],1)

    def test_historical_and_recent_agent_access_do_not_mix_evidence(self):
        self.put([access(),access(time_text='01/Jan/2020:00:00:00 +0000')])
        self.worker.process_once()
        self.assertEqual(self.panel.black,[])
        self.assertEqual(len(self.model.calls),2)
        self.assertEqual(sum(d['historical'] for d in self.store.dashboard(source='agent')['decisions']),1)

    def test_recently_received_rows_are_analyzed_before_a_backlog(self):
        self.put([access('9.9.9.9') for _ in range(5)])
        with self.store.lock,self.store.db:
            self.store.db.execute('UPDATE agent_events SET received=received-3600')
        self.put([access(),access(path='/wp-admin')])
        self.assertEqual({e['raw'].split()[0] for e in self.store.pending(2)},{'8.8.8.8'})
        rows=self.store.pending(500)
        self.assertEqual([e['raw'].split()[0] for e in rows],['8.8.8.8']*2+['9.9.9.9']*5)

    def test_single_live_requests_split_across_waves_combine_for_a_ban(self):
        self.put([access()]); self.worker.process_once()
        self.assertEqual(self.panel.black,[])
        self.assertEqual(self.store.dashboard(source='agent')['decisions'][0]['state'],'review')
        self.put([access(path='/wp-admin')]); self.worker.process_once()
        self.assertEqual(self.panel.black[0]['ipv4'],'8.8.8.8')

    def test_split_waves_do_not_borrow_from_other_servers_or_low_confidence(self):
        other=self.register('另一台服务器')
        self.put([access()]); self.worker.process_once()
        self.put([access(path='/wp-admin')],other); self.worker.process_once()
        self.assertEqual(self.panel.black,[])
        self.model.confidence=.5; self.put([access(path='/x')],other); self.worker.process_once()
        self.model.confidence=.99; self.put([access(path='/y')]); self.worker.process_once()
        self.assertEqual(self.panel.black[0]['ipv4'],'8.8.8.8')

    def test_repeated_identical_request_counts_as_two_requests(self):
        self.store.append('panel',{},1,'access.log',[access(),access()])
        with patch.object(self.model,'analyze',side_effect=lambda events,config:[{'ip':'8.8.8.8','is_attack':True,'confidence':.99,
                'attack_type':'scanner','reason':'扫描','evidence_ids':[events[0]['id']]}]):
            self.worker.process_once()
        self.assertEqual(self.panel.black[0]['ipv4'],'8.8.8.8')

    def daily(self, ip='6.6.6.6', count=18, hours=20):
        last=time.strftime('%d/%b/%Y:%H:%M:%S +0000',time.gmtime(time.time()-hours*3600))
        return json.dumps({'remote_addr':ip,'time_local':last,'request':'GET /a/actuator/env HTTP/1.1','status':404,
                           'count':count,'first_time':last,'last_time':last,'last_request':'GET /a/actuator/env HTTP/1.1',
                           'clean_date':'2026-10-15','clean_kind':'suspicious','clean_ai':True})

    def test_daily_cleaned_attack_from_yesterday_is_blocked(self):
        self.put([self.daily()],source='D:/logs/access_2026-10-15.log'); self.worker.process_once()
        decision=self.store.dashboard(source='agent')['decisions'][0]
        self.assertTrue(decision['historical']); self.assertEqual(decision['state'],'listed')
        self.assertEqual(self.panel.black[0]['ipv4'],'6.6.6.6')

    def test_old_or_single_daily_cleaned_rows_stay_review_only(self):
        self.put([self.daily('6.6.6.6',hours=72),self.daily('7.7.7.7',count=1)],source='D:/logs/access_2026-10-15.log')
        self.worker.process_once()
        self.assertEqual(self.panel.black,[])
        self.assertEqual({d['state'] for d in self.store.dashboard(source='agent')['decisions']},{'review'})

    def test_missing_original_time_is_reviewed_without_automatic_ban(self):
        raw=json.dumps({'remote_addr':'8.8.8.8','request':'GET /.env HTTP/1.1','status':404})
        self.put([raw,raw]); self.worker.process_once()
        self.assertTrue(self.store.dashboard(source='agent')['decisions'][0]['historical'])
        self.assertEqual(self.panel.black,[])
        self.assertFalse(self.model.calls[0][0]['timeReliable'])

    def test_normal_results_retry_idempotence_and_nonaccess_raw_retention(self):
        self.model.attack=False
        body=self.put([access(),access()]); self.worker.process_once()
        retry=self.hub.ingest(self.agent['agentId'],body)
        self.put(['Java application trace'],kind='error.log')
        self.put(['No visitor in this access row'])
        self.worker.process_once()
        data=self.store.dashboard(source='agent')
        self.assertEqual(retry['inserted'],0)
        self.assertEqual(data['summary']['analyzed'],2)
        self.assertEqual(data['summary']['unparsed'],1)
        self.assertEqual(data['history']['normalTotal'],1)
        self.assertEqual(self.hub.feed()['total'],4)
        self.assertEqual(self.panel.black,[])

    def test_model_failure_preserves_agent_queue_and_disabled_agent_pauses_it(self):
        self.put([access(),access()]); self.model.failure=True
        with self.assertRaises(SecurityError): self.worker.process_once()
        self.assertEqual(len(self.store.pending(500)),2)
        self.assertEqual(self.store.dashboard(source='agent')['history']['allTotal'],0)
        self.hub.set_enabled(self.agent['agentId'],False)
        self.assertEqual(self.store.pending(500),[])
        self.hub.set_enabled(self.agent['agentId'],True)
        self.model.failure=False; self.worker.process_once()
        self.assertEqual(self.store.pending(500),[])

    def test_private_and_admin_agent_ips_keep_existing_protections(self):
        self.put([access('10.0.0.1'),access('10.0.0.1'),access('8.8.6.173'),access('8.8.6.173')])
        self.worker.process_once()
        self.assertEqual(self.panel.black,[])
        self.assertEqual({d['state'] for d in self.store.dashboard(source='agent')['decisions']},{'protected'})

    def test_jev_negative_ids_use_real_evidence_and_redact_sso_ticket(self):
        self.put([access(path='/a?ticket=private-sso'),access(path='/b?ticket=another-secret')])
        events=[normalized_event(e) for e in self.store.pending(500)]
        body,originals=Jev.build(events,{'model':'typesafe/jev-1.13'})
        encoded=json.dumps(body)
        self.assertNotIn('private-sso',encoded); self.assertNotIn('another-secret',encoded)
        result=Jev.decode(answer_for(body,scores={'attack_p0':.99,'attack_p1':.99},category='scanner'),body,originals,events)
        self.assertEqual(set(result[0]['evidence_ids']),{-1,-2})

    def test_history_source_filter_snapshot_stays_stable_during_new_results(self):
        self.model.attack=False
        for _ in range(22): self.put([access()]); self.worker.process_once()
        first=self.store.dashboard(source='agent')
        ids=[d['id'] for d in first['decisions']]
        self.put([access()]); self.worker.process_once()
        second=self.store.dashboard(page=2,through=first['history']['through'],source='agent')
        self.assertEqual(second['history']['total'],22)
        self.assertFalse(set(ids)&{d['id'] for d in second['decisions']})
        self.assertEqual(self.store.dashboard(source='panel')['history']['allTotal'],0)

    def test_existing_agent_database_migrates_access_only_and_only_once(self):
        path=self.root/'legacy.sqlite3'
        with closing(sqlite3.connect(path)) as db:
            db.executescript('''CREATE TABLE agent_events (id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,event_id TEXT NOT NULL,kind TEXT NOT NULL,source TEXT NOT NULL,
                raw TEXT NOT NULL,collected REAL NOT NULL,received REAL NOT NULL,UNIQUE(agent_id,event_id));''')
            for kind in ('access.log','error.log'):
                db.execute('INSERT INTO agent_events(agent_id,event_id,kind,source,raw,collected,received) VALUES(?,?,?,?,?,?,?)',
                    ('legacy',uuid.uuid4().hex,kind,'file','raw',1,1))
            db.commit()
        migrated=Store(path)
        try:
            self.assertEqual([r[0] for r in migrated.db.execute('SELECT ai_state FROM agent_events ORDER BY id')],['pending','ignored'])
            migrated.mark([-1],'analyzed'); migrated.ensure_agent_schema()
            self.assertEqual(migrated.db.execute('SELECT ai_state FROM agent_events WHERE id=1').fetchone()[0],'analyzed')
        finally:migrated.close()


class BlacklistTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.env=patch.dict('os.environ',{},clear=True); self.env.start()
        self.root.joinpath('.env').write_text('PANEL_API_KEY=panel-secret\nOPENROUTER_API_KEY=model-secret\n',encoding='utf-8')
        self.store=Store(self.root/'state.sqlite3'); self.panel=FakePanel()
        self.waf=Waf(self.panel,self.store); self.service=BlacklistService(self.root,self.waf)
        self.hub=Hub(self.store,self.service)
        self.servers=[]

    def tearDown(self):
        for server,thread in self.servers:
            server.shutdown(); server.server_close(); thread.join(3)
        self.store.close(); self.env.stop(); self.temp.cleanup()

    def rule(self, address, name='manual', state='on'):
        return {'name':name,'type':'ipv4','ipv4':address,'state':state}

    def launch(self,local=False):
        server=LogServer(('127.0.0.1',0),self.panel,self.store,hub=self.hub,blacklist=self.service) if local else IngestServer(('127.0.0.1',0),self.hub)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        self.servers.append((server,thread)); return f'http://127.0.0.1:{server.server_port}'

    def get(self,url,headers=None,body=None):
        req=request.Request(url,headers=headers or {},data=None if body is None else json.dumps(body).encode())
        try:
            with request.urlopen(req,timeout=3) as response:
                return response.status,response.headers,response.read().decode()
        except error.HTTPError as response:
            return response.code,response.headers,response.read().decode()

    def test_generated_export_key_persists_and_preserves_other_secrets(self):
        key=self.service.key(); self.assertGreaterEqual(len(key),32)
        self.assertEqual(BlacklistService(self.root,self.waf).key(),key)
        contents=self.root.joinpath('.env').read_text()
        self.assertIn('PANEL_API_KEY=panel-secret\n',contents)
        self.assertIn('OPENROUTER_API_KEY=model-secret\n',contents)
        self.assertFalse(self.service.authorize('Bearer panel-secret'))
        self.assertFalse(self.service.authorize('Bearer 非ASCII'))

    def test_fresh_inventory_includes_manual_rules_and_omits_removed_local_blocks(self):
        self.store.set_block('8.8.8.8','removed',True,'listed')
        self.panel.black=[self.rule('9.9.9.9'),self.rule('1.1.1.1',name='disabled',state='off')]
        first=self.service.snapshot()
        self.assertEqual(first['ips'],['9.9.9.9']); self.assertEqual(first['disabledRuleCount'],1)
        self.panel.black=[self.rule('4.4.4.4')]
        second=self.service.snapshot()
        self.assertEqual(second['ips'],['4.4.4.4'])
        self.assertNotEqual(first['snapshotId'],second['snapshotId'])
        self.assertTrue(all(not p.endswith(('/create','/delete')) for p,b in self.panel.calls))

    def test_ipv6_cidr_ranges_dedupe_and_hash_are_not_expanded(self):
        self.panel.black=[self.rule('8.8.8.8'),self.rule('8.8.8.8/32',name='same'),
            self.rule('10.1.2.3/8',name='net'),
            {'name':'v6','state':'on','type':'ipv6','ipv6':'2001:4860:4860:0000:0000:0000:0000:8888'},
            {'name':'range','state':'on','type':'ipArr','ipStart':'9.9.9.1','ipEnd':'9.9.9.5'}]
        data=self.service.snapshot()
        self.assertEqual(data['total'],4); self.assertEqual(data['activeRuleCount'],5)
        self.assertEqual(data['ips'],['8.8.8.8','2001:4860:4860::8888'])
        self.assertEqual(data['networks'],['10.0.0.0/8'])
        self.assertIn('9.9.9.1-9.9.9.5\n',self.service.text(data))
        self.panel.black.reverse()
        self.assertEqual(self.service.snapshot()['snapshotId'],data['snapshotId'])

    def test_invalid_and_unexpanded_group_fail_instead_of_partial_export(self):
        for bad in [self.rule('bad'),{'name':'group','state':'on','type':'ipGroup','ipGroup':'group-id'},
            {'name':'range','state':'on','type':'ipArr','ipStart':'9.9.9.5','ipEnd':'9.9.9.1'}]:
            with self.subTest(rule=bad):
                self.panel.black=[self.rule('8.8.8.8'),bad]
                with self.assertRaises(SecurityError):self.service.snapshot()

    def test_full_pagination_and_mid_read_changes_cannot_succeed_as_partial(self):
        rules=[self.rule(f'10.0.{n//256}.{n%256}',name=str(n)) for n in range(201)]
        def search(path,body=None):
            if path.endswith('/search'):
                start=(body['page']-1)*100
                return {'items':rules[start:start+100],'total':len(rules)}
            return FakePanel.call(self.panel,path,body)
        with patch.object(self.panel,'call',side_effect=search):
            self.assertEqual(self.service.snapshot()['total'],201)
        for pages in [
            [{'items':rules[:100],'total':201},{'items':[],'total':201}],
            [{'items':rules[:100],'total':201},{'items':rules[100:200],'total':202}],
            [{'items':rules[:100],'total':201},{'items':rules[:100],'total':201}]]:
            with patch.object(self.panel,'call',side_effect=pages):
                with self.assertRaises(SecurityError):self.service.snapshot()

    def test_remote_bearer_auth_roles_json_and_text(self):
        url=self.launch(); self.panel.black=[self.rule('8.8.8.8')]
        agent=self.hub.register({'name':'test','platformUrl':url,'sources':[{'path':'file','kind':'access.log'}]})
        for headers in [{},{'Authorization':'Bearer '+agent['token']},{'Authorization':'Bearer panel-secret'}]:
            self.assertEqual(self.get(url+'/v1/blacklist',headers)[0],401)
        self.assertEqual(self.get(url+'/v1/blacklist?key='+self.service.key())[0],401)
        auth={'Authorization':'Bearer '+self.service.key()}
        status,headers,body=self.get(url+'/v1/blacklist',auth)
        data=json.loads(body); self.assertEqual(status,200); self.assertTrue(data['complete'])
        self.assertEqual(data['ips'],['8.8.8.8']); self.assertNotIn(self.service.key(),body)
        self.assertNotIn('panel-secret',body); self.assertNotIn('model-secret',body)
        status,headers,body=self.get(url+'/v1/blacklist?format=text',auth)
        self.assertEqual(body,'8.8.8.8\n'); self.assertTrue(headers['Content-Type'].startswith('text/plain'))
        self.assertEqual(self.get(url+'/v1/blacklist?format=bad',auth)[0],400)
        self.assertEqual(self.get(url+'/v1/blacklist',{**auth,'Origin':'http://other.example'})[0],403)
        self.assertEqual(self.get(url+'/v1/ingest',{**auth,'X-Agent-ID':agent['agentId'],'Content-Type':'application/json'},{'events':[]})[0],401)

    def test_upstream_failure_is_503_complete_false_and_real_empty_is_valid(self):
        url=self.launch(); auth={'Authorization':'Bearer '+self.service.key()}
        with patch.object(self.panel,'call',side_effect=PanelError('private upstream diagnostic',504)):
            status,_,body=self.get(url+'/v1/blacklist',auth)
        self.assertEqual(status,503); self.assertFalse(json.loads(body)['complete'])
        self.assertNotIn('private upstream diagnostic',body)
        status,_,body=self.get(url+'/v1/blacklist',auth)
        self.assertEqual(status,200); self.assertEqual(json.loads(body)['ips'],[])
        self.assertEqual(self.get(url+'/v1/blacklist?format=text',auth)[2],'')

    def test_local_key_api_and_download_reject_foreign_host_or_origin(self):
        url=self.launch(local=True); self.panel.black=[self.rule('8.8.8.8')]
        self.assertEqual(self.get(url+'/api/blacklist?format=text')[2],'8.8.8.8\n')
        self.assertEqual(self.get(url+'/api/blacklist/key')[0],404)
        self.assertEqual(self.get(url+'/api/blacklist/key',{'Content-Type':'application/json'},{} )[0],200)
        for headers in [{'Host':'evil.example'},{'Origin':'http://other.example'},{'Sec-Fetch-Site':'cross-site'}]:
            self.assertEqual(self.get(url+'/api/blacklist',headers)[0],403)
            self.assertEqual(self.get(url+'/api/blacklist/key',{**headers,'Content-Type':'application/json'},{} )[0],403)
        config=self.get(url+'/api/config')[2]
        self.assertNotIn(self.service.key(),config)
        with patch.object(self.panel,'call',side_effect=PanelError('upstream failed')):
            status,_,body=self.get(url+'/api/blacklist')
        self.assertEqual(status,503); self.assertFalse(json.loads(body)['complete'])


if __name__=='__main__': unittest.main()
