import copy
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib import error, request
import uuid
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.agent import Agent, QueueFull, load_config, transfer_state
from hub import Hub, IngestServer, platform_url
from server import LogServer
from storage import Store


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / 'access.log'
        self.path.write_bytes(b'')
        self.config = {'agentId': str(uuid.uuid4()), 'token': 'test-token-1234567890123456789',
                       'platformUrl': 'http://127.0.0.1:9', 'interval': 3, 'initialLines': 0,
                       'maxQueueMB': 8, 'sources': [{'path': str(self.path), 'kind': 'access.log', 'encoding': 'utf-8'}]}
        self.agent = Agent(self.config, self.root / 'state')
        self.agent.collect()

    def tearDown(self):
        self.agent.close()
        self.temp.cleanup()

    def raws(self):
        return [event['raw'] for _, event in self.agent.pending()]

    def append(self, data):
        with self.path.open('ab') as f: f.write(data)

    def test_incremental_duplicate_content_is_not_dropped(self):
        self.append(b'same\nsame\n')
        self.agent.collect(); self.agent.collect()
        self.assertEqual(self.raws(), ['same', 'same'])
        self.assertEqual(len({e['eventId'] for _, e in self.agent.pending()}), 2)

    def test_split_utf8_and_partial_survive_restart(self):
        data = '完整中文\n'.encode()
        self.append(data[:2]); self.agent.collect()
        self.assertEqual(self.raws(), [])
        self.agent.close()
        self.agent = Agent(self.config, self.root / 'state')
        self.append(data[2:]); self.agent.collect()
        self.assertEqual(self.raws(), ['完整中文'])

    def test_initial_tail_reads_only_last_200(self):
        self.path.write_text(''.join(f'{i}\n' for i in range(600)), encoding='utf-8')
        config = copy.deepcopy(self.config); config['initialLines'] = 200
        agent = Agent(config, self.root / 'tail-state')
        try:
            agent.collect(); agent.collect()
            self.assertEqual([e['raw'] for _, e in agent.pending()], [str(i) for i in range(400,600)])
        finally: agent.close()

    def test_install_state_transfer_preserves_queue_ids_and_cursor(self):
        self.append(b'pending portable\n'); self.agent.collect()
        event_id = self.agent.pending()[0][1]['eventId']
        transfer_state(self.root/'state', self.root/'installed'/'runtime')
        installed = Agent(self.config, self.root/'installed'/'runtime')
        try:
            installed.collect()
            self.assertEqual(installed.queue_depth(),1)
            self.assertEqual(installed.pending()[0][1]['eventId'],event_id)
            self.append(b'after install\n'); installed.collect()
            self.assertEqual([e['raw'] for _, e in installed.pending()],['pending portable','after install'])
            with self.assertRaises(ValueError): transfer_state(self.root/'state',self.root/'installed'/'runtime')
        finally: installed.close()

    def test_baseline_unfinished_line_is_skipped(self):
        self.path.write_bytes(b'old partial')
        agent = Agent(self.config, self.root / 'baseline')
        try:
            agent.collect()
            self.append(b' completed\nnew\n'); agent.collect()
            self.assertEqual([e['raw'] for _, e in agent.pending()], ['new'])
        finally: agent.close()

    def test_rename_rotation_drains_unread_old_file_and_reads_new_from_zero(self):
        self.append(b'old1\n'); self.agent.collect()
        self.append(b'old2\n')
        self.path.rename(self.root / 'access.log.1')
        self.path.write_bytes(b'new1\nnew2\n')
        self.agent.collect(); self.agent.collect()
        self.assertEqual(self.raws(), ['old1', 'old2', 'new1', 'new2'])

    def test_wildcard_rotation_without_replacement_does_not_repeat_tail(self):
        self.config['sources'][0]['path'] = str(self.root / 'access.log*')
        self.config['initialLines'] = 200
        self.append(b'old\n'); self.agent.collect()
        rotated = self.root / 'access.log.1'
        self.path.rename(rotated)
        with rotated.open('ab') as f: f.write(b'unread\n')
        self.agent.collect()
        self.path.write_bytes(b'new\n'); self.agent.collect(); self.agent.collect()
        self.assertEqual(self.raws(), ['old', 'unread', 'new'])

    def test_same_file_truncation_and_regrowth_reset_cursor(self):
        self.append(b'old old old\n'); self.agent.collect()
        self.path.write_bytes(b'new\n'); self.agent.collect()
        self.path.write_bytes(b'replacement is longer than old\n'); self.agent.collect()
        self.assertEqual(self.raws(), ['old old old', 'new', 'replacement is longer than old'])

    def test_queue_limit_does_not_advance_file_position(self):
        self.config['maxQueueMB'] = 0
        self.append(b'preserve\n'); self.agent.collect()
        self.assertIn('full', self.agent.last_error)
        self.assertEqual(self.raws(), [])
        self.config['maxQueueMB'] = 8; self.agent.collect()
        self.assertEqual(self.raws(), ['preserve'])

    def test_offline_retry_keeps_same_ids_and_collection_continues(self):
        self.append(b'first\n')
        with patch.object(self.agent, 'send', side_effect=OSError('secret should not be logged')):
            self.agent.tick(); ids = [e['eventId'] for _, e in self.agent.pending()]
            self.append(b'second\n'); self.agent.tick()
        self.assertEqual(self.raws(), ['first','second'])
        self.assertEqual(self.agent.pending()[0][1]['eventId'], ids[0])
        self.assertNotIn('secret', self.agent.last_error)

    def test_gbk_and_long_partial_are_bounded(self):
        self.config['sources'][0]['encoding'] = 'gbk'
        self.append('中文日志\n'.encode('gbk')); self.agent.collect()
        self.append(b'x' * 200000); self.agent.collect()
        self.append(b'\nnext\n'); self.agent.collect()
        self.assertEqual(self.raws()[0], '中文日志')
        self.assertIn('truncated', self.raws()[1]); self.assertLess(len(self.raws()[1]), 8250)
        self.assertEqual(self.raws()[2], 'next')

    def test_tomcat_daily_file_reads_every_line_even_over_initial_tail_limit(self):
        config=copy.deepcopy(self.config); config['initialLines']=200
        config['sources'][0]['path']=str(self.root/'localhost_access_log.*.txt')
        today=self.root/'localhost_access_log.2026-10-14.txt'; today.write_bytes(b'')
        agent=Agent(config,self.root/'tomcat')
        try:
            agent.collect()
            tomorrow=self.root/'localhost_access_log.2026-10-15.txt'
            tomorrow.write_text(''.join(f'request {i}\n' for i in range(750)),encoding='utf-8')
            agent.collect(); agent.collect()
            raws=[r['raw'] for r in agent.db.execute('SELECT raw FROM outbox ORDER BY seq')]
            self.assertEqual(raws,[f'request {i}' for i in range(750)])
        finally:agent.close()

    def test_tomcat_first_existing_file_still_respects_tail_limit(self):
        config=copy.deepcopy(self.config); config['initialLines']=200
        config['sources'][0]['path']=str(self.root/'localhost_access_log.*.txt')
        path=self.root/'localhost_access_log.2026-10-13.txt'
        path.write_text(''.join(f'old {i}\n' for i in range(400)),encoding='utf-8')
        agent=Agent(config,self.root/'tomcat-tail')
        try:
            agent.collect()
            self.assertEqual([e['raw'] for _,e in agent.pending()],[f'old {i}' for i in range(200,400)])
        finally:agent.close()

    def test_new_daily_file_during_restart_is_not_baselined_again(self):
        config=copy.deepcopy(self.config); config['initialLines']=0
        config['sources'][0]['path']=str(self.root/'catalina.*.log')
        agent=Agent(config,self.root/'daily-restart'); agent.collect(); agent.close()
        path=self.root/'catalina.2026-10-15.log'; path.write_text('new file\n中文\n',encoding='utf-8')
        agent=Agent(config,self.root/'daily-restart')
        try:
            agent.collect(); agent.collect()
            self.assertEqual([e['raw'] for _,e in agent.pending()],['new file','中文'])
        finally:agent.close()

    def test_wildcard_with_over_100_old_files_keeps_newest_file(self):
        config=copy.deepcopy(self.config); config['initialLines']=200
        config['sources'][0]['path']=str(self.root/'localhost_access_log.*.txt')
        for i in range(125):
            path=self.root/f'localhost_access_log.2025-{i:03d}.txt'; path.write_bytes(b'')
            os.utime(path,ns=(1000+i,1000+i))
        newest=self.root/'localhost_access_log.2026-10-14.txt'; newest.write_text('latest\n',encoding='utf-8')
        agent=Agent(config,self.root/'many-files')
        try:
            agent.collect()
            self.assertEqual([e['raw'] for _,e in agent.pending()],['latest'])
            self.assertEqual(agent.statuses[0]['path'],str(newest))
        finally:agent.close()

    def test_old_agent_cursors_migrate_without_skipping_new_date_file(self):
        config=copy.deepcopy(self.config); config['initialLines']=0
        config['sources'][0]['path']=str(self.root/'localhost_access_log.*.txt')
        today=self.root/'localhost_access_log.2026-10-14.txt'; today.write_bytes(b'')
        agent=Agent(config,self.root/'migration')
        try:
            agent.collect()
            agent.db.execute('DROP TABLE source_patterns'); agent.db.commit()
        finally:agent.close()
        new=self.root/'localhost_access_log.2026-10-15.txt'; new.write_text('migration preserved\n',encoding='utf-8')
        agent=Agent(config,self.root/'migration')
        try:
            agent.collect()
            self.assertEqual([e['raw'] for _,e in agent.pending()],['migration preserved'])
        finally:agent.close()

    def test_config_rejects_url_credentials_redirect_targets_and_bad_encoding(self):
        path = self.root / 'config.json'
        for key, value in [('platformUrl','http://user:pass@host/'), ('platformUrl','http://host/?token=secret'),
                           ('token','short')]:
            bad = copy.deepcopy(self.config); bad[key] = value
            path.write_text(json.dumps(bad), encoding='utf-8')
            with self.assertRaises(ValueError): load_config(path)
        bad = copy.deepcopy(self.config); bad['sources'][0]['encoding'] = 'utf-16'
        path.write_text(json.dumps(bad),encoding='utf-8')
        with self.assertRaises(ValueError): load_config(path)


class HubTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.store = Store(self.root / 'hub.sqlite3'); self.hub = Hub(self.store)
        self.hub.advertised_url = 'http://127.0.0.1:8788'
        self.config = self.hub.register({'name': '中文服务器', 'sources': [{'kind':'access.log','path':'C:/nginx/logs/access.log'}]})

    def tearDown(self):
        self.hub.stop_receiver(); self.store.db.close(); self.temp.cleanup()

    def events(self, count):
        return [{'eventId': uuid.uuid4().hex, 'raw': f'GET /normal/{i} 200', 'source':'C:/nginx/logs/access.log',
                 'kind':'access.log','collectedAt':1700000000+i} for i in range(count)]

    def test_hash_only_authentication_revocation_and_independent_agents(self):
        self.assertTrue(self.hub.authenticate(self.config['agentId'], 'Bearer '+self.config['token']))
        other = self.hub.register({'name':'other','sources':self.config['sources']})
        self.assertFalse(self.hub.authenticate(other['agentId'],'Bearer '+self.config['token']))
        public = json.dumps(self.hub.overview())
        self.assertNotIn(self.config['token'], public); self.assertNotIn('token_hash', public)
        saved = self.store.db.execute('SELECT token_hash FROM agents WHERE id=?',(self.config['agentId'],)).fetchone()[0]
        self.assertNotEqual(saved, self.config['token'])
        self.hub.set_enabled(self.config['agentId'],False)
        self.assertFalse(self.hub.authenticate(self.config['agentId'],'Bearer '+self.config['token']))

    def test_duplicate_retry_is_idempotent_but_identical_rows_are_kept(self):
        events = self.events(2); events[1]['raw'] = events[0]['raw']
        self.assertEqual(self.hub.ingest(self.config['agentId'],{'events':events})['inserted'],2)
        self.assertEqual(self.hub.ingest(self.config['agentId'],{'events':events}),{'accepted':2,'inserted':0})
        self.assertEqual(self.hub.feed()['total'],2)

    def test_stable_pagination_search_wildcards_and_type_filters(self):
        events = self.events(210); events[0]['raw'] = 'literal %_ marker'
        self.hub.ingest(self.config['agentId'],{'events':events})
        first = self.hub.feed(); self.hub.ingest(self.config['agentId'],{'events':self.events(5)})
        second = self.hub.feed(page=2,through=first['through'])
        self.assertEqual(second['total'],210)
        self.assertFalse({e['id'] for e in first['events']} & {e['id'] for e in second['events']})
        self.assertEqual(self.hub.feed(query='%_')['total'],1)
        self.assertEqual(self.hub.feed(kind='error.log')['total'],0)

    def test_invalid_batch_is_atomic_and_disabled_ingest_rejected(self):
        events = self.events(2); events[1]['collectedAt'] = float('nan')
        with self.assertRaises(ValueError): self.hub.ingest(self.config['agentId'],{'events':events})
        self.assertEqual(self.hub.feed()['total'],0)
        self.hub.set_enabled(self.config['agentId'],False)
        with self.assertRaises(PermissionError): self.hub.ingest(self.config['agentId'],{'events':self.events(1)})

    def test_receiver_exposes_only_authenticated_upload_and_health(self):
        self.hub.start_receiver('127.0.0.1',0,'http://127.0.0.1')
        base = self.hub.advertised_url
        for path in ('/api/agents','/.env','/','/v1/ingest'):
            with self.assertRaises(error.HTTPError) as raised: request.urlopen(base+path)
            self.assertEqual(raised.exception.code,404)
        headers = {'Content-Type':'application/json','X-Agent-ID':self.config['agentId'],'Authorization':'Bearer '+self.config['token']}
        payload = json.dumps({'events':self.events(1)}).encode()
        with request.urlopen(request.Request(base+'/v1/ingest',data=payload,headers=headers)) as res:
            self.assertEqual(json.load(res)['inserted'],1)
        for bad in ({'Authorization':'Bearer invalid'}, {'Origin':'http://example.com'}):
            with self.assertRaises(error.HTTPError) as raised:
                request.urlopen(request.Request(base+'/v1/ingest',data=payload,headers={**headers,**bad}))
            self.assertIn(raised.exception.code,(401,403))

    def test_real_agent_upload_ack_and_restart_exactly_once(self):
        self.hub.start_receiver('127.0.0.1',0,'http://127.0.0.1')
        config = copy.deepcopy(self.config); config['platformUrl'] = self.hub.advertised_url
        log = self.root / 'real.log'; log.write_text('one\none\n',encoding='utf-8')
        config['sources'][0]['path'] = str(log)
        agent = Agent(config,self.root/'real-agent')
        try:
            agent.tick(); self.assertEqual(agent.queue_depth(),0)
            self.assertEqual(self.hub.feed()['total'],2)
        finally: agent.close()
        agent = Agent(config,self.root/'real-agent')
        try:
            agent.tick(); self.assertEqual(self.hub.feed()['total'],2)
            with log.open('a',encoding='utf-8') as f: f.write('third\n')
            agent.tick(); self.assertEqual(self.hub.feed()['total'],3)
            self.assertEqual(self.hub.overview()['online'],1)
        finally: agent.close()

    def test_personal_package_contains_only_own_token_and_installer(self):
        import hub
        fake_root = self.root / 'package'; (fake_root/'agent'/'dist').mkdir(parents=True)
        (fake_root/'agent'/'dist'/'LogAgent.exe').write_bytes(b'test-exe')
        for name in ('run.cmd','install.cmd','uninstall.cmd','README.txt'):
            (fake_root/'agent'/name).write_text('test',encoding='utf-8')
        with patch.object(hub,'ROOT',fake_root):
            agent_id, data = self.hub.enroll({'name':'fresh','sources':self.config['sources']})
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            config = json.loads(archive.read('config.json'))
            self.assertEqual(config['agentId'],agent_id)
            self.assertNotEqual(config['token'],self.config['token'])
            self.assertEqual(set(archive.namelist()),{'LogAgent.exe','run.cmd','install.cmd','uninstall.cmd','README.txt','config.json'})
        self.assertTrue(self.hub.authenticate(agent_id,'Bearer '+config['token']))

    def test_local_admin_routes_keep_same_origin_guard(self):
        client = type('Client',(),{'config':{'url':'http://panel.test','prefix':'/api/v2'}})()
        server = LogServer(('127.0.0.1',0),client,store=self.store,hub=self.hub)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            with request.urlopen(base+'/api/agents') as res:
                self.assertEqual(json.load(res)['agents'][0]['name'],'中文服务器')
            data = json.dumps({'agentId':self.config['agentId'],'enabled':False}).encode()
            with self.assertRaises(error.HTTPError) as raised:
                request.urlopen(request.Request(base+'/api/agents/state',data=data,
                    headers={'Content-Type':'application/json','Origin':'https://external.test'}))
            self.assertEqual(raised.exception.code,403)
            with request.urlopen(request.Request(base+'/api/agents/state',data=data,headers={'Content-Type':'application/json'})) as res:
                self.assertTrue(json.load(res)['ok'])
        finally: server.shutdown(); server.server_close()


if __name__ == '__main__': unittest.main()
