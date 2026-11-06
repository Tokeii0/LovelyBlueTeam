"""Run the built Windows executable against a temporary receiver, never the live panel."""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hub import Hub
from storage import Store


def main():
    exe = ROOT / 'agent' / 'dist' / 'LogAgent.exe'
    with tempfile.TemporaryDirectory(prefix='nginx agent ') as directory:
        root = Path(directory)
        store = Store(root/'hub.sqlite3'); hub = Hub(store)
        hub.start_receiver('127.0.0.1',0,'http://127.0.0.1')
        path = root/'中文访问.log'; path.write_text('same\nsame\n中文\n',encoding='utf-8')
        config = hub.register({'name':'Windows EXE smoke test',
                               'sources':[{'path':str(path),'kind':'access.log'}]})
        config_file = root/'config.json'
        def run(ok=True):
            config_file.write_text(json.dumps(config,ensure_ascii=False),encoding='utf-8')
            result = subprocess.run([str(exe),'--once','--config',str(config_file)],
                                    capture_output=True,timeout=40,
                                    creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if (result.returncode == 0) != ok:
                raise AssertionError('Windows executable unexpected exit code: '+str(result.returncode))
        try:
            run(); assert hub.feed()['total'] == 3
            run(); assert hub.feed()['total'] == 3
            config['platformUrl'] = 'http://127.0.0.1:1'
            with path.open('ab') as file: file.write('离线新增\n'.encode())
            run(False)
            queue = sqlite3.connect(root/'runtime'/'agent.sqlite3')
            assert queue.execute('SELECT COUNT(*) FROM outbox').fetchone()[0] == 1
            queue.close(); assert hub.feed()['total'] == 3
            config['platformUrl'] = hub.advertised_url
            run(); assert hub.feed()['total'] == 4
            with path.open('ab') as file: file.write('轮转未读\n'.encode())
            path.rename(root/'中文访问.log.1')
            path.write_text('新文件\n',encoding='utf-8')
            run(); assert hub.feed()['total'] == 6
            queue = sqlite3.connect(root/'runtime'/'agent.sqlite3')
            assert queue.execute('SELECT COUNT(*) FROM outbox').fetchone()[0] == 0
            queue.close()
            assert hub.overview()['online'] == 1
            tomcat=root/'tomcat'; tomcat.mkdir()
            config['sources']=[{'kind':kind,'path':str(tomcat/pattern)} for kind,pattern in
                              [('access.log','localhost_access_log.*.txt'),('error.log','catalina.*.log'),('custom.log','localhost.*.log')]]
            for name in ('localhost_access_log.2026-10-14.txt','catalina.2026-10-14.log','localhost.2026-10-14.log'):
                (tomcat/name).write_bytes(b'')
            run(); assert hub.feed()['total']==6
            (tomcat/'localhost_access_log.2026-10-15.txt').write_text(''.join(f'tomcat request {i}\n' for i in range(750)),encoding='utf-8')
            (tomcat/'catalina.2026-10-15.log').write_text('Tomcat startup 中文\n',encoding='utf-8')
            (tomcat/'localhost.2026-10-15.log').write_text('Application event\n',encoding='utf-8')
            run(); assert hub.feed()['total']==758
            run(); assert hub.feed()['total']==758
            print(json.dumps({'windowsExe':True,'unicodeAndSpacePaths':True,'duplicateRowsPreserved':True,
                              'restartNoReplay':True,'offlineQueueAndReplay':True,'rotationUnreadDrained':True,
                              'tomcatDateRolloverAll750Rows':True,'threeTomcatSources':True,
                              'receivedRows':758,'persistentTaskInstalled':False}))
        finally:
            hub.stop_receiver(); store.db.close()


if __name__ == '__main__': main()
