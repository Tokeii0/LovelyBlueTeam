"""The WAF global blacklist: read-only export with a separate key, manual blocking, and full list management."""
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

from security import SETTINGS_LOCK, SecurityError, protection_reason, settings

MANUAL_STATES = {'listed': '已加入黑名单', 'inactive': '已加入 · WAF 未就绪', 'existing': '已在黑名单中',
                 'protected': '受保护 · 未加黑', 'failed': '失败', 'unblocked': '已移除'}


class BlacklistService:
    def __init__(self, root, waf):
        self.root, self.waf = Path(root), waf
        self.clear_state, self.clear_guard = {'running': False}, threading.Lock()
        self.ensure_key()
        store = waf.store
        with store.lock, store.db:
            store.db.execute('''CREATE TABLE IF NOT EXISTS manual_blocks (
                ip TEXT PRIMARY KEY, reason TEXT NOT NULL, state TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
                created REAL NOT NULL, updated REAL NOT NULL)''')

    # ----- 手动加黑: an administrator puts addresses on the WAF global blacklist from the page -----
    def manual_list(self):
        with self.waf.store.lock:
            rows = [dict(r) for r in self.waf.store.db.execute(
                'SELECT ip,reason,state,detail,created,updated FROM manual_blocks ORDER BY updated DESC LIMIT 200')]
        for row in rows:
            row['label'] = MANUAL_STATES.get(row['state'], row['state'])
        return {'rows': rows}

    def record_manual(self, ip, reason, state, detail):
        now = time.time()
        with self.waf.store.lock, self.waf.store.db:
            self.waf.store.db.execute('''INSERT INTO manual_blocks(ip,reason,state,detail,created,updated) VALUES(?,?,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,state=excluded.state,detail=excluded.detail,
                updated=excluded.updated''', (ip, reason, state, detail[:300], now, now))

    @staticmethod
    def parse_ips(value):
        items = [v for v in re.split(r'[\s,，;；]+', value) if v] if isinstance(value, str) else None
        if not items or len(items) > 50:
            raise ValueError('请填写 1–50 个 IP，每行一个或用逗号分隔。')
        result = []
        for item in items:
            try:
                address = ipaddress.ip_address(item)
            except ValueError:
                raise ValueError(f'“{item[:60]}”不是有效的单个 IP 地址（暂不支持网段，请在 1Panel 中添加）。') from None
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            if str(address) not in result:
                result.append(str(address))
        return result

    def manual_add(self, body):
        ips = self.parse_ips(body.get('ips'))
        reason = body.get('reason', '')
        if not isinstance(reason, str) or len(reason.strip()) > 100 or any(c in reason for c in '\r\n\x00'):
            raise ValueError('加黑原因最长 100 个字符，不能换行。')
        reason = reason.strip() or '手动加黑'
        config = settings(self.root)
        panel = urlsplit(getattr(self.waf.client, 'config', {}).get('url', '')).hostname or ''
        results = []
        for ip in ips:
            # The same protections as automatic blocking: panel, reserved, private (unless allowed) and the allowlist.
            protected = protection_reason(ip, config, panel)
            if protected:
                state, detail = 'protected', protected + '，未加入黑名单。确需封禁请先调整 AI 设置中的保护名单 / 内网选项。'
            else:
                try:
                    state, detail = self.waf.add(ip, f'手动加黑：{reason}', origin='Manual')
                except SecurityError as exc:
                    state, detail = ('protected' if exc.status == 409 else 'failed'), str(exc)
            self.record_manual(ip, reason, state, detail)
            results.append({'ip': ip, 'state': state, 'label': MANUAL_STATES.get(state, state), 'detail': detail})
        return {'results': results, **self.manual_list()}

    def manual_remove(self, ip):
        if not isinstance(ip, str):
            raise ValueError('IP 参数不正确。')
        with self.waf.store.lock:
            row = self.waf.store.db.execute('SELECT reason FROM manual_blocks WHERE ip=?', (ip,)).fetchone()
        if not row:
            raise ValueError('只能移除在此页面手动加入的 IP。')
        self.waf.remove(ip)  # Only rules this program created; existing 1Panel rules stay untouched.
        self.record_manual(ip, row['reason'], 'unblocked', '已从 WAF 全局黑名单移除')
        return self.manual_list()

    # ----- 全部黑名单: every WAF global blacklist rule, whoever created it -----
    @staticmethod
    def rule_view(rule):
        kind = rule.get('type')
        target = (rule.get(kind) if kind in ('ipv4', 'ipv6') else
                  f"{rule.get('ipStart', '')}-{rule.get('ipEnd', '')}" if kind == 'ipArr' else
                  f"IP 组 {rule.get('ipGroup', '')}" if kind == 'ipGroup' else str(rule.get(kind, '')))
        description = str(rule.get('description', ''))
        match = re.match(r'^(DeepSeek|SiteVisit|CleanRule|Manual|AFSyslog) \[[^\]]*\] ?', description)
        return {'name': rule['name'], 'target': target, 'type': kind, 'enabled': rule.get('state') == 'on',
                'origin': match[1] if match else 'Panel', 'description': description[match.end():] if match else description}

    def rules(self):
        rules = [self.rule_view(r) for r in self.waf.rules('ipBlack')]
        return {'rules': rules, 'total': len(rules), 'clear': dict(self.clear_state)}

    def forget(self, rule, protect):
        """Record a removed rule locally so the automatic blockers neither show it as listed nor fight the removal."""
        try:
            address = str(ipaddress.ip_address(rule['target']))
        except ValueError:
            return  # Networks, ranges and groups have no per-IP state.
        state = 'unblocked' if protect else 'removed'
        detail = '已从黑名单移除并保护，停止再次自动加黑' if protect else '已从黑名单移除；再次命中时可重新自动加黑'
        store = self.waf.store
        previous = store.block(address)
        store.set_block(address, rule['name'], bool(previous and previous['managed']), state)
        store.update_ip_decisions(address, state, detail)
        with store.lock, store.db:
            store.db.execute("UPDATE manual_blocks SET state='unblocked',detail=?,updated=? WHERE ip=?", (detail, time.time(), address))
            for table in ('rule_block_ips', 'site_visit_ips'):
                try:
                    store.db.execute(f'UPDATE {table} SET state=?,detail=?,updated=? WHERE ip=?', (state, detail, time.time(), address))
                except Exception:
                    pass  # That feature's table does not exist on this installation.

    def delete_rule(self, rule, protect):
        with self.waf.lock:  # Never interleave with an automatic add of the same address.
            self.waf.client.call('/xpack/waf/rule/ip/delete', {'name': rule['name'], 'scope': 'ipBlack'})
        self.forget(rule, protect)

    def remove_rules(self, body):
        names, protect = body.get('names'), body.get('protect', False)
        if (not isinstance(names, list) or not 1 <= len(names) <= 200 or len(set(names)) != len(names) or
                any(not isinstance(n, str) or not 1 <= len(n) <= 100 for n in names) or type(protect) is not bool):
            raise ValueError('请选择 1–200 条要移除的黑名单。')
        if self.clear_state.get('running'):
            raise ValueError('正在清空黑名单，请等待完成。')
        current = {r['name']: r for r in self.rules()['rules']}
        missing = [n for n in names if n not in current]
        removed, failed = [], []
        for name in names:
            if name in missing:
                continue
            try:
                self.delete_rule(current[name], protect)
                removed.append(current[name]['target'])
            except Exception as exc:
                failed.append(f"{current[name]['target']}：{exc}"[:200])
        left = {r['name'] for r in self.waf.rules('ipBlack')}
        unconfirmed = [current[n]['target'] for n in names if n in current and n in left]
        return {'removed': len(removed) - len(unconfirmed), 'missing': len(missing), 'failed': failed,
                'unconfirmed': unconfirmed, **self.rules()}

    def clear_all(self, body):
        if body.get('confirm') != '清空' or type(body.get('protect', False)) is not bool:
            raise ValueError('请输入“清空”确认。')
        with self.clear_guard:
            if self.clear_state.get('running'):
                raise ValueError('正在清空黑名单，请等待完成。')
            snapshot = self.rules()['rules']
            self.clear_state = {'running': True, 'total': len(snapshot), 'done': 0, 'failed': 0, 'errors': [],
                                'started': time.time(), 'finished': None}
        protect = body.get('protect', False)

        def work():
            for rule in snapshot:
                try:
                    self.delete_rule(rule, protect)
                    self.clear_state['done'] += 1
                except Exception as exc:
                    self.clear_state['failed'] += 1
                    if len(self.clear_state['errors']) < 20:
                        self.clear_state['errors'].append(f"{rule['target']}：{exc}"[:200])
            self.clear_state.update(running=False, finished=time.time())
        threading.Thread(target=work, daemon=True, name='blacklist-clear').start()
        return self.rules()

    def key(self):
        if 'BLACKLIST_API_KEY' in os.environ:
            return os.environ['BLACKLIST_API_KEY']
        path = self.root / '.env'
        with SETTINGS_LOCK:
            for line in path.read_text(encoding='utf-8-sig').splitlines() if path.exists() else []:
                if not line.lstrip().startswith('#') and '=' in line:
                    name,value = line.split('=',1)
                    if name.strip() == 'BLACKLIST_API_KEY': return value.strip().strip('"\'')
        return ''

    def ensure_key(self):
        with SETTINGS_LOCK:
            key = self.key()
            if key:
                if not 24 <= len(key) <= 512 or any(not 33 <= ord(c) <= 126 for c in key):
                    raise ValueError('BLACKLIST_API_KEY 应为至少 24 个可打印 ASCII 字符。')
                return
            if 'BLACKLIST_API_KEY' in os.environ:
                return  # Explicitly empty environment variable disables remote access.
            path=self.root/'.env'; lines=path.read_text(encoding='utf-8-sig').splitlines() if path.exists() else []
            lines=[line for line in lines if line.split('=',1)[0].strip()!='BLACKLIST_API_KEY']
            lines.append('BLACKLIST_API_KEY='+secrets.token_urlsafe(32))
            temporary=self.root/'.env.tmp'; temporary.write_text('\n'.join(lines)+'\n',encoding='utf-8')
            os.replace(temporary,path)

    def authorize(self, header):
        key=self.key()
        if not key or not key.isascii() or not isinstance(header,str) or not header.startswith('Bearer '): return False
        supplied=header[7:]
        if not supplied.isascii() or len(supplied)>512: return False
        return hmac.compare_digest(key,supplied)

    def snapshot(self):
        # Always fetch the upstream inventory: manual changes and site rules count too.
        rules=self.waf.rules('ipBlack')
        ips,networks,ranges,unresolved=set(),set(),set(),[]
        active,disabled=0,0
        for rule in rules:
            if rule.get('state')!='on': disabled+=1; continue
            active+=1; kind=rule.get('type')
            try:
                if kind in ('ipv4','ipv6'):
                    network=ipaddress.ip_network(rule[kind],strict=False)
                    if network.version != (4 if kind=='ipv4' else 6): raise ValueError()
                    if network.num_addresses==1: ips.add(str(network.network_address))
                    else: networks.add(str(network))
                elif kind=='ipArr':
                    first,last=ipaddress.ip_address(rule['ipStart']),ipaddress.ip_address(rule['ipEnd'])
                    if first.version!=last.version or int(first)>int(last): raise ValueError()
                    ranges.add((str(first),str(last)))
                else:
                    unresolved.append({'name':str(rule.get('name','')),'type':str(kind),
                                       'reason':'IP 组或未支持的规则类型，需要展开成员后同步。'})
            except (ValueError,KeyError,TypeError):
                unresolved.append({'name':str(rule.get('name','')),'type':str(kind),'reason':'规则地址格式不完整。'})
        if unresolved:
            raise SecurityError('存在无法完整展开的黑名单规则，已停止导出以避免遗漏。请检查 IP 组或无效地址。',503)
        ips=sorted(ips,key=lambda v:(ipaddress.ip_address(v).version,int(ipaddress.ip_address(v))))
        networks=sorted(networks)
        ranges=[{'start':first,'end':last} for first,last in sorted(ranges)]
        targets=ips+networks+[f'{value["start"]}-{value["end"]}' for value in ranges]
        return {'version':1,'complete':True,'source':'1panel-waf-global-ipBlack',
                'generatedAt':datetime.now(timezone.utc).isoformat(),'total':len(targets),
                'activeRuleCount':active,'disabledRuleCount':disabled,'ips':ips,'networks':networks,'ranges':ranges,
                'targets':targets,'snapshotId':hashlib.sha256(('\n'.join(targets)).encode()).hexdigest(),
                'waf':self.waf.status()}

    @staticmethod
    def text(snapshot):
        return '\n'.join(snapshot['targets'])+('\n' if snapshot['targets'] else '')
