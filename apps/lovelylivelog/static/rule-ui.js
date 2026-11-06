import {isActive} from './nav.js';

const $ = id => document.getElementById(id);
const labels = {pending:'等待加黑',failed:'失败 · 自动重试',protected:'已保护',paused:'已暂停',
  listed:'已加入全局名单',existing:'已有黑名单',inactive:'已加入 · WAF 未就绪',removed:'已移出黑名单',unblocked:'已移除并保护'};
const date = value => value ? new Date(value * 1000).toLocaleString('zh-CN',{hour12:false}) : '—';
let loading = false, writing = false, revision = 0, enabledState = false;
async function refresh(body) {
  if (!body && (loading || writing)) return;
  const currentRevision = body ? ++revision : revision;
  if (body) writing = true; else loading = true;
  try {
    const response = await fetch('/api/site-rule',{signal:AbortSignal.timeout(15000),
      ...(body ? {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)} : {})});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '规则状态读取失败。');
    if (currentRevision !== revision) return;
    enabledState = data.enabled;
    document.querySelectorAll('[data-site-rule-domain]').forEach(el => {el.textContent = data.domain;});
    $('visit-rule-enabled').checked = data.enabled;
    $('visit-rule-badge').textContent = data.enabled ? data.busy ? '正在加黑' : '每分钟执行' : '已暂停';
    $('visit-rule-badge').className = `status-badge${data.enabled ? ' success' : ''}`;
    $('visit-rule-timing').textContent = `最近统计：${date(data.checkedAt)} · 下次统计：${data.enabled ? date(data.nextCheckAt) : '已暂停'} · 本轮 ${data.lastRows.toLocaleString()} 条访问 / ${data.lastIps.toLocaleString()} 个 IP`;
    $('visit-rule-counts').textContent = `命中 ${data.totalIps.toLocaleString()} 个 IP · 加入/已有名单 ${data.listed.toLocaleString()} · 待处理 ${data.pending.toLocaleString()} · 受保护 ${data.protected.toLocaleString()}${data.unparsed ? ` · 无法提取 IP ${data.unparsed.toLocaleString()} 条` : ''}`;
    $('visit-rule-notice').hidden = !data.lastError; $('visit-rule-notice').textContent = data.lastError;
    $('visit-rule-empty').hidden = Boolean(data.results.length);
    $('visit-rule-rows').replaceChildren(...data.results.map(item => {
      const row = document.createElement('tr');
      for (const value of [item.ip,item.count.toLocaleString(),date(item.last_seen),labels[item.state]||item.state,
        item.detail + (item.retry_at && item.state==='failed' ? ` · 重试时间 ${date(item.retry_at)}` : '')]) {
        const cell = document.createElement('td'); cell.textContent = value; cell.title = value; row.append(cell);
      }
      row.firstChild.dataset.geoIp = item.ip;
      return row;
    }));
    return true;
  } catch (error) {
    if (currentRevision !== revision) return;
    $('visit-rule-notice').hidden = false;
    $('visit-rule-notice').textContent = error.name==='TimeoutError' ? '读取超时，稍后自动重试。' : error.message;
    return false;
  } finally {if (body) writing = false; else loading = false;}
}
$('visit-rule-enabled').addEventListener('change', async () => {
  const toggle = $('visit-rule-enabled'); const enabled = toggle.checked;
  toggle.disabled = true;
  try {if (!await refresh({enabled})) toggle.checked = enabledState;} finally {toggle.disabled = false;}
});
const onScreen = () => isActive('rule');
document.addEventListener('view-change', () => {if (onScreen()) refresh();});
if (onScreen()) refresh();
setInterval(() => {if (!document.hidden && onScreen()) refresh();},3000);
