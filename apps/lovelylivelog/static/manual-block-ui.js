// 手动加黑 on the 黑名单 page: an administrator adds IPs to the WAF global blacklist.
import {isActive} from './nav.js';
import {$, toast} from './ui.js';

const TONES = {listed: 'action-ai', existing: 'action-ai', inactive: 'action-drop', protected: 'action-archive',
  failed: 'action-drop', unblocked: 'action-archive'};
const date = seconds => seconds ? new Date(seconds * 1000).toLocaleString('zh-CN', {hour12: false}) : '';

async function call(path, body) {
  // Each IP is written to the WAF and read back, so a batch of 50 can take a while.
  const response = await fetch(path, {signal: AbortSignal.timeout(180000),
    ...(body ? {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)} : {})});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '操作失败。');
  return data;
}

function notice(message) {
  $('manual-block-notice').hidden = !message;
  $('manual-block-notice').textContent = message || '';
}

function cell(text, className = '') {
  const node = document.createElement('td');
  node.textContent = text; node.title = text;
  if (className) node.className = className;
  return node;
}

function render(data) {
  $('manual-block-empty').hidden = data.rows.length > 0;
  $('manual-block-rows').replaceChildren(...data.rows.map(row => {
    const tr = document.createElement('tr');
    const actions = document.createElement('td');
    if (['listed', 'inactive', 'existing'].includes(row.state)) {
      const button = Object.assign(document.createElement('button'), {type: 'button', className: 'text-button accent', textContent: '移除'});
      button.addEventListener('click', () => remove(row.ip, button));
      actions.append(button);
    }
    tr.append(cell(row.ip), cell(row.reason), cell(row.label, TONES[row.state] || ''), cell(row.detail), cell(date(row.updated)), actions);
    tr.firstChild.dataset.geoIp = row.ip;
    return tr;
  }));
}

async function refresh() {
  try { render(await call('/api/blacklist/manual')); } catch (error) { notice(error.message); }
}

async function remove(ip, button) {
  if (!confirm(`把 ${ip} 从 WAF 全局黑名单移除？`)) return;
  button.disabled = true;
  try { render(await call('/api/blacklist/manual/remove', {ip})); notice(''); toast(`${ip} 已移除`); }
  catch (error) { notice(error.message); button.disabled = false; }
}

$('manual-block-form').addEventListener('submit', async event => {
  event.preventDefault();
  const ips = $('manual-block-ips').value.trim();
  const count = ips.split(/[\s,，;；]+/).filter(Boolean).length;
  if (!count) return;
  if (!confirm(`把 ${count} 个 IP 加入 1Panel WAF 全局黑名单（并随 AF 联动同步到防火墙）？`)) return;
  const button = $('manual-block-submit');
  button.disabled = true; button.textContent = '正在加入…';
  try {
    const data = await call('/api/blacklist/manual/add', {ips, reason: $('manual-block-reason').value});
    render(data);
    const done = data.results.filter(r => ['listed', 'inactive', 'existing'].includes(r.state)).length;
    const skipped = data.results.filter(r => !['listed', 'inactive', 'existing'].includes(r.state));
    notice(skipped.map(r => `${r.ip}：${r.label}，${r.detail}`).join('\n'));
    toast(`已加入 ${done} 个${skipped.length ? `，${skipped.length} 个未加入` : ''}`, skipped.length ? 'error' : '');
    if (!skipped.length) { $('manual-block-ips').value = ''; $('manual-block-reason').value = ''; }
  } catch (error) { notice(error.message); }
  finally { button.disabled = false; button.textContent = '加入黑名单'; }
});

const onScreen = () => isActive('blacklist');
document.addEventListener('view-change', () => { if (onScreen()) refresh(); });
if (onScreen()) refresh();
