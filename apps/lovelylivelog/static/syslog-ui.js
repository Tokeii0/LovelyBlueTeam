import {isActive} from './nav.js';
import {$, toast} from './ui.js';

const types = {waf: 'Web 应用防护', ips: '漏洞攻击防护', other: '其他', unknown: '未识别'};
const blockStates = {pending: '待处理', listed: '已加入 WAF', existing: '已在 WAF 名单', inactive: '已入名单 · WAF 未就绪',
  protected: '已跳过', failed: '失败 · 自动重试'};
const number = n => Number(n || 0).toLocaleString('zh-CN');
const date = t => t ? new Date(t * 1000).toLocaleString('zh-CN', {hour12: false}) : '尚未收到';
let filled = false, busy = false, page = 1, pages = 1, through = null, filters = {kind: 'security'};

async function api(path, body) {
  const response = await fetch('/api/syslog/' + path, {
    signal: AbortSignal.timeout(15000),
    ...(body ? {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)} : {})
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '读取失败，请重试。');
  return data;
}

function notice(text) {
  $('syslog-notice').hidden = !text;
  $('syslog-notice').textContent = text || '';
}

function renderStatus(data) {
  const config = data.settings;
  if (!filled) {
    $('syslog-bind').value = config.bind;
    $('syslog-port').value = config.port;
    $('syslog-sender').value = config.sender;
    $('syslog-enabled').checked = config.enabled;
    $('syslog-autoblock').checked = config.autoBlock;
    $('syslog-setup').open = !data.listening;
    filled = true;
  }
  $('syslog-badge').textContent = data.listening ? `接收中 · UDP ${config.port}` : config.enabled ? '监听失败' : '未启用';
  $('syslog-badge').className = 'status-badge' + (data.listening ? ' success' : '');
  $('syslog-status').textContent = `本地保存 ${number(data.total)} 条 · Web ${number(data.counts.waf)} · IPS ${number(data.counts.ips)} · 未识别 ${number(data.counts.unknown)} · 最后接收 ${date(data.lastReceived)} · 待写入 ${number(data.queueDepth)} · 本次运行拒收 ${number(data.rejected)} / 丢弃 ${number(data.dropped)}`;
  const blocking = data.blocking || {}, counts = blocking.counts || {};
  $('syslog-block-status').textContent = `自动拉黑${config.autoBlock ? '已开启' : '已关闭'} · 仅公网源 IP · 已入 WAF ${number((counts.listed || 0) + (counts.existing || 0) + (counts.inactive || 0))} 个 · 跳过 ${number(counts.protected)} 个 · 待处理 ${number(counts.pending)} 个 · 重试 ${number(counts.failed)} 个 · AF 名单同步${blocking.afSyncEnabled ? '已开启' : '未开启（可在黑名单页开启）'}`;
  $('syslog-target').textContent = `AF 转发目标：${data.address && data.address !== '0.0.0.0' ? data.address : '本机可被 AF 访问的 IPv4 地址'}，UDP 端口 ${config.port}；允许的发送设备：${config.sender || '尚未配置'}。`;
  $('syslog-firewall').textContent = config.sender
    ? `New-NetFirewallRule -DisplayName "LovelyLivelog Syslog UDP ${config.port}" -Direction Inbound -Action Allow -Protocol UDP -LocalPort ${config.port} -RemoteAddress ${config.sender}`
    : '先填写允许发送的 AF IP 并保存。';
  notice(data.error || blocking.error || (data.dropped ? '本次运行发生未保存消息，请检查磁盘、接收队列和日志流量。' : ''));
}

function pagination() {
  $('syslog-prev').disabled = busy || page <= 1;
  $('syslog-next').disabled = busy || page >= pages;
  $('syslog-refresh').disabled = busy;
}

function render(data) {
  page = data.page; pages = data.pages; through = data.through;
  $('syslog-result').textContent = `符合条件 ${number(data.total)} 条 · 按接收时间筛选 · 每页 50 条`;
  $('syslog-page').textContent = `第 ${page} / ${pages} 页`;
  $('syslog-empty').hidden = data.events.length > 0;
  $('syslog-empty').textContent = '当前条件下没有日志。若已收到数据，可切换“全部日志”或“未识别”检查原文。';
  $('syslog-rows').replaceChildren(...data.events.map(item => {
    const row = document.createElement('tr');
    for (const text of [item.occurred ? `${item.occurred}\n收到 ${date(item.received)}` : date(item.received),
      types[item.kind] || item.kind, item.src_ip || '—', item.dst_ip || '—',
      `${item.level || '—'} / ${item.action || '—'}`, item.title || '—']) {
      const cell = document.createElement('td');
      cell.textContent = text; row.append(cell);
    }
    const blockCell = document.createElement('td');
    blockCell.textContent = item.blocking ? (blockStates[item.blocking.state] || item.blocking.state) : '—';
    blockCell.title = item.blocking?.detail || '未触发自动拉黑';
    row.append(blockCell);
    const cell = document.createElement('td'), button = document.createElement('button');
    button.type = 'button'; button.className = 'text-button'; button.textContent = '原文';
    button.addEventListener('click', () => detail(item.id));
    cell.append(button); row.append(cell);
    return row;
  }));
}

async function load(targetPage = page, reset = false) {
  if (busy) return;
  busy = true; pagination();
  try {
    renderStatus(await api('status'));
    render(await api('search', {...filters, page: targetPage, through: reset ? null : through}));
  } catch (error) { notice(error.message); }
  finally { busy = false; pagination(); }
}

async function detail(id) {
  try {
    const data = await api('detail', {id});
    const fields = {'发送设备': data.peer, '收到时间': date(data.received), '解码': data.encoding, ...data.fields};
    $('syslog-detail-fields').replaceChildren(...Object.entries(fields).flatMap(([key, value]) => {
      const term = document.createElement('dt'), desc = document.createElement('dd');
      term.textContent = key; desc.textContent = typeof value === 'object' ? JSON.stringify(value) : String(value);
      return [term, desc];
    }));
    $('syslog-detail-raw').textContent = data.text;
    $('syslog-detail').showModal();
  } catch (error) { notice(error.message); }
}

$('syslog-detail-close').addEventListener('click', () => $('syslog-detail').close());
$('syslog-settings').addEventListener('submit', async event => {
  event.preventDefault();
  if (busy) return;
  busy = true; pagination();
  const button = event.submitter;
  if (button) button.disabled = true;
  try {
    const data = await api('settings', {enabled: $('syslog-enabled').checked, bind: $('syslog-bind').value.trim(),
      port: Number($('syslog-port').value), sender: $('syslog-sender').value.trim(),
      autoBlock: $('syslog-autoblock').checked});
    filled = false; renderStatus(data);
    toast(data.error || '接收设置已保存', data.error ? 'error' : '');
  } catch (error) { notice(error.message); }
  finally { busy = false; if (button) button.disabled = false; pagination(); }
});
$('syslog-search').addEventListener('submit', event => {
  event.preventDefault();
  if (busy) return;
  filters = {kind: $('syslog-kind').value, start: $('syslog-from').value, end: $('syslog-to').value,
    src_ip: $('syslog-src').value.trim(), dst_ip: $('syslog-dst').value.trim(), query: $('syslog-query').value.trim()};
  load(1, true);
});
$('syslog-refresh').addEventListener('click', () => load(1, true));
$('syslog-prev').addEventListener('click', () => load(page - 1));
$('syslog-next').addEventListener('click', () => load(page + 1));
document.addEventListener('view-change', () => { if (isActive('af-logs')) load(page, page === 1); });
if (isActive('af-logs')) load(1, true);
setInterval(() => {
  if (isActive('af-logs') && !document.hidden && $('syslog-auto').checked && page === 1 && !$('syslog-detail').open) load(1, true);
}, 5000);
