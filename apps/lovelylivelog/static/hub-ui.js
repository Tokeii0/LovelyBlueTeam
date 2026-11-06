import {formatLogTime, parseLine} from './log-parser.js';
import {view, isActive, selectSource} from './nav.js';

const $ = id => document.getElementById(id);
const state = {feedActive: false, agents: [], receiver: {}, page: 1, pages: 1, through: null,
  generation: 0, loading: false, timer: null, searchTimer: null, controller: null};
const number = value => Number(value || 0).toLocaleString('zh-CN');
const date = seconds => seconds ? new Date(seconds * 1000).toLocaleString('zh-CN', {hour12: false}) : '等待连接';
function element(tag, text, className = '') {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}
function notice(message = '') {
  $('hub-notice').textContent = message;
  $('hub-notice').hidden = !message;
}
async function response(url, options = {}) {
  const result = await fetch(url, {...options, signal: options.signal || AbortSignal.timeout(15000)});
  if (!result.ok) {
    let body = {};
    try {body = await result.json();} catch { /* Show a readable connection error. */ }
    throw new Error(body.error || '连接失败，请检查平台是否正在运行。');
  }
  return result;
}
function renderOverview(data) {
  state.agents = data.agents;
  state.receiver = data.receiver;
  document.dispatchEvent(new CustomEvent('hub-overview', {detail: data}));
  $('server-tab-count').textContent = number(data.agents.length);
  $('hub-servers').textContent = number(data.agents.length);
  $('hub-online').textContent = number(data.online);
  $('hub-total').textContent = number(data.total);
  $('hub-queued').textContent = number(data.agents.reduce((n, a) => n + Number(a.metadata.queueDepth || 0), 0));
  $('hub-receiver').textContent = data.receiver.ready
    ? `接收端已启动：${data.receiver.url} · 首次接入请确认服务器能够访问此地址和端口。`
    : data.receiver.error || '代理接收端尚未启动。';
  $('hub-receiver').classList.toggle('ready', data.receiver.ready);
  $('add-agent').disabled = !data.receiver.ready || !data.receiver.packageReady;
  if (data.receiver.ready && !data.receiver.packageReady) $('hub-receiver').textContent += ' · Windows 代理正在打包。';
  const signature = JSON.stringify(data.agents.map(a => [a.id, a.name]));
  if ($('hub-agent-filter').dataset.signature !== signature) {
    const all = element('option', '全部服务器'); all.value = '';
    $('hub-agent-filter').replaceChildren(all, ...data.agents.map(a => {
      const option = element('option', a.name); option.value = a.id; return option;
    }));
    $('hub-agent-filter').value = data.agents.some(a => a.id === view.agent) ? view.agent : '';
    $('hub-agent-filter').dataset.signature = signature;
  }
  $('hub-agents').replaceChildren(...data.agents.map(a => {
    const card = element('article', '', 'hub-agent-card');
    const heading = element('div', '', 'hub-agent-heading');
    const label = {online: '在线', waiting: '待接入', offline: '离线', disabled: '已停用'}[a.status];
    heading.append(element('strong', a.name), element('span', label, `status-badge ${a.status === 'online' ? 'success' : ''}`));
    const info = element('div', `${a.metadata.hostname || '等待代理首次上传'} · ${number(a.count)} 条日志`, 'hub-agent-info');
    const checked = element('div', `最后心跳：${date(a.last_seen)}`, 'muted');
    const ai = element('div', `AI 已分析 ${number(a.ai?.analyzed)} 条 · 待分析 ${number(a.ai?.pending)} 条 · 攻击判断 ${number(a.ai?.attacks)}`, 'muted');
    const sources = element('div', '', 'hub-source-status');
    for (const source of a.metadata.sources || []) {
      if (!source || typeof source !== 'object') continue;
      let status = {ok: '采集中', missing: '文件不存在', error: '读取失败'}[source.status] || '等待';
      if (source.mode === 'daily') {
        status = {ok: `按日期 · ${source.day} 已清洗 ${number(source.rows)} 行（AI ${number(source.aiRows)} 行）`,
          waiting: `按日期 · 等待清洗 ${source.day}`, missing: `按日期 · ${source.day} 文件尚未生成`,
          cleaning: `按日期 · 正在清洗 ${source.day} · ${source.percent ?? 0}%`,
          error: '按日期 · 读取失败'}[source.status] || status;
      }
      sources.append(element('div', `${status} · ${source.path || ''}`, ['ok', 'waiting', 'cleaning'].includes(source.status) ? '' : 'source-warning'));
    }
    const actions = element('div', '', 'hub-agent-actions');
    const filter = element('button', '查看日志', 'text-button accent');
    filter.addEventListener('click', () => selectSource('server', a.id));
    const toggle = element('button', a.enabled ? '停用接入' : '恢复接入', 'text-button');
    toggle.addEventListener('click', async () => {
      toggle.disabled = true;
      try {
        await response('/api/agents/state', {method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({agentId: a.id, enabled: !a.enabled})});
        await refresh();
      } catch (e) { notice(e.message); toggle.disabled = false; }
    });
    actions.append(filter, toggle);
    card.append(heading, info, checked, ai, sources);
    if (a.metadata.lastError) card.append(element('div', a.metadata.lastError, 'source-warning'));
    card.append(actions); return card;
  }));
}
// The time written in the log line itself; collection time only when the line has none.
function logTime(parsed, event) {
  const first = formatLogTime(parsed.time);
  if (!first) return {text: date(event.collected), title: `日志中没有时间，显示采集时间\n采集时间：${date(event.collected)}`};
  const last = parsed.count > 1 && parsed.lastTime ? formatLogTime(parsed.lastTime) : '';
  return {text: first, title: `日志时间：${first}${last && last !== first ? ` ~ ${last}（${number(parsed.count)} 次）` : ''}\n采集时间：${date(event.collected)}`};
}
function showDetail(event) {
  const time = logTime(parseLine(event.raw), event);
  $('hub-detail-content').textContent = `服务器：${event.server_name}\n${time.title}\n平台接收：${date(event.received)}\n来源文件：${event.source}\n类型：${event.kind}\n\n${event.raw}`;
  $('hub-detail-dialog').showModal();
}
function renderFeed(data) {
  state.page = data.page; state.pages = data.pages; state.through = data.through;
  $('hub-page').textContent = `第 ${number(data.page)} / ${number(data.pages)} 页`;
  $('hub-page-description').textContent = `共 ${number(data.total)} 条 · 每页 100 条 · 点击记录查看原文`;
  $('hub-prev').disabled = data.page <= 1; $('hub-next').disabled = data.page >= data.pages;
  $('hub-empty').hidden = Boolean(data.events.length);
  const title = $('hub-empty').querySelector('strong');
  title.textContent = state.agents.length ? '当前条件没有日志' : '还没有服务器日志';
  $('hub-rows').replaceChildren(...data.events.map(event => {
    const parsed = parseLine(event.raw);
    const row = element('tr', ''); row.tabIndex = 0;
    const time = logTime(parsed, event);
    const timeCell = element('td', time.text, 'log-time'); timeCell.title = time.title;
    row.append(timeCell, element('td', event.server_name),
      element('td', parsed.ip || '—', 'log-ip'), element('td', (parsed.request || parsed.message || event.raw) + (parsed.count > 1 ? ` ×${number(parsed.count)}` : ''), 'log-request'),
      element('td', parsed.status || parsed.level || '—'), element('td', event.kind),
      element('td', {pending:'待分析',analyzed:'已分析',unparsed:'无法识别 IP / 请求',expired:'过期',ignored:'应用日志 · 保留原文',filtered:'清洗后仅存档'}[event.ai_state] || event.ai_state || '—'));
    if (parsed.ip) row.children[2].dataset.geoIp = parsed.ip;
    row.title = '查看完整日志';
    row.addEventListener('click', () => showDetail(event));
    row.addEventListener('keydown', e => {if (e.key === 'Enter') showDetail(event);});
    return row;
  }));
}
async function loadFeed() {
  const generation = state.generation;
  state.controller?.abort();
  const controller = new AbortController(); state.controller = controller;
  const timeout = setTimeout(() => controller.abort(), 15000);
  const params = new URLSearchParams({agent: $('hub-agent-filter').value, type: $('hub-kind').value,
    q: $('hub-search').value, page: String(state.page)});
  if (state.page > 1 && state.through !== null) params.set('through', String(state.through));
  try {
    const data = await (await response(`/api/agents/logs?${params}`, {signal: controller.signal})).json();
    if (generation === state.generation) { renderFeed(data); notice(); }
  } catch (e) {if (generation === state.generation && !controller.signal.aborted) notice(e.message);}
  finally {clearTimeout(timeout);}
}
async function refresh() {
  if (state.loading) return;
  state.loading = true; clearTimeout(state.timer);
  try {
    renderOverview(await (await response('/api/agents')).json());
    if (state.feedActive && (state.through === null || (state.page === 1 && $('hub-auto-refresh').checked))) await loadFeed();
  } catch (e) {notice(e.message);}
  finally {
    state.loading = false;
    // The sidebar server list always needs the overview; poll faster while server pages are open.
    const busy = view.scope === 'server' || view.page === 'agents';
    if (!document.hidden) state.timer = setTimeout(refresh, busy ? 3000 : 15000);
  }
}
function latest() {
  state.generation++; state.page = 1; state.through = null; loadFeed();
}
$('hub-refresh').addEventListener('click', latest);
$('hub-kind').addEventListener('change', latest);
document.addEventListener('view-change', () => {
  const wasActive = state.feedActive, changed = $('hub-agent-filter').value !== view.agent;
  state.feedActive = isActive('logs', 'server');
  if (changed) $('hub-agent-filter').value = view.agent;
  if (state.feedActive && (changed || !wasActive)) latest();
  clearTimeout(state.timer); refresh();
});
$('hub-search').addEventListener('input', () => {clearTimeout(state.searchTimer); state.searchTimer = setTimeout(latest, 250);});
for (const [id, direction] of [['hub-prev', -1], ['hub-next', 1]]) $(id).addEventListener('click', () => {
  state.generation++; state.page = Math.min(state.pages, Math.max(1, state.page + direction)); loadFeed();
});
$('hub-auto-refresh').addEventListener('change', () => {if ($('hub-auto-refresh').checked) latest();});
$('add-agent').addEventListener('click', () => {
  $('agent-url').value = state.receiver.url || '';
  $('agent-form-error').hidden = true; $('agent-dialog').showModal();
});
$('close-agent-dialog').addEventListener('click', () => $('agent-dialog').close());
$('close-hub-detail').addEventListener('click', () => $('hub-detail-dialog').close());
$('agent-template').addEventListener('change', () => {
  const tomcat = $('agent-template').value === 'tomcat';
  $('agent-access').value = tomcat ? 'D:/ezwebapp/logs/localhost_access_log.*.txt' : 'C:/nginx/logs/access.log';
  $('agent-error').value = tomcat ? 'D:/ezwebapp/logs/catalina.*.log' : 'C:/nginx/logs/error.log';
  $('agent-custom').value = tomcat ? 'D:/ezwebapp/logs/localhost.*.log' : '';
});
$('agent-access-mode').addEventListener('change', () => {
  const daily = $('agent-access-mode').value === 'daily';
  const path = $('agent-access').value.trim();
  if (daily && path && !path.includes('{date}')) $('agent-access').value = path.replace(/(\.[^./\\]+)?$/, '_{date}$1');
  if (!daily) $('agent-access').value = path.replace(/_?\{date\}/, '');
  $('agent-access-daily-hint').hidden = !daily;
});
$('agent-form').addEventListener('submit', async event => {
  event.preventDefault(); $('download-agent').disabled = true; $('agent-form-error').hidden = true;
  try {
    const sources = [['agent-access', 'access.log'], ['agent-error', 'error.log'], ['agent-custom', 'custom.log']]
      .map(([id, kind]) => ({kind, path: $(id).value.trim()})).filter(s => s.path);
    const access = sources.find(s => s.kind === 'access.log');
    if (access && $('agent-access-mode').value === 'daily') Object.assign(access, {mode: 'daily', daysAgo: 1});
    if (!sources.length) throw new Error('至少填写一条真实日志路径。');
    const result = await response('/api/agents/register', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name: $('agent-name').value.trim(), platformUrl: $('agent-url').value.trim(),
        sources, initialLines: Number($('agent-initial').value)})});
    const url = URL.createObjectURL(await result.blob());
    const link = document.createElement('a'); link.href = url; link.download = 'Windows-Nginx-Agent.zip';
    document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 10000);
    $('agent-dialog').close(); $('agent-name').value = ''; await refresh();
  } catch (e) { $('agent-form-error').textContent = e.message; $('agent-form-error').hidden = false; }
  finally {$('download-agent').disabled = false;}
});
document.addEventListener('visibilitychange', () => {
  clearTimeout(state.timer); if (!document.hidden) refresh();
});
state.feedActive = isActive('logs', 'server');
refresh();
