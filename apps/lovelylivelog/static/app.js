import {parseLine, summarize, filterRows, displayTime, displayBytes, requestPath, topCounts, distribution} from './log-parser.js';
import {$, toast, copyText} from './ui.js';
import {view, isActive, navigate, PAGES} from './nav.js';

let preferences = {};
try { preferences = JSON.parse(localStorage.getItem('onepanel-log-preferences') || '{}'); } catch { /* Optional preferences. */ }
const state = {
  websites: [], siteId: null, kind: preferences.kind === 'error.log' ? 'error.log' : 'access.log',
  interval: [1, 3, 5, 10, 30].includes(preferences.interval) ? preferences.interval : 3,
  limit: [200, 500, 1000, 2000, 5000].includes(preferences.limit) ? preferences.limit : 500,
  paused: false, latest: true, history: [null], historyIndex: 0, data: null, rows: [], visible: [],
  incremental: preferences.incremental !== false, eventAfter: null, newTotal: 0, more: false,
  failures: 0, busy: false, generation: 0, controller: null, timer: null,
  offscreen: !isActive('logs', 'website'), fresh: null, detailRow: null,
};
let searchTimer = null;
let suppressScroll = false;
let loadingSites = false;

function remember() {
  try { localStorage.setItem('onepanel-log-preferences', JSON.stringify({
    siteId: state.siteId, kind: state.kind, interval: state.interval, limit: state.limit,
    raw: $('raw-view').checked, follow: $('follow').checked,
    incremental: state.incremental, insights: $('insights').open,
  })); } catch { /* The viewer also works without browser storage. */ }
}

async function getJson(url, signal) {
  const controller = new AbortController();
  const relay = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener('abort', relay, {once: true});
  }
  const timeout = setTimeout(() => controller.abort('timeout'), 35000);
  try {
    const response = await fetch(url, {signal: controller.signal, cache: 'no-store'});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '读取失败，请稍后重试。');
    return data;
  } catch (error) {
    if (signal?.aborted) throw error;
    if (controller.signal.reason === 'timeout') throw new Error('本机服务响应超时，请检查程序窗口后重试。');
    if (error instanceof TypeError || error instanceof SyntaxError) throw new Error('无法连接本机日志程序，请确认启动窗口仍在运行。');
    throw error;
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener('abort', relay);
  }
}

function notice(message = '', error = false) {
  $('notice').hidden = !message;
  $('notice').textContent = message;
  $('notice').classList.toggle('error', error);
}

function mode() {
  const connected = state.websites.length > 0;
  $('connection').className = `connection ${state.failures ? 'failed' : connected ? 'connected' : ''}`;
  $('connection-text').textContent = state.failures ? '连接中断' : connected ? '连接正常' : '连接中';
  $('live-label').classList.toggle('inactive', state.paused || !state.latest || !!state.failures);
  $('live-label').lastChild.textContent = state.latest ? state.paused ? ' 已暂停' : ' 实时读取' : ' 历史浏览';
  $('pause').textContent = state.paused ? '▶ 继续' : 'Ⅱ 暂停';
  $('pause').setAttribute('aria-pressed', String(state.paused));
  $('pause').disabled = !state.siteId || !state.latest;
  $('refresh').disabled = !state.siteId;
  $('refresh').setAttribute('aria-busy', String(state.busy));
  $('refresh').title = state.latest ? '立即读取最新日志' : '重新读取当前历史页';
  $('download').disabled = !state.visible.length;
  $('follow').disabled = !state.latest;
  $('older').disabled = state.busy || !!state.failures || !state.data?.hasOlder;
  $('older').hidden = state.latest && state.incremental;
  $('incremental').disabled = !state.latest;
  $('newer').hidden = state.latest;
  $('newer').disabled = state.busy;
  $('back-live').hidden = state.latest;
  $('page-info').textContent = state.latest ? '' : `历史第 ${state.historyIndex} 页`;
  $('window-description').textContent = state.latest ? state.incremental ? `新增跟踪 · 已载入 ${state.newTotal} 条` : `最近 ${state.limit} 条` : `历史第 ${state.historyIndex} 页`;
  document.querySelectorAll('.tab').forEach(tab => {
    const active = tab.dataset.kind === state.kind;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', String(active));
  });
  $('status-filter').disabled = state.kind === 'error.log';
  $('metric-errors-hint').textContent = state.kind === 'error.log' ? 'error / crit / alert / emerg' : '4xx / 5xx';
}

function renderSites() {
  const query = $('site-search').value.toLocaleLowerCase();
  const list = $('site-list');
  list.replaceChildren();
  $('site-count').textContent = state.websites.length;
  const visible = state.websites.filter(site => `${site.name} ${site.alias} ${site.remark}`.toLocaleLowerCase().includes(query));
  for (const site of visible) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `site-button${site.id === state.siteId ? ' selected' : ''}`;
    button.setAttribute('aria-pressed', String(site.id === state.siteId));
    const dot = document.createElement('span');
    dot.className = `site-dot${site.status === 'Running' ? '' : ' stopped'}`;
    const content = document.createElement('span');
    const name = document.createElement('span');
    name.className = 'site-name'; name.textContent = site.name;
    if (site.aiExcluded) {
      const tag = document.createElement('span');
      tag.className = 'site-tag'; tag.textContent = '不识别'; tag.title = '此网站不参与 AI 识别';
      name.append(tag);
    }
    const subtitle = document.createElement('span');
    subtitle.className = 'site-type'; subtitle.textContent = site.remark || (site.status === 'Running' ? '运行中' : '已停止');
    content.append(name, subtitle); button.append(dot, content);
    button.addEventListener('click', () => selectSite(site.id));
    list.append(button);
  }
  if (!visible.length) {
    const empty = document.createElement('div');
    empty.className = 'muted sidebar-empty';
    empty.textContent = state.websites.length ? '没有匹配的网站' : '面板中暂无网站';
    list.append(empty);
  }
}

function header() {
  const site = state.websites.find(site => site.id === state.siteId);
  $('site-title').textContent = site?.name || '暂无网站';
  $('site-subtitle').textContent = site ? site.remark || `网站 #${site.id} · ${site.alias || site.name}` : '在 1Panel 中添加网站后，重新加载网站列表。';
  $('site-state').textContent = site ? site.status === 'Running' ? 'RUNNING' : 'STOPPED' : '';
  $('site-state').classList.toggle('stopped', !!site && site.status !== 'Running');
  $('site-ai-toggle').hidden = !site;
  if (site) {
    $('site-ai-enabled').checked = !site.aiExcluded;
    $('site-ai-label').textContent = site.aiExcluded ? '不参与 AI 识别' : '参与 AI 识别';
    $('site-ai-toggle').classList.toggle('off', !!site.aiExcluded);
  }
}

async function setAiExcluded(site, excluded) {
  const toggle = $('site-ai-enabled');
  toggle.disabled = true;
  try {
    const response = await fetch('/api/websites/ai', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({website: site.id, excluded}), signal: AbortSignal.timeout(15000)});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '设置失败，请重试。');
    site.aiExcluded = data.aiExcluded;
    toast(excluded ? `${site.name} 已取消 AI 识别，日志仍会照常收集` : `${site.name} 已恢复 AI 识别，从新增日志开始分析`);
  } catch (error) {
    toast(error.name === 'TimeoutError' ? '连接超时，请重试。' : error.message, 'error');
  } finally {
    toggle.disabled = false;
    header(); renderSites();
  }
}

function clearSnapshot() {
  state.data = null; state.rows = []; state.visible = []; state.failures = 0;
  state.eventAfter = null; state.newTotal = 0; state.more = false;
  ['metric-total', 'metric-lines', 'metric-errors', 'metric-ips', 'metric-time'].forEach(id => $(id).textContent = '—');
  $('metric-time-hint').textContent = '等待首次读取';
  $('source-path').textContent = '1PANEL API';
  notice(); renderInsights();
}

function detail(row) {
  state.detailRow = row;
  const clean = value => value && value !== '-' ? value : '';
  const fields = [['时间', row.time], ['来源 IP', row.ip],
    [row.status !== null ? '状态' : '级别', row.status !== null ? String(row.status) : row.level],
    ['请求', row.request !== row.raw ? row.request : ''], ['大小', row.bytes !== null ? displayBytes(row.bytes) : ''],
    ['来源页', clean(row.referer)], ['User-Agent', clean(row.userAgent)]].filter(([, value]) => value);
  $('detail-fields').replaceChildren(...fields.flatMap(([label, value]) => {
    const term = document.createElement('dt'), data = document.createElement('dd');
    term.textContent = label; data.textContent = value;
    if (label === '来源 IP') data.dataset.geoIp = value;
    return [term, data];
  }));
  $('detail-content').textContent = row.raw;
  $('detail-filter-ip').hidden = $('detail-copy-ip').hidden = !row.ip;
  $('detail-dialog').showModal();
}

function applySearch(value) {
  $('log-search').value = value;
  renderLogs();
  $('log-scroll').scrollTop = 0;
}

// Fills node with text, wrapping case-insensitive matches of needle in <mark>.
function highlight(node, text, needle) {
  const lower = text.toLocaleLowerCase();
  if (!needle || lower.length !== text.length) { node.textContent = text; return; }
  let index = 0, found;
  while ((found = lower.indexOf(needle, index)) !== -1) {
    if (found > index) node.append(text.slice(index, found));
    const mark = document.createElement('mark');
    mark.textContent = text.slice(found, found + needle.length);
    node.append(mark);
    index = found + needle.length;
  }
  if (index < text.length) node.append(text.slice(index));
}

const accessGroups = [['2', '2xx 成功', 'success'], ['3', '3xx 跳转', 'redirect'], ['4', '4xx 客户端', 'warn'], ['5', '5xx 服务端', 'danger'], ['other', '其他', 'other']];
const errorGroups = [['error', 'error 及以上', 'danger'], ['warn', 'warn', 'warn'], ['info', 'notice / info', 'info'], ['other', '其他', 'other']];

function topList(id, entries, total) {
  const max = entries[0]?.[1] || 1;
  $(id).replaceChildren(...entries.map(([value, count]) => {
    const item = document.createElement('li'), button = document.createElement('button');
    button.type = 'button'; button.title = `筛选：${value}`;
    const fill = document.createElement('span'); fill.className = 'top-fill'; fill.style.width = `${count / max * 100}%`;
    const label = document.createElement('span'); label.className = 'top-label'; label.textContent = value;
    if (id === 'top-ips') label.dataset.geoIp = value;
    const number = document.createElement('span'); number.className = 'top-count';
    number.textContent = `${count.toLocaleString()} · ${Math.round(count / total * 100)}%`;
    button.append(fill, label, number);
    button.addEventListener('click', () => applySearch(value));
    item.append(button); return item;
  }));
  if (!entries.length) {
    const empty = document.createElement('li'); empty.className = 'top-empty'; empty.textContent = '暂无数据';
    $(id).append(empty);
  }
}

function legendKey(index) {
  return (state.kind === 'error.log' ? errorGroups : accessGroups)[index]?.[0];
}

function renderInsights() {
  const rows = state.rows, error = state.kind === 'error.log', total = rows.length || 1;
  $('insights-scope').textContent = rows.length ? `基于当前窗口 ${rows.length.toLocaleString()} 条记录` : '等待日志';
  $('dist-title').textContent = error ? '日志级别分布' : '响应状态分布';
  $('top-paths-title').textContent = error ? '错误信息 Top 5' : '请求路径 Top 5';
  const counts = distribution(rows, state.kind), filter = $('status-filter').value;
  const groups = error ? errorGroups : accessGroups;
  $('dist-bar').replaceChildren(...groups.filter(([key]) => counts[key]).map(([key, , tone]) => {
    const segment = document.createElement('span'); segment.className = `tone-${tone}`;
    segment.style.width = `${counts[key] / total * 100}%`; return segment;
  }));
  $('dist-legend').replaceChildren(...groups.map(([key, label, tone]) => {
    const clickable = !error && key !== 'other';
    const item = document.createElement(clickable ? 'button' : 'div');
    item.className = `dist-item${clickable && filter === key ? ' active' : ''}`;
    const swatch = document.createElement('i'); swatch.className = `tone-${tone}`;
    const name = document.createElement('span'); name.textContent = label;
    const count = document.createElement('b'); count.textContent = counts[key].toLocaleString();
    const share = document.createElement('small'); share.textContent = rows.length ? `${Math.round(counts[key] / total * 100)}%` : '—';
    item.append(swatch, name, count, share);
    if (clickable) {
      item.type = 'button'; item.title = `只看 ${label}，再次点击取消`;
      item.addEventListener('click', () => { $('status-filter').value = $('status-filter').value === key ? 'all' : key; renderLogs(); });
    }
    return item;
  }));
  topList('top-ips', topCounts(rows.map(row => row.ip)), total);
  // Nginx prefixes errors with "pid#tid: *conn"; drop it and the client tail so repeats group together.
  const message = row => row.request.replace(/^\d+#\d+:\s*(\*\d+\s*)?/, '').replace(/,\s*client:.*$/, '').slice(0, 120);
  topList('top-paths', topCounts(rows.map(row => error ? message(row) : requestPath(row.request))), total);
}

function badge(row) {
  const span = document.createElement('span');
  span.className = 'status-badge';
  if (row.status !== null) {
    span.textContent = row.status;
    span.classList.add(row.status >= 500 ? 'server-error' : row.status >= 400 ? 'client-error' : row.status >= 300 ? 'redirect' : 'success');
  } else if (row.level) {
    span.textContent = row.level;
    if (/^(error|crit|alert|emerg)$/i.test(row.level)) span.classList.add('level-error');
    else if (/^warn$/i.test(row.level)) span.classList.add('level-warn');
  } else span.textContent = '—';
  return span;
}

function renderLogs() {
  const scroll = $('log-scroll');
  const previousTop = scroll.scrollTop;
  suppressScroll = true;
  const needle = $('log-search').value.trim().toLocaleLowerCase();
  state.visible = filterRows(state.rows, needle, $('status-filter').value);
  document.querySelectorAll('#dist-legend .dist-item').forEach((item, index) =>
    item.classList.toggle('active', item.tagName === 'BUTTON' && legendKey(index) === $('status-filter').value));
  $('visible-count').textContent = state.data ? `显示 ${state.visible.length} / ${state.rows.length} 条` : '等待日志';
  const raw = $('raw-view').checked;
  $('log-table').hidden = raw || !state.visible.length;
  $('raw-lines').hidden = !raw || !state.visible.length;
  $('empty').hidden = !!state.visible.length;
  $('retry').hidden = !state.failures;
  if (!state.visible.length) {
    let title = '正在读取日志', description = '连接成功后，最新记录会显示在这里。';
    if (!state.siteId) { title = '暂无网站'; description = '重新加载网站列表以继续。'; }
    else if (state.failures && !state.data) { title = '暂时无法读取'; description = '检查上方的提示；程序会自动重试。'; }
    else if (state.data?.enabled === false) { title = '此日志尚未启用'; description = '请在 1Panel 的网站设置中启用相应日志，随后刷新。'; }
    else if (state.rows.length) { title = '没有匹配的日志'; description = '尝试更换关键词或响应状态。搜索仅针对当前读取窗口。'; }
    else if (state.data) { title = state.latest && state.incremental ? '等待新增日志' : '暂无日志记录'; description = state.latest && state.incremental ? '已建立读取位置，只显示之后新增的记录。取消“仅跟踪新增”可查看现有日志。' : state.latest ? '正在等待新的记录，程序会按设定间隔刷新。' : '此历史页没有记录，可以返回实时查看。'; }
    $('empty-title').textContent = title; $('empty-description').textContent = description;
  }
  const table = document.createDocumentFragment(), lines = document.createDocumentFragment();
  const fresh = state.fresh; state.fresh = null;
  state.visible.forEach((row, index) => {
    const isFresh = fresh?.has(row.eventId);
    if (raw) {
      const line = document.createElement('div'); line.className = `raw-line${isFresh ? ' fresh' : ''}`;
      const number = document.createElement('span'); number.textContent = index + 1;
      const text = document.createElement('span'); highlight(text, row.raw, needle);
      line.append(number, text); line.addEventListener('click', () => detail(row)); lines.append(line);
    } else {
      const tr = document.createElement('tr'); tr.title = '点击查看日志详情';
      if (isFresh) tr.className = 'fresh';
      const cells = [[index + 1, 'line-number'], [displayTime(row.time), 'log-time'], [row.ip || '—', 'log-ip'],
        [row.request, 'log-request'], ['', 'log-status'], [displayBytes(row.bytes), 'log-bytes']];
      for (const [text, className] of cells) {
        const td = document.createElement('td'); td.className = className;
        if (className === 'log-status') td.append(badge(row));
        else if (className === 'log-request') { highlight(td, text, needle); td.title = row.request; }
        else if (className === 'log-ip' && row.ip) {
          const button = document.createElement('button'); button.type = 'button'; button.className = 'ip-link';
          button.title = `只看 ${row.ip}`; highlight(button, row.ip, needle);
          button.addEventListener('click', event => { event.stopPropagation(); applySearch(row.ip); });
          td.append(button); td.dataset.geoIp = row.ip;
        } else td.textContent = String(text);
        tr.append(td);
      }
      tr.tabIndex = 0;
      tr.addEventListener('click', () => detail(row));
      tr.addEventListener('keydown', event => { if (event.key === 'Enter' && event.target === tr) detail(row); });
      table.append(tr);
    }
  });
  $('log-rows').replaceChildren(table); $('raw-lines').replaceChildren(lines);
  scroll.scrollTop = $('follow').checked && state.latest ? scroll.scrollHeight : previousTop;
  requestAnimationFrame(() => { suppressScroll = false; });
  mode();
}

function cancelPolling() {
  clearTimeout(state.timer); state.timer = null;
  state.controller?.abort(); state.controller = null;
  state.generation++;
}

function schedule() {
  clearTimeout(state.timer);
  if (!state.siteId || !state.latest || state.paused || document.hidden || state.offscreen) return;
  const seconds = Math.min(30, state.interval * 2 ** Math.min(state.failures, 4));
  state.timer = setTimeout(requestLogs, state.more ? 0 : seconds * 1000);
}

async function requestLogs() {
  if (!state.siteId) return;
  cancelPolling();
  const generation = state.generation;
  const controller = new AbortController(); state.controller = controller;
  state.busy = true; mode();
  const params = new URLSearchParams({id: state.siteId, type: state.kind, limit: state.limit, latest: state.latest});
  if (!state.latest) params.set('before', state.history[state.historyIndex]);
  const incremental = state.latest && state.incremental;
  if (incremental && state.eventAfter !== null) params.set('after', state.eventAfter);
  try {
    let data = await getJson(`${incremental ? '/api/events' : '/api/logs'}?${params}`, controller.signal);
    if (generation !== state.generation) return;
    let feedNotice = '';
    if (incremental) {
      if (data.error || data.status.error) throw new Error(data.error || data.status.error);
      const rows = data.events.map(event => ({...parseLine(event.raw), eventId: event.id}));
      // Flash rows that arrive after the first load; skip large catch-up batches.
      state.fresh = state.eventAfter !== null && rows.length && rows.length <= 200 ? new Set(rows.map(row => row.eventId)) : null;
      state.rows = (state.eventAfter === null ? rows : [...state.rows, ...rows]).slice(-state.limit);
      state.eventAfter = data.after; state.newTotal += rows.length; state.more = data.hasMore;
      if (data.retentionGap) feedNotice = '本机较早的记录已超过保留上限，完整日志可在 1Panel 中查看。';
      else if (data.status.rotated) feedNotice = '检测到日志轮转，已从新文件继续跟踪。';
      else if (data.status.backlog) feedNotice = '正在追赶新增日志，未读部分会继续补读。';
      data = {...data, lines: state.rows.map(row => row.raw), enabled: data.status.enabled !== false,
              path: data.status.path || '', hasOlder: false};
    } else {
      state.rows = data.lines.map(parseLine); state.more = false;
    }
    state.data = data; state.failures = 0;
    const stats = summarize(state.rows, state.kind);
    // Everything collected for this website and log type, not just the window loaded below.
    if (typeof data.total === 'number') $('metric-total').textContent = data.total.toLocaleString();
    $('metric-lines').textContent = stats.lines.toLocaleString();
    $('metric-errors').textContent = stats.errors.toLocaleString();
    $('metric-ips').textContent = stats.ips.toLocaleString();
    $('metric-time').textContent = new Date(data.fetchedAt * 1000).toLocaleTimeString('zh-CN', {hour12: false});
    $('metric-time-hint').textContent = state.latest ? state.paused ? '读取已暂停' : `每 ${state.interval} 秒刷新` : '历史页 · 自动刷新已暂停';
    $('source-path').textContent = data.path || '1PANEL API'; $('source-path').title = data.path || '日志来源';
    notice(data.enabled ? feedNotice : '该网站的日志处于关闭状态，请在 1Panel 中启用后再刷新。');
    renderInsights();
    renderLogs();
  } catch (error) {
    if (generation !== state.generation || controller.signal.aborted) return;
    state.failures++;
    notice(error.message, true);
    $('metric-time-hint').textContent = state.data ? '旧数据 · 连接恢复后更新' : '等待重新连接';
    renderLogs();
  } finally {
    if (generation === state.generation) {
      state.busy = false; state.controller = null; mode(); schedule();
    }
  }
}

function selectSite(id) {
  if (id === state.siteId) return;
  cancelPolling(); state.busy = false; state.siteId = id; state.latest = true; state.history = [null]; state.historyIndex = 0;
  clearSnapshot(); remember(); renderSites(); header(); renderLogs(); requestLogs();
}

async function loadSites() {
  if (loadingSites) return;
  loadingSites = true; $('reload-sites').disabled = true;
  try {
    const data = await getJson('/api/websites');
    state.websites = data.websites;
    const current = state.websites.find(site => site.id === state.siteId);
    renderSites();
    if (!current) {
      const preferred = state.websites.find(site => site.id === preferences.siteId);
      const id = (preferred || state.websites[0])?.id || null;
      if (id) selectSite(id);
      else { cancelPolling(); state.siteId = null; state.busy = false; clearSnapshot(); header(); renderLogs(); }
    } else { header(); if (state.failures) requestLogs(); }
    mode();
  } catch (error) {
    state.failures++;
    notice(error.message, true);
    if (!state.websites.length) {
      $('site-title').textContent = '无法读取网站列表';
      $('site-subtitle').textContent = '检查连接提示后，点击重新连接。';
      $('site-list').replaceChildren();
    }
    renderLogs();
    clearTimeout(state.timer);
    if (!state.siteId && !document.hidden) state.timer = setTimeout(loadSites, 10000);
  } finally { loadingSites = false; $('reload-sites').disabled = false; }
}

function older() {
  if (!state.data?.hasOlder) return;
  state.history = state.history.slice(0, state.historyIndex + 1);
  state.history.push(state.data.before); state.historyIndex++;
  state.latest = false; requestLogs();
}

function backLive() {
  state.latest = true; state.history = [null]; state.historyIndex = 0; state.paused = false;
  requestLogs();
}

$('interval').value = state.interval; $('limit').value = state.limit;
$('raw-view').checked = !!preferences.raw; $('follow').checked = preferences.follow !== false;
$('incremental').checked = state.incremental;
$('insights').open = preferences.insights !== false;
$('site-search').addEventListener('input', renderSites);
$('site-ai-enabled').addEventListener('change', () => {
  const site = state.websites.find(item => item.id === state.siteId);
  if (site) setAiExcluded(site, !$('site-ai-enabled').checked);
});
$('reload-sites').addEventListener('click', loadSites);
$('log-search').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(renderLogs, 120); });
$('log-search').addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  if ($('log-search').value) { event.preventDefault(); applySearch(''); }
  else $('log-search').blur();
});
$('status-filter').addEventListener('change', renderLogs);
$('insights').addEventListener('toggle', remember);
$('raw-view').addEventListener('change', () => { remember(); renderLogs(); });
$('incremental').addEventListener('change', () => {
  cancelPolling(); state.busy = false; state.incremental = $('incremental').checked;
  clearSnapshot(); remember(); renderLogs(); requestLogs();
});
$('follow').addEventListener('change', () => { remember(); if ($('follow').checked) $('log-scroll').scrollTop = $('log-scroll').scrollHeight; });
$('log-scroll').addEventListener('scroll', () => {
  const scroll = $('log-scroll');
  if (!suppressScroll && $('follow').checked && state.latest && scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight > 80) {
    $('follow').checked = false; remember();
  }
});
document.querySelectorAll('.tab').forEach(tab => tab.addEventListener('click', () => {
  if (state.kind === tab.dataset.kind) return;
  cancelPolling(); state.busy = false; state.kind = tab.dataset.kind; state.latest = true; state.history = [null]; state.historyIndex = 0;
  $('status-filter').value = 'all'; clearSnapshot(); remember(); renderLogs(); requestLogs();
}));
$('interval').addEventListener('change', () => {
  state.interval = Number($('interval').value); remember(); schedule();
  if (state.data && !state.failures && state.latest && !state.paused) $('metric-time-hint').textContent = `每 ${state.interval} 秒刷新`;
});
$('limit').addEventListener('change', () => {
  cancelPolling(); state.busy = false; state.limit = Number($('limit').value); state.latest = true; state.history = [null]; state.historyIndex = 0;
  clearSnapshot(); remember(); renderLogs(); requestLogs();
});
$('pause').addEventListener('click', () => {
  state.paused = !state.paused; cancelPolling(); state.busy = false; mode();
  if (state.paused) $('metric-time-hint').textContent = state.failures ? '旧数据 · 读取已暂停' : '读取已暂停';
  else requestLogs();
});
$('refresh').addEventListener('click', requestLogs);
$('retry').addEventListener('click', () => state.siteId ? requestLogs() : loadSites());
$('older').addEventListener('click', older);
$('newer').addEventListener('click', () => {
  if (state.historyIndex <= 1) backLive();
  else { state.historyIndex--; requestLogs(); }
});
$('back-live').addEventListener('click', backLive);
$('download').addEventListener('click', () => {
  if (!state.visible.length) return;
  const site = state.websites.find(site => site.id === state.siteId);
  const name = (site?.name || 'website').replace(/[^\p{L}\p{N}._-]/gu, '_');
  const blob = new Blob([state.visible.map(row => row.raw).join('\n') + '\n'], {type: 'text/plain;charset=utf-8'});
  const url = URL.createObjectURL(blob), link = document.createElement('a');
  link.href = url; link.download = `${name}_${state.kind.replace('.log', '')}_${Date.now()}.log`;
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$('close-detail').addEventListener('click', () => $('detail-dialog').close());
$('copy-detail').addEventListener('click', () => copyText($('detail-content').textContent, '日志已复制'));
$('detail-copy-ip').addEventListener('click', () => copyText(state.detailRow?.ip || '', `已复制 ${state.detailRow?.ip || ''}`));
$('detail-filter-ip').addEventListener('click', () => {
  $('detail-dialog').close();
  if (state.detailRow?.ip) applySearch(state.detailRow.ip);
});
$('open-shortcuts').addEventListener('click', () => $('shortcuts-dialog').showModal());
$('close-shortcuts').addEventListener('click', () => $('shortcuts-dialog').close());
const themeNames = {system: '跟随系统', light: '浅色', dark: '深色'};
document.addEventListener('keydown', event => {
  if (event.ctrlKey || event.metaKey || event.altKey || event.isComposing) return;
  if (/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) || document.querySelector('dialog[open]')) return;
  const website = view.scope === 'website';
  // Refresh button for whichever panel is on screen.
  const refreshTargets = {logs: website ? 'refresh' : 'hub-refresh', ai: website ? 'ai-history-refresh' : 'hub-ai-refresh', blacklist: 'blacklist-refresh'};
  const actions = {
    '/': () => { if (view.page !== 'logs') navigate('logs'); (website ? $('log-search') : $('hub-search')).focus(); },
    '?': () => $('shortcuts-dialog').showModal(),
    t: () => toast(`配色：${themeNames[window.onepanelTheme?.cycle()] || '跟随系统'}`),
    r: () => { const button = $(refreshTargets[view.page] || ''); if (button && !button.disabled) button.click(); },
    p: () => {
      if (!isActive('logs', 'website') || $('pause').disabled) return;
      $('pause').click(); toast(state.paused ? '已暂停实时读取' : '已继续实时读取');
    },
  };
  Object.keys(PAGES).forEach((page, index) => { actions[String(index + 1)] = () => navigate(page); });
  const action = actions[event.key.toLowerCase()];
  if (action) { event.preventDefault(); action(); }
});
// Website log polling runs only while its page is on screen and resumes on return.
document.addEventListener('view-change', () => {
  const offscreen = !isActive('logs', 'website');
  if (offscreen === state.offscreen) return;
  state.offscreen = offscreen;
  if (offscreen) { cancelPolling(); state.busy = false; mode(); }
  else if (state.siteId && state.latest && !state.paused) requestLogs();
});
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { clearTimeout(state.timer); state.timer = null; }
  else if (state.offscreen) return;
  else if (state.siteId && state.latest && !state.paused) requestLogs();
  else if (!state.siteId && !loadingSites) loadSites();
});
window.addEventListener('beforeunload', cancelPolling);

mode();
getJson('/api/config').then(config => {
  try { $('panel-host').textContent = new URL(config.panelUrl).host; } catch { $('panel-host').textContent = config.panelUrl; }
}).catch(() => { $('panel-host').textContent = '本机连接'; });
loadSites();
