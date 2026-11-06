// 深度分析 page: start an IP analysis, then keep asking about it in a chat.
import {isActive} from './nav.js';
import {$, toast} from './ui.js';

const date = seconds => seconds ? new Date(seconds * 1000).toLocaleString('zh-CN', {hour12: false}) : '';
const number = value => Number(value || 0).toLocaleString('zh-CN');
const BLOCK_STATES = {listed: '已拉黑', existing: '已拉黑', inactive: '已加入 · WAF 未就绪', unblocked: '已移除'};
let sessions = [], current = null, waiting = false;

async function call(path, body, timeout = 20000) {
  const response = await fetch(path, {signal: AbortSignal.timeout(timeout),
    ...(body ? {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)} : {})});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '操作失败。');
  return data;
}

function notice(message) {
  $('deep-notice').hidden = !message;
  $('deep-notice').textContent = message || '';
}

const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

// Minimal Markdown for model answers, built as DOM nodes: model text is never parsed as HTML.
function inline(text) {
  const fragment = document.createDocumentFragment();
  for (const part of text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g)) {
    if (!part) continue;
    if (part.startsWith('**') && part.endsWith('**')) fragment.append(el('strong', '', part.slice(2, -2)));
    else if (part.startsWith('`') && part.endsWith('`')) fragment.append(el('code', '', part.slice(1, -1)));
    else fragment.append(part);
  }
  return fragment;
}

function markdown(text) {
  const root = el('div', 'deep-md');
  const lines = text.replace(/\r/g, '').split('\n');
  let list = null, table = null;
  const close = () => { list = null; table = null; };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('```')) {
      close();
      const code = [];
      while (++i < lines.length && !lines[i].startsWith('```')) code.push(lines[i]);
      root.append(el('pre', '', code.join('\n')));
      continue;
    }
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    const bullet = line.match(/^\s*[-*•]\s+(.*)$/);
    const ordered = line.match(/^\s*(\d+)[.)]\s+(.*)$/);
    if (/^\s*\|.*\|\s*$/.test(line)) {
      const cells = line.trim().slice(1, -1).split('|').map(c => c.trim());
      if (cells.every(c => /^:?-{2,}:?$/.test(c))) continue;  // header separator row
      if (!table) { list = null; table = el('table', 'deep-table'); root.append(el('div', 'deep-table-wrap')); root.lastChild.append(table); }
      const row = el('tr');
      cells.forEach(c => { const cell = el(table.rows.length ? 'td' : 'th'); cell.append(inline(c)); row.append(cell); });
      table.append(row);
    } else if (heading) {
      close();
      const node = el(`h${Math.min(4, heading[1].length + 2)}`); node.append(inline(heading[2])); root.append(node);
    } else if (bullet || ordered) {
      table = null;
      const tag = bullet ? 'ul' : 'ol';
      if (!list || list.tagName.toLowerCase() !== tag) { list = el(tag); root.append(list); }
      const item = el('li'); item.append(inline((bullet || ordered).at(-1))); list.append(item);
    } else if (!line.trim()) {
      close();
    } else {
      close();
      const paragraph = el('p'); paragraph.append(inline(line)); root.append(paragraph);
    }
  }
  return root;
}

function bubble(role, content, at) {
  const wrap = el('div', `deep-msg ${role}`);
  const body = el('div', 'deep-bubble');
  if (role === 'assistant') body.append(markdown(content)); else body.textContent = content;
  wrap.append(body);
  if (at) wrap.append(el('div', 'deep-time', date(at)));
  return wrap;
}

function pending(text) {
  const wrap = el('div', 'deep-msg assistant pending');
  const body = el('div', 'deep-bubble');
  body.append(el('span', 'deep-dots'), document.createTextNode(text));
  wrap.append(body);
  return wrap;
}

function renderList() {
  $('deep-list').replaceChildren(...(sessions.length ? sessions.map(item => {
    const button = el('button', `deep-list-item${current && current.id === item.id ? ' selected' : ''}`);
    button.type = 'button';
    const ip = el('strong', '', item.ip); ip.dataset.geoIp = item.ip;
    button.append(ip, el('span', 'muted', `${number(item.requests)} 条 · ${date(item.updated)}`));
    button.addEventListener('click', () => open(item.id));
    return button;
  }) : [el('div', 'muted deep-list-empty', '还没有深度分析记录。')]));
}

function facts(summary) {
  const chips = [`${number(summary.requests)} 条请求`, `${summary.firstSeen || '—'} 至 ${summary.lastSeen || '—'}`,
    `${number(summary.distinctPaths)} 个路径`, `可疑 ${number(summary.suspicious)}`, `AI 判定攻击 ${number(summary.aiAttacks)} 次`,
    ...Object.entries(summary.statusClasses || {}).map(([k, v]) => `${k} ${number(v)}`),
    ...Object.keys(summary.sources || {}).slice(0, 3)];
  const blocked = Object.values(summary.blockState || {}).find(s => s in BLOCK_STATES);
  if (blocked) chips.unshift(BLOCK_STATES[blocked]);
  chips.push(...(summary.protection || []));
  return chips.map(text => el('span', 'deep-chip', text));
}

function renderSession() {
  const messages = $('deep-messages');
  if (!current) {
    $('deep-head').hidden = true; $('deep-ask-form').hidden = true;
    messages.replaceChildren(el('div', 'deep-empty', '在左侧输入 IP 开始深度分析。平台会汇总该 IP 在本地保存的全部访问日志、错误日志、历史 AI 判断和封禁状态，再交给 AI 综合分析；之后可以像聊天一样继续追问。'));
    return;
  }
  $('deep-head').hidden = false; $('deep-ask-form').hidden = false;
  const title = el('span', '', current.ip); title.dataset.geoIp = current.ip;
  $('deep-title').replaceChildren(title);
  $('deep-facts').replaceChildren(...facts(current.summary));
  messages.replaceChildren(el('div', 'deep-snapshot muted', `日志摘要截至 ${date(current.created)}；之后的新日志需要重新分析该 IP。`),
    ...current.messages.map(m => bubble(m.role, m.content, m.at)));
  messages.scrollTop = messages.scrollHeight;
}

async function loadList() {
  try { sessions = (await call('/api/deep')).sessions; renderList(); } catch (error) { notice(error.message); }
}

async function open(id) {
  if (waiting) return;
  try { current = await call('/api/deep/session?id=' + id); notice(''); renderSession(); renderList(); }
  catch (error) { notice(error.message); }
}

function busy(state) {
  waiting = state;
  for (const id of ['deep-start', 'deep-send', 'deep-block', 'deep-delete']) $(id).disabled = state;
}

$('deep-start-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (waiting) return;
  const ip = $('deep-ip').value.trim();
  if (!ip) return;
  current = null; renderSession(); renderList();
  $('deep-messages').replaceChildren(bubble('user', `深度分析 ${ip}`), pending('正在汇总该 IP 的全部日志并交给 AI 分析，日志较多时需要一两分钟…'));
  busy(true); notice('');
  try {
    current = await call('/api/deep/start', {ip}, 300000);
    $('deep-ip').value = '';
    await loadList();
  } catch (error) { notice(error.message); current = null; }
  finally { busy(false); renderSession(); renderList(); }
});

async function ask() {
  const question = $('deep-question').value.trim();
  if (!question || !current || waiting) return;
  const messages = $('deep-messages');
  messages.append(bubble('user', question), pending('正在思考…'));
  messages.scrollTop = messages.scrollHeight;
  $('deep-question').value = '';
  busy(true); notice('');
  try { current = await call('/api/deep/ask', {id: current.id, question}, 240000); await loadList(); }
  catch (error) { notice(error.message); $('deep-question').value = question; }
  finally { busy(false); renderSession(); }
}

$('deep-ask-form').addEventListener('submit', event => { event.preventDefault(); ask(); });
$('deep-question').addEventListener('keydown', event => {
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); ask(); }
});

$('deep-block').addEventListener('click', async () => {
  if (!current || !confirm(`把 ${current.ip} 加入 1Panel WAF 全局黑名单（并随 AF 联动同步到防火墙）？`)) return;
  try {
    const data = await call('/api/blacklist/manual/add', {ips: current.ip, reason: '深度分析后手动加黑'}, 120000);
    const result = data.results[0];
    toast(`${current.ip}：${result.label}`, ['listed', 'existing', 'inactive'].includes(result.state) ? '' : 'error');
    if (!['listed', 'existing', 'inactive'].includes(result.state)) notice(`${result.label}：${result.detail}`);
    else current.summary.blockState = {...current.summary.blockState, manual: result.state};
    renderSession();
  } catch (error) { notice(error.message); }
});

$('deep-delete').addEventListener('click', async () => {
  if (!current || !confirm(`删除 ${current.ip} 的这次深度分析会话？`)) return;
  try { sessions = (await call('/api/deep/delete', {id: current.id})).sessions; current = null; renderSession(); renderList(); }
  catch (error) { notice(error.message); }
});

const onScreen = () => isActive('deep');
document.addEventListener('view-change', () => { if (onScreen()) loadList(); });
renderSession();
if (onScreen()) loadList();
