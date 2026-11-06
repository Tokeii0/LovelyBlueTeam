// 当前黑名单 on the 黑名单 page: every WAF global blacklist rule, with remove and clear-all.
import {isActive} from './nav.js';
import {$, toast} from './ui.js';

const ORIGINS = {DeepSeek: 'AI 判定', SiteVisit: '访问即加黑', CleanRule: '清洗规则必封', Manual: '手动加黑', AFSyslog: 'AF 安全日志', Panel: '1Panel 直接添加'};
const PAGE = 100;
const number = value => Number(value || 0).toLocaleString('zh-CN');
let rules = [], page = 1, selected = new Set(), loading = false, poll = null;

async function call(path, body, timeout = 120000) {
  const response = await fetch(path, {signal: AbortSignal.timeout(timeout), method: 'POST',
    headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body || {})});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '操作失败。');
  return data;
}

function notice(message) {
  $('rules-notice').hidden = !message;
  $('rules-notice').textContent = message || '';
}

function cell(text, className = '') {
  const node = document.createElement('td');
  node.textContent = text; node.title = text;
  if (className) node.className = className;
  return node;
}

function filtered() {
  const query = $('rules-search').value.trim().toLowerCase();
  const origin = $('rules-origin').value;
  return rules.filter(rule => (!origin || rule.origin === origin) &&
    (!query || rule.target.toLowerCase().includes(query) || rule.description.toLowerCase().includes(query)));
}

function render() {
  const list = filtered();
  const pages = Math.max(1, Math.ceil(list.length / PAGE));
  page = Math.min(page, pages);
  const shown = list.slice((page - 1) * PAGE, page * PAGE);
  const counts = {};
  rules.forEach(rule => { counts[rule.origin] = (counts[rule.origin] || 0) + 1; });
  $('rules-badge').textContent = `共 ${number(rules.length)} 条`;
  $('rules-count').textContent = `${list.length === rules.length ? '' : `筛选出 ${number(list.length)} 条 · `}` +
    Object.entries(counts).map(([origin, count]) => `${ORIGINS[origin] || origin} ${number(count)}`).join(' · ');
  $('rules-page').textContent = `第 ${page} / ${pages} 页`;
  $('rules-prev').disabled = page <= 1; $('rules-next').disabled = page >= pages;
  $('rules-empty').hidden = list.length > 0;
  $('rules-rows').replaceChildren(...shown.map(rule => {
    const row = document.createElement('tr');
    const check = Object.assign(document.createElement('input'), {type: 'checkbox', checked: selected.has(rule.name)});
    check.setAttribute('aria-label', `选择 ${rule.target}`);
    check.addEventListener('change', () => { check.checked ? selected.add(rule.name) : selected.delete(rule.name); toolbar(); });
    const pick = document.createElement('td'); pick.append(check);
    const actions = document.createElement('td');
    const remove = Object.assign(document.createElement('button'), {type: 'button', className: 'text-button accent', textContent: '移除'});
    remove.addEventListener('click', () => removeRules([rule.name]));
    actions.append(remove);
    row.append(pick, cell(rule.target), cell(ORIGINS[rule.origin] || rule.origin), cell(rule.description || '—'),
      cell(rule.enabled ? '启用' : '已停用', rule.enabled ? '' : 'disabled'), actions);
    if (rule.type === 'ipv4' || rule.type === 'ipv6') row.children[1].dataset.geoIp = rule.target;
    return row;
  }));
  $('rules-all').checked = shown.length > 0 && shown.every(rule => selected.has(rule.name));
  toolbar();
}

function toolbar() {
  const busy = loading || !!poll;
  $('rules-remove').disabled = busy || selected.size === 0;
  $('rules-remove').textContent = selected.size ? `移除所选（${selected.size}）` : '移除所选';
  $('rules-clear').disabled = busy || rules.length === 0;
}

function progress(clear) {
  const box = $('rules-progress');
  if (!clear || (!clear.running && !clear.finished)) { box.hidden = true; return; }
  box.hidden = false;
  box.textContent = clear.running
    ? `正在清空：已移除 ${number(clear.done)} / ${number(clear.total)} 条${clear.failed ? `，失败 ${number(clear.failed)} 条` : ''}…`
    : `上次清空已完成：移除 ${number(clear.done)} / ${number(clear.total)} 条${clear.failed ? `，失败 ${number(clear.failed)} 条：${clear.errors.join('；')}` : ''}`;
}

function apply(data) {
  rules = data.rules;
  const names = new Set(rules.map(rule => rule.name));
  selected = new Set([...selected].filter(name => names.has(name)));
  progress(data.clear);
  if (data.clear && data.clear.running && !poll) poll = setInterval(refresh, 2000);
  if (data.clear && !data.clear.running && poll) { clearInterval(poll); poll = null; toast('清空完成'); }
  render();
}

async function refresh() {
  if (loading) return;
  loading = true; toolbar();
  try { apply(await call('/api/blacklist/rules/list')); notice(''); }
  catch (error) { notice(error.message); }
  finally { loading = false; toolbar(); }
}

async function removeRules(names) {
  const protect = $('rules-protect').checked;
  const label = names.length === 1 ? rules.find(rule => rule.name === names[0])?.target : `${names.length} 条黑名单`;
  if (!confirm(`从 1Panel WAF 全局黑名单移除 ${label}？\n${protect ? '移除后保护：这些 IP 以后不会再被自动加黑。' : '这些 IP 再次命中 AI、访问规则或必封规则时，会被重新自动加黑。'}`)) return;
  loading = true; toolbar();
  try {
    const data = await call('/api/blacklist/rules/remove', {names, protect});
    names.forEach(name => selected.delete(name));
    apply(data);
    const problems = [...data.failed, ...data.unconfirmed.map(target => `${target}：未确认移除`)];
    notice(problems.join('；'));
    toast(`已移除 ${data.removed} 条${problems.length ? `，${problems.length} 条未完成` : ''}`, problems.length ? 'error' : '');
  } catch (error) { notice(error.message); }
  finally { loading = false; toolbar(); }
}

$('rules-refresh').addEventListener('click', refresh);
$('rules-search').addEventListener('input', () => { page = 1; render(); });
$('rules-origin').addEventListener('change', () => { page = 1; render(); });
$('rules-prev').addEventListener('click', () => { page--; render(); });
$('rules-next').addEventListener('click', () => { page++; render(); });
$('rules-all').addEventListener('change', () => {
  const list = filtered().slice((page - 1) * PAGE, page * PAGE);
  list.forEach(rule => $('rules-all').checked ? selected.add(rule.name) : selected.delete(rule.name));
  render();
});
$('rules-remove').addEventListener('click', () => {
  if (selected.size > 200) { notice('一次最多移除 200 条；大量移除请用“清空黑名单”。'); return; }
  removeRules([...selected]);
});
$('rules-clear').addEventListener('click', async () => {
  const protect = $('rules-protect').checked;
  const typed = prompt(`将删除 1Panel WAF 全局黑名单中的全部 ${rules.length} 条记录（包括在 1Panel 中直接添加的），之前拦截的扫描器和攻击者都会被放行。\n` +
    `${protect ? '勾选了“移除后保护”：这些 IP 以后不会再被自动加黑。' : '这些 IP 再次命中规则时会被重新自动加黑。'}\n\n确认请输入：清空`);
  if (typed === null) return;
  try { apply(await call('/api/blacklist/rules/clear', {confirm: typed.trim(), protect})); notice(''); }
  catch (error) { notice(error.message); }
});

const onScreen = () => isActive('blacklist');
document.addEventListener('view-change', () => { if (onScreen()) refresh(); });
if (onScreen()) refresh();
