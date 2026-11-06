// 清洗规则 page: user cleaning rules, built-in switches and a line tester.
import {isActive} from './nav.js';
import {$, toast} from './ui.js';

const ACTIONS = {drop: '丢弃', archive: '仅存档', ai: '强制送 AI', block: '必封'};
const BLOCK_STATES = {pending: '等待加黑', failed: '失败 · 自动重试', protected: '受保护 · 未加黑', listed: '已加入黑名单',
  existing: '已在黑名单中', inactive: '已加入 · WAF 未就绪', removed: '已移出黑名单', unblocked: '已移除并保护'};
const number = value => Number(value || 0).toLocaleString('zh-CN');
const date = seconds => seconds ? new Date(seconds * 1000).toLocaleString('zh-CN', {hour12: false}) : '';
let rules = [], editing = null, loaded = false;

function cell(text, className = '') {
  const node = document.createElement('td');
  node.textContent = text; node.title = text;
  if (className) node.className = className;
  return node;
}

async function call(path, body) {
  const response = await fetch(path, {signal: AbortSignal.timeout(20000),
    ...(body ? {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)} : {})});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '操作失败。');
  return data;
}

function conditions(rule) {
  const parts = [];
  if (rule.ip) parts.push(`IP ${rule.ip}`);
  if (rule.method) parts.push(`方法 ${rule.method}`);
  if (rule.status) parts.push(`状态 ${rule.status}`);
  if (rule.path) parts.push(`路径 /${rule.path}/`);
  if (rule.ua) parts.push(`UA /${rule.ua}/`);
  if (rule.includeSuspicious && rule.action !== 'ai') parts.push('包括可疑请求');
  return parts.join(' · ');
}

function render(data) {
  rules = data.rules;
  $('clean-version').textContent = `${rules.filter(r => r.enabled).length} 条启用 · 版本 ${data.version}`;
  $('clean-empty').hidden = rules.length > 0;
  $('clean-rows').replaceChildren(...rules.map((rule, index) => {
    const row = document.createElement('tr');
    const toggle = document.createElement('input');
    toggle.type = 'checkbox'; toggle.checked = rule.enabled; toggle.setAttribute('aria-label', `启用规则 ${rule.name}`);
    toggle.addEventListener('change', () => save({...rule, enabled: toggle.checked}).catch(() => { toggle.checked = rule.enabled; }));
    const enabled = document.createElement('td'); enabled.append(toggle);
    const actions = document.createElement('td');
    for (const [label, handler, disabled] of [
      ['上移', () => move(rule.id, -1), index === 0], ['下移', () => move(rule.id, 1), index === rules.length - 1],
      ['编辑', () => open(rule)], ['删除', () => remove(rule)]]) {
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'text-button accent'; button.textContent = label; button.disabled = !!disabled;
      button.addEventListener('click', handler);
      actions.append(button);
    }
    const hits = cell(number(rule.hits)); if (rule.last_hit) hits.title = `最近命中：${date(rule.last_hit)}`;
    row.append(cell(String(index + 1)), cell(rule.name, rule.enabled ? '' : 'disabled'), cell(conditions(rule), rule.enabled ? '' : 'disabled'),
      cell(ACTIONS[rule.action], `action-${rule.action}`), hits, enabled, actions);
    return row;
  }));
  renderBlocks(data.blocks);
  const options = data.options;
  $('clean-drop-static').checked = options.dropStatic;
  $('clean-drop-preflight').checked = options.dropPreflight;
  $('clean-widespread').value = options.widespreadIps;
  $('clean-context').value = options.contextRows;
  loaded = true;
}

function renderBlocks(blocks) {
  if (!blocks) return;
  const counts = blocks.counts || {};
  const done = (counts.listed || 0) + (counts.existing || 0) + (counts.inactive || 0);
  $('clean-block-badge').textContent = blocks.rescanning ? '正在扫描已保存日志' :
    `已加黑 ${number(done)} · 等待 ${number((counts.pending || 0) + (counts.failed || 0))} · 受保护 ${number(counts.protected)}`;
  $('clean-rescan').disabled = blocks.rescanning;
  $('clean-block-notice').hidden = !blocks.error; $('clean-block-notice').textContent = blocks.error || '';
  $('clean-block-empty').hidden = blocks.rows.length > 0;
  $('clean-block-rows').replaceChildren(...blocks.rows.map(item => {
    const row = document.createElement('tr');
    row.append(cell(item.ip), cell(item.rule_name), cell(number(item.hits)), cell(date(item.last_seen)),
      cell(BLOCK_STATES[item.state] || item.state, item.state === 'protected' ? 'action-archive' : item.state === 'failed' ? 'action-drop' : 'action-ai'),
      cell(`${item.origin ? item.origin + ' · ' : ''}${item.sample}${item.detail ? '\n' + item.detail : ''}`));
    row.firstChild.dataset.geoIp = item.ip;
    return row;
  }));
}

function notice(message) {
  $('clean-notice').hidden = !message;
  $('clean-notice').textContent = message || '';
}

async function refresh() {
  try { render(await call('/api/clean-rules')); notice(''); }
  catch (error) { notice(error.name === 'TimeoutError' ? '读取超时，稍后重试。' : error.message); }
}

async function save(rule) {
  try { render(await call('/api/clean-rules/save', rule)); notice(''); }
  catch (error) { notice(error.message); throw error; }
}

async function move(id, direction) {
  try { render(await call('/api/clean-rules/move', {id, direction})); } catch (error) { notice(error.message); }
}

async function remove(rule) {
  if (!confirm(`删除规则“${rule.name}”？`)) return;
  try { render(await call('/api/clean-rules/delete', {id: rule.id})); toast('规则已删除'); } catch (error) { notice(error.message); }
}

const FIELDS = ['name', 'ip', 'method', 'status', 'path', 'ua'];
function open(rule = null) {
  editing = rule;
  $('clean-rule-title').textContent = rule ? '编辑清洗规则' : '添加清洗规则';
  for (const field of FIELDS) $(`clean-rule-${field}`).value = rule?.[field] || '';
  $('clean-rule-action').value = rule?.action || 'drop';
  $('clean-rule-suspicious').checked = !!rule?.includeSuspicious;
  $('clean-rule-enabled').checked = rule ? rule.enabled : true;
  $('clean-rule-error').hidden = true;
  blockHint();
  $('clean-rule-dialog').showModal();
}
function blockHint() {
  const block = $('clean-rule-action').value === 'block';
  $('clean-rule-block-hint').hidden = !block;
  $('clean-rule-suspicious').closest('label').hidden = block || $('clean-rule-action').value === 'ai';
}
$('clean-rule-action').addEventListener('change', blockHint);
$('clean-rescan').addEventListener('click', async () => {
  if (!confirm('用当前启用的必封规则扫描平台已保存的全部访问日志，命中的 IP 会加入 WAF 全局黑名单。继续？')) return;
  try { render(await call('/api/clean-rules/rescan', {})); toast('已开始扫描'); } catch (error) { notice(error.message); }
});

$('clean-add').addEventListener('click', () => open());
$('close-clean-rule').addEventListener('click', () => $('clean-rule-dialog').close());
$('clean-rule-form').addEventListener('submit', async event => {
  event.preventDefault();
  const body = Object.fromEntries(FIELDS.map(field => [field, $(`clean-rule-${field}`).value]));
  Object.assign(body, {action: $('clean-rule-action').value, includeSuspicious: $('clean-rule-suspicious').checked,
    enabled: $('clean-rule-enabled').checked});
  if (editing) body.id = editing.id;
  try {
    render(await call('/api/clean-rules/save', body));
    $('clean-rule-dialog').close(); toast('规则已保存'); notice('');
  } catch (error) { $('clean-rule-error').textContent = error.message; $('clean-rule-error').hidden = false; }
});

$('clean-options-form').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    render(await call('/api/clean-rules/options', {dropStatic: $('clean-drop-static').checked,
      dropPreflight: $('clean-drop-preflight').checked, widespreadIps: Number($('clean-widespread').value),
      contextRows: Number($('clean-context').value)}));
    toast('内置设置已保存'); notice('');
  } catch (error) { notice(error.message); }
});

$('clean-test').addEventListener('click', async () => {
  const lines = $('clean-test-input').value;
  try {
    const data = await call('/api/clean-rules/test', {lines});
    $('clean-test-rows').replaceChildren(...data.results.map(item => {
      const row = document.createElement('tr');
      const request = item.parsed ? `${item.ip}  ${item.method} ${item.target}  → ${item.status}` : '—';
      const tone = item.outcome === '必封' ? 'action-block' : item.outcome === '丢弃' ? 'action-drop' : item.outcome.includes('AI') ? 'action-ai' : 'action-archive';
      row.append(cell(request), cell(item.outcome, tone), cell(item.detail));
      return row;
    }));
    notice('');
  } catch (error) { notice(error.message); }
});

const onScreen = () => isActive('clean');
document.addEventListener('view-change', () => { if (onScreen()) refresh(); });
if (onScreen()) refresh();
// Hit counts change as agents report; refresh quietly while the page is open.
setInterval(() => { if (!document.hidden && onScreen() && loaded && !$('clean-rule-dialog').open) refresh(); }, 15000);
