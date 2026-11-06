// 告警推送 page: NapCat connection, keyword rules with group / content choice, delivery log.
import {isActive} from './nav.js';
import {$, toast} from './ui.js';

const KIND_LABELS = {'access.log': '访问', 'error.log': '错误', 'custom.log': '应用'};
const PLACEHOLDER_LABELS = {rule: '规则名', keyword: '命中关键词', source: '来源', kind: '日志类型', time: '时间', ip: 'IP',
  geo: 'IP 归属地', method: '请求方法', path: '请求路径', status: '状态码', count: '合并条数', raw: '原始日志'};
const number = value => Number(value || 0).toLocaleString('zh-CN');
const date = seconds => seconds ? new Date(seconds * 1000).toLocaleString('zh-CN', {hour12: false}) : '';
let data = null, filled = false, editing = null, groups = null, sources = null, previewTimer = null;

async function call(path, body, timeout = 20000) {
  const response = await fetch(path, {signal: AbortSignal.timeout(timeout),
    ...(body ? {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)} : {})});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || '操作失败。');
  return result;
}

function cell(text, className = '') {
  const node = document.createElement('td');
  node.textContent = text; node.title = text;
  if (className) node.className = className;
  return node;
}

const el = (tag, className, text) => Object.assign(document.createElement(tag), {className, textContent: text ?? ''});

function notice(message) {
  $('notify-notice').hidden = !message;
  $('notify-notice').textContent = message || '';
}

const groupName = id => {
  const group = groups?.find(g => g.id === id);
  return group ? `${group.name}（${id}）` : String(id);
};

function sourceText(rule) {
  const kinds = rule.kinds.length === 3 ? '全部日志' : rule.kinds.map(k => KIND_LABELS[k]).join(' / ') + '日志';
  if (!rule.sources.length) return `${kinds} · 全部来源`;
  const names = rule.sources.map(value => sources?.find(s => s.value === value)?.label || value);
  return `${kinds} · ${names.join('、')}`;
}

const mentionText = rule => [rule.mentionAll ? '@全体成员' : '', rule.mentions?.length ? `@${rule.mentions.length} 人` : '']
  .filter(Boolean).map(text => ` · ${text}`).join('');

function render(next) {
  data = next;
  const config = data.settings;
  if (!filled) {
    // Fill the form once so a refresh never overwrites what is being typed.
    $('notify-url').value = config.url; $('notify-enabled').checked = config.enabled;
    $('notify-token').placeholder = config.tokenSet ? '已保存，留空不修改' : 'NapCat 未设置 token 时留空';
    filled = true;
  }
  const badge = $('notify-badge');
  badge.textContent = !config.enabled ? '推送已关闭' : data.error ? '推送异常' : '推送已开启';
  badge.className = `status-badge${config.enabled && !data.error ? ' success' : config.enabled ? ' server-error' : ''}`;
  const active = data.rules.filter(r => r.enabled).length;
  $('notify-rule-badge').textContent = `${active} 条启用 · 共 ${data.rules.length} 条`;
  $('notify-status').replaceChildren(...[
    `待发送消息 ${number(data.queued)} 条`,
  ].map(text => Object.assign(document.createElement('span'), {textContent: text})));
  notice(data.error || '');
  $('notify-empty').hidden = data.rules.length > 0;
  $('notify-rows').replaceChildren(...data.rules.map(rule => {
    const row = document.createElement('tr');
    const toggle = document.createElement('input');
    toggle.type = 'checkbox'; toggle.checked = rule.enabled; toggle.setAttribute('aria-label', `启用规则 ${rule.name}`);
    toggle.addEventListener('change', () => save({...rule, enabled: toggle.checked}).catch(() => { toggle.checked = rule.enabled; }));
    const enabled = document.createElement('td'); enabled.append(toggle);
    const actions = document.createElement('td');
    for (const [label, handler] of [['编辑', () => open(rule)], ['删除', () => remove(rule)]]) {
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'text-button accent'; button.textContent = label;
      button.addEventListener('click', handler);
      actions.append(button);
    }
    const tone = rule.enabled ? '' : 'disabled';
    const hits = cell(number(rule.hits)); if (rule.lastHit) hits.title = `最近命中：${date(rule.lastHit)}`;
    row.append(cell(rule.name, tone), cell(rule.keywords.join('、') + (rule.matchAll ? '（全部包含）' : ''), tone),
      cell(sourceText(rule), tone), cell(rule.groups.map(groupName).join('、') + mentionText(rule), tone), hits, enabled, actions);
    return row;
  }));
  $('notify-log-empty').hidden = data.log.length > 0;
  $('notify-log-rows').replaceChildren(...data.log.map(item => {
    const row = document.createElement('tr');
    row.append(cell(date(item.at)), cell(item.rule_name), cell(groupName(item.group_id)),
      cell(item.ok ? '成功' : item.detail, item.ok ? 'action-ai' : 'action-drop'), cell(item.preview));
    return row;
  }));
}

async function refresh() {
  try { render(await call('/api/notify')); } catch (error) { notice(error.message); }
}

async function loadGroups(force = false) {
  if (groups && !force) return groups;
  const box = $('notify-groups');
  box.replaceChildren(Object.assign(document.createElement('span'), {className: 'muted', textContent: '正在从 NapCat 读取群列表…'}));
  try {
    groups = (await call('/api/notify/groups', {})).groups;
  } catch (error) {
    groups = null;
    box.replaceChildren(Object.assign(document.createElement('span'), {className: 'notify-error', textContent: error.message}));
    throw error;
  }
  return groups;
}

async function loadSources() {
  if (sources) return sources;
  const [sites, agents] = await Promise.allSettled([call('/api/websites'), call('/api/agents')]);
  sources = [
    ...(sites.status === 'fulfilled' ? sites.value.websites.map(s => ({value: `site:${s.id}`, label: `网站 · ${s.name}`})) : []),
    ...(agents.status === 'fulfilled' ? agents.value.agents.map(a => ({value: `agent:${a.id}`, label: `服务器 · ${a.name}`})) : []),
  ];
  return sources;
}

function checkbox(name, value, label, checked) {
  const wrap = document.createElement('label');
  wrap.className = 'settings-checkbox';
  const input = Object.assign(document.createElement('input'), {type: 'checkbox', name, value, checked});
  wrap.append(input, document.createTextNode(label));
  wrap.title = label;
  return wrap;
}

function renderGroups(selected) {
  const filter = $('notify-group-filter').value.trim().toLowerCase();
  const chosen = new Set(selected);
  const list = (groups || []).filter(g => !filter || chosen.has(g.id) || g.name.toLowerCase().includes(filter) || String(g.id).includes(filter));
  // Groups saved earlier but no longer in the bot's list stay selectable, so a save never drops them silently.
  const missing = selected.filter(id => !(groups || []).some(g => g.id === id));
  const nodes = [...missing.map(id => checkbox('notify-group', id, `${id}（机器人已不在该群）`, true)),
    ...list.map(g => checkbox('notify-group', g.id, `${g.name}（${g.id}${g.members ? ` · ${g.members} 人` : ''}）`, chosen.has(g.id)))];
  $('notify-groups').replaceChildren(...(nodes.length ? nodes : [Object.assign(document.createElement('span'), {className: 'muted', textContent: '没有匹配的群。'})]));
}

const selectedGroups = () => [...document.querySelectorAll('input[name="notify-group"]:checked')].map(i => Number(i.value));

function renderSources(selected) {
  const chosen = new Set(selected);
  const nodes = (sources || []).map(s => checkbox('notify-source', s.value, s.label, chosen.has(s.value)));
  for (const value of selected) if (!(sources || []).some(s => s.value === value)) nodes.push(checkbox('notify-source', value, value, true));
  $('notify-sources').replaceChildren(...(nodes.length ? nodes : [Object.assign(document.createElement('span'), {className: 'muted', textContent: '暂无网站或服务器。'})]));
}

function schedulePreview() {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(async () => {
    try {
      const {text} = await call('/api/notify/preview', {template: $('notify-rule-template').value, name: $('notify-rule-name').value});
      $('notify-preview').textContent = text;
    } catch (error) { $('notify-preview').textContent = error.message; }
  }, 250);
}

function insertPlaceholder(name) {
  const area = $('notify-rule-template');
  const start = area.selectionStart ?? area.value.length, end = area.selectionEnd ?? start;
  area.value = area.value.slice(0, start) + `{${name}}` + area.value.slice(end);
  area.focus();
  area.selectionStart = area.selectionEnd = start + name.length + 2;
  schedulePreview();
}

// ----- @ 成员: QQ numbers to mention; names come from the member lists read so far -----
const MAX_MENTIONS = 20;
const memberNames = new Map();
let mentions = [], members = [];

function mentionName(qq) {
  const name = memberNames.get(qq);
  return name ? `${name}（${qq}）` : String(qq);
}

function renderMentions() {
  const chips = mentions.map(qq => {
    const chip = el('span', 'notify-mention', `@${mentionName(qq)}`);
    const remove = Object.assign(document.createElement('button'), {type: 'button', className: 'notify-mention-remove', textContent: '×'});
    remove.setAttribute('aria-label', `不再 @ ${qq}`);
    remove.addEventListener('click', () => { mentions = mentions.filter(q => q !== qq); renderMentions(); renderMembers(); });
    chip.append(remove);
    return chip;
  });
  $('notify-mentions').replaceChildren(...(chips.length ? chips : [el('span', 'muted', '不 @ 任何人')]));
}

function addMention(qq) {
  if (!Number.isInteger(qq) || qq < 10000 || qq > 1e11) { dialogError('QQ 号格式不正确。'); return false; }
  if (mentions.includes(qq)) return true;
  if (mentions.length >= MAX_MENTIONS) { dialogError(`最多 @ ${MAX_MENTIONS} 人。`); return false; }
  mentions.push(qq); dialogError(''); renderMentions();
  return true;
}

function renderMembers() {
  const filter = $('notify-member-filter').value.trim().toLowerCase();
  const total = selectedGroups().length;
  const list = members.filter(m => !filter || m.name.toLowerCase().includes(filter) || m.nickname.toLowerCase().includes(filter) ||
    String(m.id).includes(filter)).slice(0, 300);
  $('notify-members').replaceChildren(...(list.length ? list.map(m => {
    const role = m.role === 'owner' ? ' · 群主' : m.role === 'admin' ? ' · 管理员' : '';
    const partial = m.groups.length < total ? ` · 仅在 ${m.groups.length}/${total} 个群` : '';
    const box = checkbox('notify-member', m.id, `${m.name}（${m.id}${role}${partial}）`, mentions.includes(m.id));
    box.querySelector('input').addEventListener('change', event => {
      if (event.target.checked) { if (!addMention(m.id)) event.target.checked = false; }
      else { mentions = mentions.filter(q => q !== m.id); renderMentions(); }
    });
    return box;
  }) : [el('span', 'muted', members.length ? '没有匹配的成员。' : '所选群中没有读取到成员。')]));
}

async function loadMembers() {
  const chosen = selectedGroups();
  if (!chosen.length) { dialogError('请先勾选推送群聊。'); return; }
  $('notify-member-box').hidden = false;
  $('notify-members').replaceChildren(el('span', 'muted', '正在读取群成员，第一次读取较大的群可能需要几秒…'));
  try {
    members = (await call('/api/notify/members', {groups: chosen}, 60000)).members;
    members.forEach(m => memberNames.set(m.id, m.name));
    renderMembers(); renderMentions(); dialogError('');
  } catch (error) { $('notify-members').replaceChildren(el('span', 'notify-error', error.message)); }
}

function formBody() {
  const body = {
    name: $('notify-rule-name').value, keywords: $('notify-rule-keywords').value, matchAll: $('notify-rule-all').checked,
    kinds: [...document.querySelectorAll('input[name="notify-kind"]:checked')].map(i => i.value),
    sources: [...document.querySelectorAll('input[name="notify-source"]:checked')].map(i => i.value),
    groups: selectedGroups(), template: $('notify-rule-template').value,
    cooldown: Number($('notify-rule-cooldown').value), enabled: $('notify-rule-enabled').checked,
    mentions: [...mentions], mentionAll: $('notify-mention-all').checked,
  };
  if (editing) body.id = editing.id;
  return body;
}

function dialogError(message) {
  $('notify-rule-error').textContent = message || '';
  $('notify-rule-error').hidden = !message;
}

async function open(rule = null) {
  editing = rule;
  $('notify-rule-title').textContent = rule ? '编辑推送规则' : '添加推送规则';
  $('notify-rule-name').value = rule?.name || '';
  $('notify-rule-keywords').value = (rule?.keywords || []).join('\n');
  $('notify-rule-all').checked = !!rule?.matchAll;
  const kinds = rule?.kinds || Object.keys(KIND_LABELS);
  document.querySelectorAll('input[name="notify-kind"]').forEach(input => { input.checked = kinds.includes(input.value); });
  $('notify-rule-template').value = rule?.template || data?.defaultTemplate || '';
  $('notify-rule-cooldown').value = rule?.cooldown ?? 60;
  $('notify-rule-enabled').checked = rule ? rule.enabled : true;
  $('notify-group-filter').value = '';
  mentions = [...(rule?.mentions || [])]; members = [];
  $('notify-mention-all').checked = !!rule?.mentionAll;
  $('notify-mention-input').value = ''; $('notify-member-filter').value = ''; $('notify-member-box').hidden = true;
  renderMentions();
  $('notify-placeholders').replaceChildren(...(data?.placeholders || []).map(name => {
    const chip = Object.assign(document.createElement('button'), {type: 'button', className: 'notify-chip',
      textContent: `{${name}} ${PLACEHOLDER_LABELS[name] || ''}`});
    chip.addEventListener('click', () => insertPlaceholder(name));
    return chip;
  }));
  dialogError('');
  $('notify-rule-dialog').showModal();
  schedulePreview();
  loadSources().then(() => renderSources(rule?.sources || [])).catch(() => renderSources(rule?.sources || []));
  loadGroups().then(() => renderGroups(rule?.groups || [])).catch(() => {});
}

async function save(rule) {
  try { render(await call('/api/notify/save', rule)); notice(''); }
  catch (error) { notice(error.message); throw error; }
}

async function remove(rule) {
  if (!confirm(`删除推送规则“${rule.name}”？`)) return;
  try { render(await call('/api/notify/delete', {id: rule.id})); toast('规则已删除'); } catch (error) { notice(error.message); }
}

async function busy(button, task) {
  button.disabled = true;
  try { await task(); } catch (error) { notice(error.message); toast(error.message, 'error'); }
  finally {
    button.disabled = false;
    if (!$('notify-log-box').hidden) loadLog();
  }
}

async function loadLog() {
  try {
    const {log} = await call('/api/notify/log');
    $('notify-log').textContent = log || '还没有日志。点击“测试连接”或有消息发送后这里会记录结果。';
    $('notify-log').scrollTop = $('notify-log').scrollHeight;
  } catch (error) { $('notify-log').textContent = error.message; }
}

async function saveSettings() {
  const body = {url: $('notify-url').value.trim(), enabled: $('notify-enabled').checked};
  if ($('notify-token').value) body.token = $('notify-token').value;
  filled = false;
  render(await call('/api/notify/settings', body));
  $('notify-token').value = '';
}

$('notify-form').addEventListener('submit', event => {
  event.preventDefault();
  busy(event.submitter || $('notify-test'), async () => { await saveSettings(); groups = null; toast('连接设置已保存'); });
});
$('notify-test').addEventListener('click', () => busy($('notify-test'), async () => {
  await saveSettings();
  const result = await call('/api/notify/test', {});
  groups = null;
  notice('');
  toast(`连接成功 · 机器人 ${result.nickname}（${result.userId}）· ${number(result.groups)} 个群`);
}));
$('notify-show-log').addEventListener('click', () => {
  const box = $('notify-log-box');
  box.hidden = !box.hidden;
  $('notify-show-log').textContent = box.hidden ? '查看日志' : '收起日志';
  if (!box.hidden) loadLog();
});
$('notify-log-refresh').addEventListener('click', loadLog);

$('notify-add').addEventListener('click', () => open());
$('close-notify-rule').addEventListener('click', () => $('notify-rule-dialog').close());
$('notify-rule-template').addEventListener('input', schedulePreview);
$('notify-rule-name').addEventListener('input', schedulePreview);
$('notify-group-filter').addEventListener('input', () => renderGroups(selectedGroups()));
$('notify-group-reload').addEventListener('click', () => {
  const selected = selectedGroups();
  loadGroups(true).then(() => renderGroups(selected)).catch(() => {});
});
$('notify-member-load').addEventListener('click', loadMembers);
$('notify-member-filter').addEventListener('input', renderMembers);
$('notify-mention-input').addEventListener('keydown', event => {
  if (event.key !== 'Enter' || event.isComposing) return;
  event.preventDefault();  // Enter adds the number instead of submitting the rule.
  const value = $('notify-mention-input').value.trim();
  if (value && addMention(Number(value))) { $('notify-mention-input').value = ''; renderMembers(); }
});
$('notify-rule-form').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    render(await call('/api/notify/save', formBody()));
    $('notify-rule-dialog').close(); toast('规则已保存'); notice('');
  } catch (error) { dialogError(error.message); }
});
$('notify-send-test').addEventListener('click', async () => {
  const chosen = selectedGroups();
  if (!chosen.length) { dialogError('请先选择要测试的群聊。'); return; }
  const who = [$('notify-mention-all').checked ? '全体成员' : '', ...mentions.map(mentionName)].filter(Boolean);
  if (!confirm(`向 ${chosen.length} 个群发送一条测试消息（示例数据）：\n${chosen.map(groupName).join('\n')}` +
    `${who.length ? `\n并 @：${who.join('、')}` : ''}\n确定发送？`)) return;
  const button = $('notify-send-test');
  button.disabled = true;
  try {
    const result = await call('/api/notify/send-test', {groups: chosen, template: $('notify-rule-template').value,
      name: $('notify-rule-name').value, mentions: [...mentions], mentionAll: $('notify-mention-all').checked}, 60000);
    dialogError(''); toast(`已发送到 ${result.sent} 个群`);
    refresh();
  } catch (error) { dialogError(error.message); refresh(); }
  finally { button.disabled = false; }
});

const onScreen = () => isActive('notify');
function show() {
  refresh();
  // Group names make the rule table and log readable; a failure only leaves group numbers.
  loadGroups().then(() => data && render(data)).catch(() => {});
  loadSources().then(() => data && render(data)).catch(() => {});
}
document.addEventListener('view-change', () => { if (onScreen()) show(); });
if (onScreen()) show();
setInterval(() => { if (!document.hidden && onScreen() && !$('notify-rule-dialog').open) refresh(); }, 10000);
