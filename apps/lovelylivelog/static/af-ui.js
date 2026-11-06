// Sangfor AF firewall blacklist sync, shown on the 黑名单 page.
import {isActive} from './nav.js';
import {$, toast} from './ui.js';

const RESULTS = {added: '已加入', removed: '已移除', skipped: '未下发', missing: '未查询到', held: '暂缓移除'};
const date = seconds => seconds ? new Date(seconds * 1000).toLocaleString('zh-CN', {hour12: false}) : '—';
const number = value => Number(value || 0).toLocaleString('zh-CN');
let filled = false;

async function call(path, body) {
  const response = await fetch(path, {signal: AbortSignal.timeout(120000),
    ...(body ? {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)} : {})});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '操作失败。');
  return data;
}

function notice(message) {
  $('af-notice').hidden = !message;
  $('af-notice').textContent = message || '';
}

function render(data) {
  const {settings: config, status} = data;
  if (!filled) {
    // Fill the form once so a refresh never overwrites what is being typed.
    $('af-url').value = config.url; $('af-namespace').value = config.namespace; $('af-username').value = config.username;
    $('af-interval').value = config.interval; $('af-enabled').checked = config.enabled; $('af-verify').checked = config.verifyTls;
    $('af-remove').checked = config.remove; $('af-private').checked = config.includePrivate;
    $('af-password').placeholder = config.passwordSet ? '已保存，留空不修改' : '请输入密码';
    filled = true;
  }
  const badge = $('af-badge');
  badge.textContent = data.busy ? '正在同步' : !config.url ? '未配置' : config.enabled ? `每 ${config.interval} 秒自动同步` : '自动同步已关闭';
  badge.className = `status-badge${config.enabled && config.url ? ' success' : ''}`;
  const lines = [];
  if (status.at) {
    lines.push(`最近同步：${date(status.at)}${status.manual ? '（手动）' : ''} · 耗时 ${status.duration ?? '—'} 秒 · ${status.ok ? '成功' : '未完成'}`);
    if (status.total !== undefined) {
      lines.push(`WAF 名单 ${number(status.total)} 条 · 应下发 ${number(status.desired)} · 新增 ${number(status.added)} · 移除 ${number(status.removed)} · 未下发 ${number(status.skipped)} · AF 已有同地址 ${number(status.existing)} · 本程序在 AF 管理 ${number(status.managed)} 条 · AF 黑名单共 ${number(status.afTotal)} 条`);
    }
  }
  $('af-status').replaceChildren(...lines.map(text => Object.assign(document.createElement('span'), {textContent: text})));
  notice(status.error || '');
  $('af-empty').hidden = data.log.length > 0;
  $('af-rows').replaceChildren(...data.log.map(item => {
    const row = document.createElement('tr');
    for (const value of [date(item.at), item.target, RESULTS[item.action] || item.action, item.detail]) {
      const cell = document.createElement('td'); cell.textContent = value; cell.title = value; row.append(cell);
    }
    return row;
  }));
}

async function refresh() {
  try { render(await call('/api/af')); } catch (error) { notice(error.message); }
}

async function loadLog() {
  try {
    const {log} = await call('/api/af/log');
    $('af-log').textContent = log || '还没有日志。点击“测试连接”后这里会记录每个 AF 请求及失败原因。';
    $('af-log').scrollTop = $('af-log').scrollHeight;
  } catch (error) { $('af-log').textContent = error.message; }
}

async function busy(button, task) {
  button.disabled = true;
  try { await task(); } catch (error) { notice(error.message); toast(error.message, 'error'); }
  finally {
    button.disabled = false;
    if (!$('af-log-box').hidden) loadLog();  // Show what was just attempted.
  }
}

$('af-show-log').addEventListener('click', () => {
  const box = $('af-log-box');
  box.hidden = !box.hidden;
  $('af-show-log').textContent = box.hidden ? '查看日志' : '收起日志';
  if (!box.hidden) loadLog();
});
$('af-log-refresh').addEventListener('click', loadLog);

// Test and sync act on what is in the form, so the form is saved first.
async function saveForm() {
  const body = {url: $('af-url').value.trim(), namespace: $('af-namespace').value.trim() || 'public',
    username: $('af-username').value.trim(), interval: Number($('af-interval').value), enabled: $('af-enabled').checked,
    verifyTls: $('af-verify').checked, remove: $('af-remove').checked, includePrivate: $('af-private').checked};
  if ($('af-password').value) body.password = $('af-password').value;
  filled = false;
  render(await call('/api/af/settings', body));
  $('af-password').value = '';
}

$('af-form').addEventListener('submit', event => {
  event.preventDefault();
  busy(event.submitter || $('af-sync'), async () => { await saveForm(); toast('AF 设置已保存'); });
});
$('af-test').addEventListener('click', () => busy($('af-test'), async () => {
  await saveForm();
  const result = await call('/api/af/test', {});
  notice('');
  toast(`连接成功 · AF 黑名单 ${number(result.blacklist)} 条，其中本程序添加 ${number(result.managed)} 条`);
}));
$('af-sync').addEventListener('click', () => busy($('af-sync'), async () => {
  if (!confirm('将 1Panel WAF 全局黑名单写入 AF 防火墙黑名单，确定同步？')) return;
  await saveForm();
  render(await call('/api/af/sync', {}));
  toast('同步完成');
}));

const onScreen = () => isActive('blacklist');
document.addEventListener('view-change', () => { if (onScreen()) refresh(); });
if (onScreen()) refresh();
setInterval(() => { if (!document.hidden && onScreen()) refresh(); }, 10000);
