import {formatTime, detail, providerName, isLocalMode, verdictName, verdictScore, stateName, renderDetectionMode, openPlatformSettings} from './security-ui.js';
import {copyText} from './ui.js';
import {view, isActive} from './nav.js';

const $ = id => document.getElementById(id);
const number = value => Number(value || 0).toLocaleString('zh-CN');
const history = {visible: false, page: 1, pages: 1, through: null, revision: 0,
  loading: false, again: false, timer: null};
let exportLoading = false;
function element(tag, text, className = '') {
  const node = document.createElement(tag); node.textContent = text;
  if (className) node.className = className;
  return node;
}
function notice(id, text = '') {$(id).textContent = text; $(id).hidden = !text;}
async function api(path, body) {
  const response = await fetch(path, {cache: 'no-store', signal: AbortSignal.timeout(45000),
    ...(body === undefined ? {} : {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '读取失败，请稍后重试。');
  return data;
}
function render(data) {
  const config = data.settings, summary = data.summary, info = data.history;
  const local = isLocalMode(config), provider = local ? '此来源 · 本地正则检测' : providerName(config.provider);
  renderDetectionMode(config, 'agent');
  $('hub-ai-badge').textContent = `${provider} · ${!config.configured ? '未填密钥' : !config.enabled ? '已暂停' : config.busy ? '正在检测' : '监听新增'}`;
  $('hub-ai-badge').className = `status-badge${config.enabled && config.configured ? ' success' : ''}`;
  for (const name of ['analyzed', 'pending', 'attacks', 'listed']) $('hub-ai-' + name).textContent = number(summary[name]);
  $('hub-ai-policy').textContent = local ? `此来源本地正则检测${config.enabled ? '已开启' : '已暂停'} · 此来源不调用 AI · ${config.platformAnalysisMode === 'ai' ? '平台其他来源继续使用 AI' : '其他来源沿用平台配置'} · 规则命中仅供复核，手动选择封禁 · 无法解析 ${number(summary.unparsed)} 条`
    : `AI ${config.enabled ? '已开启' : '已暂停'} · 自动加黑${config.autoBlock ? '已开启' : '已关闭'} · 阈值 ${Math.round(config.threshold * 100)}% · 近 5 分钟同一来源至少 2 次攻击请求 · 按日清洗 48 小时内可加黑 · 其余历史补传仅复核 · 无法解析 ${number(summary.unparsed)} 条${summary.filtered ? ` · 按日清洗后仅存档 ${number(summary.filtered)} 组` : ''}`;
  notice('hub-ai-notice', config.lastError || '');
  history.page = info.page; history.pages = info.pages; history.through = info.through;
  $('hub-ai-page').textContent = `第 ${info.page} / ${info.pages} 页 · ${number(info.total)} 次判断 · 未命中 / 正常 ${number(info.normalTotal)} · 命中 / 攻击判断 ${number(info.attackTotal)}`;
  $('hub-ai-prev').disabled = info.page <= 1; $('hub-ai-next').disabled = info.page >= info.pages;
  $('hub-ai-empty').hidden = Boolean(data.decisions.length);
  $('hub-ai-empty').textContent = info.allTotal ? '当前筛选下没有结果，可切换到全部判断。' : summary.pending ? `访问日志已进入${local ? '本地检测' : '分析'}队列，完成后显示结果。` : '等待代理上传可识别访客 IP 的访问日志。';
  $('hub-ai-decisions').replaceChildren(...data.decisions.map(item => {
    const row = element('tr', ''); row.dataset.decisionId = item.id;
    const verdict = verdictName(item);
    row.append(element('td', formatTime(item.created)),
      element('td', `${item.ip}\n${item.source_name || item.agent_id}`),
      element('td', `${verdict}${verdictScore(item)}\n${providerName(item.provider)}${item.model ? ' / ' + item.model : ''} · ${number(item.record_count)} 条${item.historical ? `\n历史${item.state === 'review' ? ' · 仅复核' : ''}` : ''}`, item.attack ? 'attack-verdict' : 'normal-verdict'),
      element('td', item.reason), element('td', stateName(item)));
    row.children[1].title = item.source_file; row.children[1].dataset.geoIp = item.ip;
    row.children[4].title = item.detail || stateName(item);
    const actions = element('td', '', 'ai-actions');
    const evidence = element('button', '查看依据', 'text-button');
    evidence.addEventListener('click', () => detail(item)); actions.append(evidence);
    for (const [kind, label, allowed] of [
      ['block', '加入黑名单', item.attack && ['review', 'failed', 'unblocked', 'removed'].includes(item.state)],
      ['unblock', '移除并保护', item.attack && item.canUnblock]]) {
      if (!allowed) continue;
      const button = element('button', label, 'text-button accent');
      button.addEventListener('click', async () => {
        button.disabled = true;
        try {await api('/api/ai/' + kind, {id: item.id}); await refresh(); await refreshBlacklist();}
        catch (error) {notice('hub-ai-notice', error.message);}
        finally {button.disabled = false;}
      });
      actions.append(button);
    }
    row.append(actions); return row;
  }));
}
async function refresh() {
  if (!history.visible) return;
  if (history.loading) {history.again = true; return;}
  history.loading = true; clearTimeout(history.timer);
  const revision = history.revision;
  const params = new URLSearchParams({source: 'agent', agent: view.agent,
    verdict: $('hub-ai-verdict').value, page: history.page, pageSize: 20});
  if (history.page > 1 && history.through !== null) params.set('through', history.through);
  try {
    const data = await api('/api/ai?' + params);
    if (revision === history.revision) render(data);
  } catch (error) {if (revision === history.revision) notice('hub-ai-notice', error.message);}
  finally {
    history.loading = false;
    if (history.again || revision !== history.revision) {history.again = false; refresh();}
    else if (history.visible && !document.hidden) history.timer = setTimeout(refresh, 3000);
  }
}
function change(page = 1, latest = true) {
  history.page = page; history.revision++;
  if (latest) history.through = null;
  refresh();
}
async function refreshBlacklist() {
  if (exportLoading) return;
  exportLoading = true; $('blacklist-refresh').disabled = true;
  try {
    const data = await api('/api/blacklist');
    $('blacklist-summary').textContent = `当前 ${number(data.total)} 个地址项 · 单个 IP ${number(data.ips.length)} · 网段 ${number(data.networks.length)} · 地址段 ${number(data.ranges.length)} · 忽略 ${number(data.disabledRuleCount)} 条停用规则 · ${new Date(data.generatedAt).toLocaleString('zh-CN', {hour12: false})}`;
    notice('blacklist-notice');
  } catch (error) {notice('blacklist-notice', error.message + ' 未更新上次显示的名单。');}
  finally {exportLoading = false; $('blacklist-refresh').disabled = false;}
}
document.addEventListener('hub-overview', event => {
  const data = event.detail;
  const signature = JSON.stringify(data.agents.map(agent => [agent.id, agent.name]));
  if ($('hub-ai-agent-filter').dataset.signature !== signature) {
    const all = element('option', '全部服务器'); all.value = '';
    $('hub-ai-agent-filter').replaceChildren(all, ...data.agents.map(agent => {
      const option = element('option', agent.name); option.value = agent.id; return option;
    }));
    $('hub-ai-agent-filter').dataset.signature = signature;
  }
  $('hub-ai-agent-filter').value = data.agents.some(agent => agent.id === view.agent) ? view.agent : '';
  const endpoint = data.receiver.url ? data.receiver.url.replace(/\/$/, '') + '/v1/blacklist' : '';
  $('blacklist-endpoint').value = endpoint;
  $('blacklist-example').textContent = endpoint ? `curl.exe -H "Authorization: Bearer YOUR_BLACKLIST_API_KEY" "${endpoint}"\n\ncurl.exe -H "Authorization: Bearer YOUR_BLACKLIST_API_KEY" "${endpoint}?format=text"` : '接收端尚未启动，请检查平台配置。';
});
let blacklistShown = false, agentShown = view.agent;
function onView() {
  history.visible = isActive('ai', 'server'); clearTimeout(history.timer);
  $('hub-ai-agent-filter').value = view.agent;
  if (history.visible) {
    if (agentShown !== view.agent) {agentShown = view.agent; change();} else refresh();
  }
  const showBlacklist = isActive('blacklist');
  if (showBlacklist && !blacklistShown) refreshBlacklist();
  blacklistShown = showBlacklist;
}
document.addEventListener('view-change', onView);
document.addEventListener('visibilitychange', () => {
  clearTimeout(history.timer); if (!document.hidden && history.visible) refresh();
});
$('hub-ai-verdict').addEventListener('change', () => change());
$('hub-ai-refresh').addEventListener('click', () => change());
$('hub-ai-prev').addEventListener('click', () => change(Math.max(1, history.page - 1), false));
$('hub-ai-next').addEventListener('click', () => change(Math.min(history.pages, history.page + 1), false));
$('hub-open-ai-settings').addEventListener('click', openPlatformSettings);
$('blacklist-refresh').addEventListener('click', refreshBlacklist);
$('blacklist-key-button').addEventListener('click', async () => {
  const button = $('blacklist-key-button'); button.disabled = true;
  try {
    if (!$('blacklist-key-field').hidden) {
      $('blacklist-key-field').hidden = true; $('blacklist-key').value = ''; button.textContent = '查看专用密钥';
    } else {
      const data = await api('/api/blacklist/key', {});
      if (!data.key) throw new Error('远程黑名单查询已被配置关闭。');
      $('blacklist-key').value = data.key; $('blacklist-key-field').hidden = false;
      button.textContent = '隐藏专用密钥';
    }
  } catch (error) {notice('blacklist-notice', error.message);}
  finally {button.disabled = false;}
});
$('blacklist-copy').addEventListener('click', () => copyText($('blacklist-example').textContent, '调用示例已复制'));
onView();
