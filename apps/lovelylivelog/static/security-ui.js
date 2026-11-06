import {isActive} from './nav.js';

const $ = id => document.getElementById(id);
let current = null, refreshing = false;
const history = {page: 1, pageSize: 20, verdict: 'all', through: null};
let historyRevision = 0, refreshAgain = false, latestWafCheck = 0;
let providerDrafts = {}, editingProvider = null, fallbackDrafts = {}, editingFallback = null;

async function api(path, body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45000);
  try {
    const response = await fetch(path, {cache: 'no-store', signal: controller.signal,
      ...(body === undefined ? {} : {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '操作失败，请重试。');
    return data;
  } catch (error) {
    if (error.name === 'AbortError' || error instanceof TypeError) throw new Error('连接超时或本机程序未启动，请刷新后重试。');
    throw error;
  } finally { clearTimeout(timer); }
}

function message(text) {
  $('ai-notice').hidden = !text;
  $('ai-notice').textContent = text;
}

export const categories = {none:'正常流量',sql_injection:'SQL 注入',xss:'XSS',rce:'命令执行',path_traversal:'路径穿越',scanner:'漏洞扫描',credential_attack:'撞库 / 暴力尝试',ddos:'拒绝服务',other:'其他攻击'};
export const states = {normal:'正常 · 未加黑',review:'待复核',listed:'已加入全局名单',inactive:'已加入 · 当时 WAF 未就绪',existing:'已有黑名单',failed:'加黑失败',protected:'已保护',unblocked:'已移除并保护',removed:'已移出黑名单',submitting:'正在加入'};
const timeFormat = new Intl.DateTimeFormat('zh-CN', {year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
export const formatTime = timestamp => timestamp ? timeFormat.format(new Date(timestamp * 1000)) : '—';
export const providerName = provider => ({local: '本地正则', jev: 'OpenRouter · Jev', deepseek: 'DeepSeek', openai: '兼容 API'}[provider] || provider || 'AI');
export const isLocalMode = config => config?.analysisMode === 'local';
export const verdictName = item => item.provider === 'local'
  ? item.attack ? `规则命中 · ${categories[item.category] || item.category}` : '未命中规则'
  : item.attack ? categories[item.category] || item.category : '正常流量';
export const verdictScore = item => item.provider === 'local' ? '' : ` · ${Math.round(item.confidence * 100)}%`;
export const stateName = item => item.provider === 'local' && item.state === 'normal'
  ? '未命中 · 未加黑' : states[item.state] || item.state;

export function renderDetectionMode(config, scope = 'panel') {
  const local = isLocalMode(config);
  $('analysis-menu-label').textContent = '流量分析';
  $('ai-settings').textContent = $('hub-open-ai-settings').textContent = '平台 AI 设置';
  if (scope === 'agent') {
    const platform = config.platformAnalysisMode === 'ai' ? '平台其他来源继续使用 AI' : '其他来源沿用平台配置';
    $('hub-ai-title').textContent = local ? '此来源本地规则检测' : '服务器 AI 分析';
    $('hub-ai-attack-label').textContent = local ? '规则命中 / 历史攻击' : '攻击判断';
    $('hub-ai-verdict-heading').textContent = local ? '规则匹配结果' : '判断 / 置信度';
    $('hub-ai-mode-description').textContent = local ? `此来源使用本地正则，不调用 AI · ${platform} · 规则命中仅供复核，手动选择封禁`
      : '访问日志使用平台 AI 配置 · 达标后加入 WAF 全局黑名单 · 历史记录保留供复核';
    $('hub-ai-footer-policy').textContent = local ? '沿用保护名单 · 此来源规则命中仅供复核，手动选择封禁'
      : '沿用保护名单 · 自动加黑至少需 2 次近期攻击请求';
  } else {
    $('ai-title').textContent = local ? '网站流量检测' : '网站 AI 分析';
    $('ai-enabled-label').textContent = local ? '平台本地正则检测' : '平台 AI 自动分析';
    $('ai-attack-label').textContent = local ? '规则命中 / 历史攻击' : '攻击判断';
    $('ai-verdict-heading').textContent = local ? '规则匹配结果' : '判断 / 置信度';
    $('ai-mode-description').textContent = local ? '平台默认使用本地正则 · 规则命中仅供复核，手动选择封禁'
      : '分析 1Panel 网站访问日志 · LovelyLog 本地规则来源单独处理 · 手动加黑对所有启用 WAF 的网站生效';
  }
  if (isActive('ai', scope === 'agent' ? 'server' : 'website')) document.title = `${local ? '本地规则检测' : 'AI 分析'} · LovelyLivelog`;
}

function renderWaf(waf) {
  if ((waf.checkedAt || 0) < latestWafCheck) return;
  latestWafCheck = waf.checkedAt || 0;
  $('ai-health-message').textContent = waf.message;
  $('ai-health').classList.toggle('ready', waf.enabled === true && waf.blacklistEnabled === true && waf.healthy === true);
  const on = value => value === true ? '已开启' : value === false ? '已关闭' : '未知';
  const health = waf.healthy === true ? '通过' : waf.healthy === false ? '未通过' : '未知';
  $('ai-health-detail').textContent = `总开关：${on(waf.enabled)} · IP 黑名单：${on(waf.blacklistEnabled)} · 健康检查：${health} · 检查时间：${formatTime(waf.checkedAt)} · 每 10 秒检查`;
}

export function detail(item) {
  const evidence = item.evidence.map(event => `${event.id<0 ? '代理记录 A'+(-event.id) : '网站记录 #'+event.id}${event.source_file ? '\n来源文件：'+event.source_file : ''}\n${event.raw}`).join('\n\n');
  const model = providerName(item.provider);
  const facts = item.modelFacts || {};
  const origin = item.source_type==='agent' ? `服务器：${item.source_name}\n来源文件：${item.source_file}` : `网站：#${item.website}`;
  const probabilities = item.provider === 'jev' ? `\n攻击概率：${(100 * facts.attackProbability).toFixed(1)}%\n分类置信度：${(100 * facts.categoryConfidence).toFixed(1)}%\n分类概率：${(100 * facts.categoryProbability).toFixed(1)}%` : '';
  const local = item.provider === 'local';
  const score = local ? '' : `\n判定分数：${Math.round(item.confidence * 100)}%${probabilities}`;
  const rules = local && (facts.rules || facts.findings) ? `\n规则与脱敏片段：\n${JSON.stringify({rules: facts.rules, findings: facts.findings}, null, 2)}` : '';
  $('ai-detail-content').textContent = `检测记录：#${item.id}\n检测时间：${formatTime(item.created)}\n${local ? '检测方式' : '模型'}：${model}${item.model ? ' / ' + item.model : ''}\n覆盖日志：${item.record_count || '早期记录未计数'} 条\nIP：${item.ip}\n${origin}\n判断：${verdictName(item)}${score}\n依据：${item.reason}${rules}\n处理：${stateName(item)}\n${item.detail}\n\n证据：${item.evidenceCount} 条（最多展示 10 条原始日志）\n${evidence || '未提供原始证据，或较早的证据已超过本机保留上限。'}`;
  $('ai-detail-dialog').showModal();
}

async function action(button, item, kind) {
  button.disabled = true; message('');
  try { await api(`/api/ai/${kind}`, {id: item.id}); await refresh(); }
  catch (error) { message(error.message); }
  finally { button.disabled = false; }
}

// Token totals as reported by the provider; cache hits are input tokens served from its prefix cache.
function usageText(usage) {
  if (!usage || !usage.requests) return '';
  const hit = usage.prompt ? Math.round(usage.cacheHit * 100 / usage.prompt) : 0;
  return ` · 今日 ${usage.requests.toLocaleString()} 次 API 请求，输入 ${usage.prompt.toLocaleString()} token（供应商缓存命中 ${hit}%），输出 ${usage.completion.toLocaleString()} token`;
}

function render(data) {
  current = data;
  const config = data.settings, summary = data.summary;
  const local = isLocalMode(config);
  renderDetectionMode(config);
  $('ai-enabled').checked = config.enabled;
  $('auto-block').checked = !local && config.autoBlock;
  $('auto-block').disabled = local || !config.enabled;
  $('ai-threshold').textContent = local ? '规则命中仅供复核，手动选择封禁' : `阈值 ${Math.round(config.threshold * 100)}% · 至少 2 条近期证据`;
  $('ai-badge').textContent = `${local ? '本地正则检测' : providerName(config.provider)} · ${!config.configured ? '未填密钥' : !config.enabled ? '已暂停' : config.busy ? '正在检测' : '监听新增'}`;
  $('ai-badge').className = `status-badge${config.configured && config.enabled ? ' success' : ''}`;
  renderWaf(config.waf);
  $('ai-analyzed').textContent = summary.analyzed.toLocaleString();
  $('ai-pending').textContent = summary.pending.toLocaleString();
  $('ai-attacks').textContent = summary.attacks.toLocaleString();
  $('ai-listed').textContent = summary.listed.toLocaleString();
  message(config.lastError || '');
  const perf = config.performance || {};
  const waiting = summary.oldestPendingReceived ? Math.max(0, Math.floor(Date.now() / 1000 - summary.oldestPendingReceived)) : 0;
  $('ai-performance').textContent = `${local ? '本地正则 · 不调用 AI' : `${config.concurrency} 并发`} · 每轮最多 ${config.batchSize.toLocaleString()} 条 · 近 1 分钟处理 ${(perf.processedLastMinute || 0).toLocaleString()} 条${perf.inputRows ? ` · ${config.busy ? '本轮' : '上轮'} ${perf.inputRows} 条${local ? '' : ` → ${perf.samples} 个样本`}${config.busy ? '，处理中' : `，耗时 ${perf.duration} 秒`}` : ''}${waiting ? ` · 最早等待 ${waiting} 秒` : ''}${local ? '' : usageText(config.usageToday)}`;
  const localCache = config.localCacheToday || {};
  if (!local && config.cacheError) $('ai-performance').textContent += ` · ${config.cacheError}`;
  if (!local && localCache.rows) $('ai-performance').textContent += ` · 今日本地复用 ${localCache.rows.toLocaleString()} 条，${localCache.hits.toLocaleString()} 次判定`;
  if (!local && perf.inputRows && !config.busy) $('ai-performance').textContent += ` · 上轮实际调用 ${perf.requests || 0} 次，本地复用 ${perf.cacheRows || 0} 条`;
  if (!local && config.fallbackEnabled) $('ai-performance').textContent += ` · 备用：${providerName(config.fallbackProvider)} / ${config.fallbackModel}`;
  if (!local && config.lastFallback) $('ai-performance').textContent += ` · 最近备用接管：${config.lastFallback.model}（${formatTime(config.lastFallback.at)}）`;
  const earlierSkipped = Math.max(0, (summary.skipped || 0) - (summary.expired || 0) - (summary.unparsed || 0));
  $('ai-skipped').textContent = `跳过 ${(summary.skipped || 0).toLocaleString()} 条（过期 ${(summary.expired || 0).toLocaleString()} · 无法解析 ${(summary.unparsed || 0).toLocaleString()}${earlierSkipped ? ` · 早期跳过 ${earlierSkipped.toLocaleString()}` : ''}）${summary.excluded ? ` · 不参与识别的网站 ${summary.excluded.toLocaleString()} 条` : ''}${summary.filtered ? ` · 按日清洗后仅存档 ${summary.filtered.toLocaleString()} 组` : ''}；原始日志仍保留`;
  const info = data.history;
  history.page = info.page;
  history.through = info.through;
  $('ai-history-count').textContent = `共 ${info.allTotal.toLocaleString()} 次判断 · 未命中 / 正常 ${info.normalTotal.toLocaleString()} · 命中 / 攻击判断 ${info.attackTotal.toLocaleString()}`;
  $('ai-history-page').textContent = `第 ${info.page} / ${info.pages} 页 · ${info.total.toLocaleString()} 条结果`;
  $('ai-history-prev').disabled = info.page <= 1;
  $('ai-history-next').disabled = info.page >= info.pages;
  $('ai-empty').hidden = data.decisions.length > 0;
  $('ai-empty').textContent = info.allTotal > 0 ? '该筛选下暂无检测结果，可切换到全部结果查看。' : local ? '新增访问日志经本地规则检查后显示结果。未命中规则不代表已确认安全。' : !config.configured ? '在 AI 设置中填写 API 密钥后，流量分析结果会显示在这里。' : '暂无分析历史，新增访问日志分析完成后将显示结果。';
  const fragment = document.createDocumentFragment();
  for (const item of data.decisions) {
    const tr = document.createElement('tr');
    tr.dataset.decisionId = item.id;
    tr.dataset.attack = String(!!item.attack);
    const verdict = verdictName(item);
    const source = `${providerName(item.provider)}${item.model ? ' / ' + item.model : ''}`;
    const contents = [formatTime(item.created), `${item.ip}\n${item.source_type==='agent' ? '服务器 '+item.source_name : '网站 #'+item.website}`, `${verdict}${verdictScore(item)}\n${source}${item.record_count ? ` · ${item.record_count} 条` : ''}${item.historical ? `\n历史${item.state === 'review' ? ' · 仅复核' : ''}` : ''}`, item.reason, stateName(item)];
    contents.forEach((text, index) => {
      const td = document.createElement('td'); td.textContent = text;
      td.title = index === 4 ? item.detail || text : text;
      if (index === 1) td.dataset.geoIp = item.ip;
      if (index === 2) td.className = item.attack ? 'attack-verdict' : 'normal-verdict';
      if (index === 4) td.className = item.state === 'normal' || ['listed','existing'].includes(item.state) ? 'accent' : 'muted';
      tr.append(td);
    });
    const actions = document.createElement('td'); actions.className = 'ai-actions';
    const evidence = document.createElement('button'); evidence.className = 'text-button'; evidence.textContent = '查看依据';
    evidence.addEventListener('click', () => detail(item)); actions.append(evidence);
    if (item.attack && ['review','failed','unblocked','removed'].includes(item.state)) {
      const block = document.createElement('button'); block.className = 'text-button accent'; block.textContent = '加入黑名单';
      block.addEventListener('click', () => action(block, item, 'block')); actions.append(block);
    }
    if (item.attack && item.canUnblock) {
      const unblock = document.createElement('button'); unblock.className = 'text-button'; unblock.textContent = '移除并保护';
      unblock.addEventListener('click', () => action(unblock, item, 'unblock')); actions.append(unblock);
    }
    tr.append(actions); fragment.append(tr);
  }
  $('ai-decisions').replaceChildren(fragment);
}

async function refresh() {
  if (refreshing) { refreshAgain = true; return; }
  refreshing = true;
  const revision = historyRevision;
  const params = new URLSearchParams({source: 'panel', page: history.page, pageSize: history.pageSize, verdict: history.verdict});
  if (history.page > 1 && history.through !== null) params.set('through', history.through);
  try {
    const data = await api(`/api/ai?${params}`);
    if (revision === historyRevision) render(data);
  }
  catch (error) { message(error.message); }
  finally {
    refreshing = false;
    if (refreshAgain || revision !== historyRevision) { refreshAgain = false; refresh(); }
  }
}

function changeHistory(change) {
  Object.assign(history, change);
  historyRevision++;
  refresh();
}
$('ai-verdict-filter').addEventListener('change', () => changeHistory({verdict: $('ai-verdict-filter').value, page: 1, through: null}));
$('ai-history-size').addEventListener('change', () => changeHistory({pageSize: Number($('ai-history-size').value), page: 1, through: null}));
$('ai-history-refresh').addEventListener('click', () => { message(''); changeHistory({page: 1, through: null}); });
$('ai-history-prev').addEventListener('click', () => changeHistory({page: Math.max(1, history.page - 1)}));
$('ai-history-next').addEventListener('click', () => changeHistory({page: history.page + 1}));
$('check-waf').addEventListener('click', async () => {
  const button = $('check-waf'); button.disabled = true; button.textContent = '正在检查…';
  try {
    const data = await api('/api/ai/waf');
    renderWaf(data.waf);
    if (current) current.settings.waf = data.waf;
  } catch (error) { message(error.message); }
  finally { button.disabled = false; button.textContent = '↻ 重新检查'; }
});

function providerFields() {
  if (editingProvider) providerDrafts[editingProvider] = {key: $('deepseek-key').value,
    model: $('deepseek-model').value, baseUrl: $('ai-base-url').value, configured: providerDrafts[editingProvider].configured};
  const provider = $('ai-provider').value, draft = providerDrafts[provider];
  editingProvider = provider;
  const jev = provider === 'jev';
  $('deepseek-key').value = draft.key;
  $('ai-key-label').textContent = provider === 'openai' ? 'API 密钥' : `${jev ? 'OpenRouter' : 'DeepSeek'} API 密钥`;
  $('deepseek-key').placeholder = draft.configured ? '已有密钥；留空保留，填写新值替换' : '填写该服务的 API Key';
  $('deepseek-model').value = draft.model;
  $('ai-base-url').value = draft.baseUrl;
  $('ai-base-url-field').hidden = jev;
  $('ai-base-url').disabled = jev;
  $('ai-provider-hint').textContent = jev ? '使用 OpenRouter 决策接口。Jev 返回类别与概率；历史依据由真实日志样本和计数组成。' : provider === 'deepseek' ? 'DeepSeek 返回中文判断依据；使用聚合样本和并发处理加速。' : '填写服务商提供的 API 地址、密钥和模型名。支持 Chat Completions 与 JSON 输出的兼容服务。';
}
function fallbackFields() {
  if (editingFallback) fallbackDrafts[editingFallback] = {key: $('ai-fallback-key').value,
    model: $('ai-fallback-model').value, baseUrl: $('ai-fallback-base-url').value, configured: fallbackDrafts[editingFallback].configured};
  const provider = $('ai-fallback-provider').value, draft = fallbackDrafts[provider];
  editingFallback = provider;
  $('ai-fallback-key').value = draft.key;
  $('ai-fallback-key').placeholder = draft.configured ? '已有备用密钥；留空保留，填写新值替换' : '填写备用服务的 API Key';
  $('ai-fallback-model').value = draft.model;
  $('ai-fallback-base-url').value = draft.baseUrl;
}
function toggleFallback() {
  const enabled = $('analysis-mode').value !== 'local' && $('ai-fallback-enabled').checked;
  $('ai-fallback-fields').hidden = !enabled;
  for (const field of $('ai-fallback-fields').querySelectorAll('input, select')) field.disabled = !enabled;
  $('ai-fallback-model').required = enabled;
  $('ai-fallback-base-url').required = enabled;
  $('ai-fallback-key').required = enabled && !fallbackDrafts[$('ai-fallback-provider').value].configured;
}
function modeFields() {
  const local = $('analysis-mode').value === 'local';
  $('ai-model-fields').hidden = local;
  for (const field of $('ai-model-fields').querySelectorAll('input, select')) field.disabled = local;
  for (const label of document.querySelectorAll('[data-ai-setting]')) {
    label.hidden = local;
    for (const field of label.querySelectorAll('input, select')) field.disabled = local;
  }
  if (!local) $('ai-base-url').disabled = $('ai-provider').value === 'jev';
  toggleFallback();
  $('analysis-mode-hint').textContent = local ? '平台默认使用本地规则，不调用 AI，命中后人工复核。此处不会改变 LovelyLog 的独立设置。'
    : '平台默认使用所选 AI 服务，产生 API 费用。LovelyLog 独立本地来源继续使用规则，不调用主模型或备用模型。';
  $('settings-block-policy').textContent = local ? '本地模式关闭自动封禁。规则命中仅供复核，手动选择封禁。WAF 总开关由你在 1Panel 中管理。'
    : '自动加黑至少需要 2 条近期证据。模型判断可供人工复核；WAF 总开关由你在 1Panel 中管理。';
}
$('analysis-mode').addEventListener('change', modeFields);
$('ai-provider').addEventListener('change', providerFields);
$('ai-fallback-provider').addEventListener('change', () => { fallbackFields(); toggleFallback(); });
$('ai-fallback-enabled').addEventListener('change', toggleFallback);
function populatePlatformSettings(config) {
  providerDrafts = {
    deepseek: {key: '', model: config.deepseekModel, baseUrl: config.deepseekBaseUrl, configured: config.deepseekConfigured},
    jev: {key: '', model: config.jevModel, baseUrl: '', configured: config.jevConfigured},
    openai: {key: '', model: config.openaiModel, baseUrl: config.openaiBaseUrl, configured: config.openaiConfigured}
  };
  fallbackDrafts = {
    deepseek: {key: '', model: 'deepseek-flash', baseUrl: 'https://api.deepseek.com', configured: false},
    openai: {key: '', model: '', baseUrl: 'https://api.openai.com/v1', configured: false}
  };
  fallbackDrafts[config.fallbackProvider] = {key: '', model: config.fallbackModel,
    baseUrl: config.fallbackBaseUrl, configured: config.fallbackConfigured};
  editingProvider = editingFallback = null;
  $('analysis-mode').value = isLocalMode(config) ? 'local' : 'ai';
  $('ai-provider').value = config.provider;
  providerFields();
  $('ai-fallback-provider').value = config.fallbackProvider;
  $('ai-fallback-enabled').checked = config.fallbackEnabled;
  fallbackFields(); toggleFallback();
  $('ai-batch-size').value = config.batchSize;
  $('ai-concurrency').value = config.concurrency;
  $('ai-idle-interval').value = config.interval;
  $('deepseek-threshold').value = Math.round(config.threshold * 100);
  $('ip-allowlist').value = config.allowlist;
  $('allow-private').checked = config.allowPrivate;
  modeFields();
  $('settings-error').hidden = true;
  $('ai-settings-dialog').showModal();
}
export async function openPlatformSettings() {
  $('ai-settings').disabled = $('hub-open-ai-settings').disabled = true;
  try {
    // Source overrides must never populate a form that writes platform settings.
    const data = await api('/api/ai?source=panel');
    if (!data.settings || data.settings.analysisScope === 'agent') throw new Error('未取得平台设置，请刷新后重试。');
    current = current ? {...current, settings: data.settings} : {settings: data.settings};
    populatePlatformSettings(data.settings);
  } catch (error) {
    message(error.message);
    $('hub-ai-notice').hidden = false; $('hub-ai-notice').textContent = error.message;
  } finally { $('ai-settings').disabled = $('hub-open-ai-settings').disabled = false; }
}
$('ai-settings').addEventListener('click', openPlatformSettings);
$('close-ai-settings').addEventListener('click', () => $('ai-settings-dialog').close());
$('close-ai-detail').addEventListener('click', () => $('ai-detail-dialog').close());
$('ai-settings-form').addEventListener('submit', async event => {
  event.preventDefault(); $('save-ai-settings').disabled = true; $('settings-error').hidden = true;
  try {
    const body = {analysisMode: $('analysis-mode').value, batchSize: Number($('ai-batch-size').value),
      interval: Number($('ai-idle-interval').value), allowlist: $('ip-allowlist').value.trim(), allowPrivate: $('allow-private').checked};
    if (body.analysisMode === 'local') body.autoBlock = false;
    else {
      Object.assign(body, {provider: $('ai-provider').value, key: $('deepseek-key').value.trim(),
        model: $('deepseek-model').value.trim(), concurrency: Number($('ai-concurrency').value),
        threshold: Number($('deepseek-threshold').value) / 100, fallbackEnabled: $('ai-fallback-enabled').checked});
      if (body.provider !== 'jev') body.baseUrl = $('ai-base-url').value.trim();
      if (body.fallbackEnabled) Object.assign(body, {fallbackProvider: $('ai-fallback-provider').value,
        fallbackKey: $('ai-fallback-key').value.trim(), fallbackModel: $('ai-fallback-model').value.trim(),
        fallbackBaseUrl: $('ai-fallback-base-url').value.trim()});
    }
    await api('/api/ai/settings', body);
    $('ai-settings-dialog').close(); message(''); await refresh();
  } catch (error) { $('settings-error').hidden = false; $('settings-error').textContent = error.message; }
  finally { $('save-ai-settings').disabled = false; }
});
$('ai-settings-dialog').addEventListener('close', () => {
  $('deepseek-key').value = ''; $('ai-fallback-key').value = '';
  providerDrafts = {}; fallbackDrafts = {}; editingProvider = editingFallback = null;
});
for (const [id, field] of [['ai-enabled','enabled'], ['auto-block','autoBlock']]) {
  $(id).addEventListener('change', async () => {
    if (field === 'autoBlock' && isLocalMode(current?.settings)) {
      $(id).checked = false; $(id).disabled = true;
      message('规则命中仅供复核，手动选择封禁'); return;
    }
    $(id).disabled = true;
    try { await api('/api/ai/settings', {[field]: $(id).checked}); message(''); }
    catch (error) { message(error.message); }
    finally { $(id).disabled = id === 'auto-block' && isLocalMode(current?.settings); await refresh(); }
  });
}
refresh();
api('/api/config').then(config => { $('open-waf').href = new URL('/xpack/waf/global', config.panelUrl).href; }).catch(() => {});
// Settings load once for the shared AI settings dialog; history polls only while its page is open.
const onScreen = () => isActive('ai', 'website');
document.addEventListener('view-change', () => { if (onScreen()) refresh(); });
setInterval(() => { if (!document.hidden && onScreen()) refresh(); }, 4000);
document.addEventListener('visibilitychange', () => { if (!document.hidden && onScreen()) refresh(); });
