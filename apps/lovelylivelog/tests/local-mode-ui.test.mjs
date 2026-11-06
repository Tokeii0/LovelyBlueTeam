import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';

const html = await readFile(new URL('../static/index.html', import.meta.url), 'utf8');
const security = await readFile(new URL('../static/security-ui.js', import.meta.url), 'utf8');
const hub = await readFile(new URL('../static/hub-ai-ui.js', import.meta.url), 'utf8');
const stripModule = source => source.replace(/^import .*;\r?$/gm, '').replace(/^export /gm, '');

class Node {
  constructor() {this.value = ''; this.checked = false; this.disabled = false; this.hidden = false;
    this.textContent = ''; this.children = []; this.dataset = {}; this.listeners = {}; this.fields = [];
    this.classList = {toggle() {}};}
  addEventListener(type, handler) {(this.listeners[type] ||= []).push(handler);}
  append(...items) {this.children.push(...items);}
  replaceChildren(...items) {this.children = items[0]?.fragment ? items[0].children : items;}
  querySelectorAll() {return this.fields;}
  showModal() {this.open = true;}
  close() {this.open = false; for (const handler of this.listeners.close || []) handler();}
}

function fixture() {
  const ids = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(match => [match[1], new Node()]));
  const $ = id => {assert.ok(ids.has(id), `Missing HTML element ${id}`); return ids.get(id);};
  const aiFields = ['ai-provider', 'ai-base-url', 'deepseek-key', 'deepseek-model', 'ai-fallback-enabled',
    'ai-fallback-provider', 'ai-fallback-key', 'ai-fallback-model', 'ai-fallback-base-url'];
  $('ai-model-fields').fields = aiFields.map($);
  $('ai-fallback-fields').fields = aiFields.slice(5).map($);
  const labels = ['ai-concurrency', 'deepseek-threshold'].map(id => {const label = new Node(); label.fields = [$(id)]; return label;});
  const document = {getElementById: $, addEventListener() {}, querySelectorAll: () => labels,
    createElement: () => new Node(), createDocumentFragment: () => Object.assign(new Node(), {fragment: true})};
  const context = vm.createContext({document, Intl, Date, URL, URLSearchParams, AbortController,
    setTimeout: () => 0, clearTimeout() {}, setInterval() {}, isActive: () => false,
    fetch: path => path === '/api/ai?source=panel'
      ? Promise.resolve({ok: true, json: async () => data({analysisMode: 'ai'})}) : new Promise(() => {})});
  vm.runInContext(stripModule(security) + '\nglobalThis.ui={render,detail,modeFields,formatTime,providerName,isLocalMode,verdictName,verdictScore,stateName,renderDetectionMode,openPlatformSettings};', context);
  return {$, document, context, ui: context.ui};
}

function data(changes = {}) {
  return {settings: {analysisMode: 'local', platformAnalysisMode: 'ai', provider: 'deepseek', configured: true, enabled: true, autoBlock: true,
    threshold: .95, concurrency: 4, batchSize: 800, interval: 10, allowlist: '', allowPrivate: false,
    deepseekModel: 'deepseek-flash', deepseekBaseUrl: 'https://api.example/v1', deepseekConfigured: true,
    jevModel: 'jev-test', jevConfigured: false, openaiModel: '', openaiBaseUrl: 'https://other.example/v1',
    openaiConfigured: false, fallbackProvider: 'openai', fallbackEnabled: false, fallbackModel: '',
    fallbackBaseUrl: 'https://backup.example/v1', fallbackConfigured: false,
    waf: {message: 'Ready', checkedAt: 1, enabled: true, blacklistEnabled: true, healthy: true}, ...changes},
    summary: {analyzed: 1, pending: 0, attacks: 0, listed: 0},
    history: {page: 1, pages: 1, through: 1, allTotal: 1, normalTotal: 1, attackTotal: 0, total: 1}, decisions: []};
}

function decision(changes = {}) {
  return {id: 1, ip: '8.8.8.8', created: 1000, provider: 'local', model: 'regex-v1', confidence: .99,
    attack: false, category: 'none', reason: '未命中规则', state: 'normal', evidence: [], evidenceCount: 0,
    record_count: 1, source_type: 'agent', source_name: 'fixture', source_file: '/site/post.log', ...changes};
}

test('local verdicts are rule results without AI probabilities or a safe verdict', () => {
  const {ui} = fixture();
  assert.equal(ui.providerName('local'), '本地正则');
  assert.equal(ui.verdictName(decision()), '未命中规则');
  assert.equal(ui.verdictScore(decision()), '');
  assert.equal(ui.stateName(decision()), '未命中 · 未加黑');
  assert.equal(ui.verdictScore(decision({provider: 'deepseek'})), ' · 99%');
});

test('local render disables auto-block even if stale backend data says true', () => {
  const {$, ui} = fixture();
  ui.render(data());
  assert.equal($('auto-block').checked, false);
  assert.equal($('auto-block').disabled, true);
  assert.equal($('analysis-menu-label').textContent, '流量分析');
  assert.equal($('ai-enabled-label').textContent, '平台本地正则检测');
  assert.match($('ai-badge').textContent, /本地正则检测/);
  assert.match($('ai-threshold').textContent, /手动选择封禁/);
  assert.match($('ai-performance').textContent, /不调用 AI/);
});

test('explicit platform local settings hide model inputs and restore them when choosing AI', async () => {
  const {$, ui, context} = fixture();
  ui.render(data());
  context.fetch = async () => ({ok: true, json: async () => data()});
  await $('ai-settings').listeners.click[0]();
  assert.equal($('analysis-mode').value, 'local');
  assert.equal($('ai-model-fields').hidden, true);
  assert.equal($('deepseek-model').disabled, true);
  assert.equal($('ai-base-url').disabled, true);
  $('analysis-mode').value = 'ai';
  ui.modeFields();
  assert.equal($('ai-model-fields').hidden, false);
  assert.equal($('deepseek-model').disabled, false);
  assert.equal($('ai-base-url').disabled, false);
  assert.equal($('ai-fallback-model').disabled, true);
});

test('selected local agent cannot overwrite platform AI controls or the global settings dialog', async () => {
  const {$, ui} = fixture();
  ui.render(data({analysisMode: 'ai'}));
  ui.renderDetectionMode(data({analysisScope: 'agent', scopedAgentId: 'lovelylog'}).settings, 'agent');
  assert.equal($('ai-enabled-label').textContent, '平台 AI 自动分析');
  assert.equal($('auto-block').checked, true);
  assert.equal($('auto-block').disabled, false);
  assert.match($('hub-ai-mode-description').textContent, /此来源.*不调用 AI/);
  assert.match($('hub-ai-mode-description').textContent, /平台其他来源继续使用 AI/);
  await $('ai-settings').listeners.click[0]();
  assert.equal($('analysis-mode').value, 'ai');
  assert.equal($('deepseek-model').disabled, false);
});

test('platform AI history keeps provider probabilities while local rows omit them', () => {
  const {$, ui} = fixture();
  const result = data({analysisMode: 'ai'});
  result.decisions = [decision({provider: 'deepseek', model: 'deepseek-flash'})];
  ui.render(result);
  assert.match($('ai-badge').textContent, /DeepSeek/);
  assert.match($('ai-decisions').children[0].children[2].textContent, /99%/);
  assert.equal($('auto-block').disabled, false);
});

test('opening settings from a local source fetches global AI settings and cannot save its local override', async () => {
  const {$, ui, context} = fixture();
  ui.render(data({analysisMode: 'ai'}));
  ui.renderDetectionMode(data({analysisScope: 'agent', scopedAgentId: 'lovelylog'}).settings, 'agent');
  const requests = [];
  context.fetch = async (path, options) => {
    requests.push({path, body: options?.body ? JSON.parse(options.body) : null});
    return {ok: true, json: async () => path === '/api/ai?source=panel' ? data({analysisMode: 'ai'}) : {}};
  };
  await $('ai-settings').listeners.click[0]();
  await $('ai-settings-form').listeners.submit[0]({preventDefault() {}});
  assert.equal(requests[0].path, '/api/ai?source=panel');
  const saved = requests.find(request => request.path === '/api/ai/settings').body;
  assert.equal(saved.analysisMode, 'ai');
  assert.equal(saved.provider, 'deepseek');
  assert.equal('autoBlock' in saved, false);
  assert.equal('scopedAgentId' in saved, false);
  assert.equal('analysisScope' in saved, false);
});

test('local detail contains rule IDs and evidence snippets without a confidence percentage', () => {
  const {$, ui} = fixture();
  ui.detail(decision({attack: true, category: 'sql_injection', state: 'review',
    modelFacts: {rules: ['SQL-001'], findings: [{snippet: 'union select'}]}}));
  assert.match($('ai-detail-content').textContent, /SQL-001/);
  assert.match($('ai-detail-content').textContent, /union select/);
  assert.match($('ai-detail-content').textContent, /规则命中/);
  assert.doesNotMatch($('ai-detail-content').textContent, /判定分数|99%/);
});

test('server rule hits retain the manual blacklist action without showing probabilities', () => {
  const {$, ui, document} = fixture();
  const context = vm.createContext({document, Intl, Date, URLSearchParams, AbortSignal, setTimeout: () => 0,
    clearTimeout() {}, isActive: () => false, view: {agent: ''}, copyText() {}, ...ui});
  vm.runInContext(stripModule(hub) + '\nglobalThis.renderHub=render;', context);
  const result = data();
  result.decisions = [decision({attack: true, category: 'sql_injection', state: 'review'})];
  context.renderHub(result);
  const row = $('hub-ai-decisions').children[0];
  assert.match(row.children[2].textContent, /规则命中/);
  assert.doesNotMatch(row.children[2].textContent, /99%/);
  assert.ok(row.children[5].children.some(node => node.textContent === '加入黑名单'));
  assert.match($('hub-ai-policy').textContent, /手动选择封禁/);
  assert.match($('hub-ai-policy').textContent, /不调用 AI/);
  assert.match($('hub-ai-policy').textContent, /平台其他来源继续使用 AI/);
});

test('server platform-settings button loads the platform endpoint rather than agent overrides', async () => {
  const {$, ui, document, context: platform} = fixture();
  ui.render(data({analysisMode: 'ai'}));
  const context = vm.createContext({document, Intl, Date, URLSearchParams, AbortSignal, setTimeout: () => 0,
    clearTimeout() {}, isActive: () => false, view: {agent: 'lovelylog'}, copyText() {}, ...ui});
  vm.runInContext(stripModule(hub) + '\nglobalThis.renderHub=render;', context);
  context.renderHub(data({analysisScope: 'agent', scopedAgentId: 'lovelylog'}));
  const calls = [];
  platform.fetch = async path => {
    calls.push(path);
    return {ok: true, json: async () => data({analysisMode: 'ai'})};
  };
  await $('hub-open-ai-settings').listeners.click[0]();
  assert.deepEqual(calls, ['/api/ai?source=panel']);
  assert.equal($('analysis-mode').value, 'ai');
  assert.equal($('deepseek-model').disabled, false);
});
