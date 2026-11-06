// Top menu + sidebar source selection. Other modules read `view` and listen for
// the `view-change` event to decide whether their panel is on screen.
import {$} from './ui.js';

export const PAGES = {logs: '日志', ai: 'AI 分析', clean: '清洗规则', rule: '访问规则', blacklist: '黑名单', 'af-logs': 'AF 安全日志', agents: '服务器接入', notify: '告警推送', deep: '深度分析'};
const SOURCE_PAGES = ['logs', 'ai'];
const KEY = 'onepanel-nav';

export const view = {page: 'logs', scope: 'website', agent: ''};
let agents = [], overview = null;

try {
  const saved = JSON.parse(localStorage.getItem(KEY) || '{}');
  if (saved.page in PAGES) view.page = saved.page;
  if (saved.scope === 'server') view.scope = 'server';
  if (typeof saved.agent === 'string') view.agent = saved.agent;
} catch { /* Start on website logs. */ }
const hashPage = location.hash.slice(1);
if (hashPage in PAGES) view.page = hashPage;

export const isActive = (page, scope) => view.page === page && (!scope || view.scope === scope);

const number = value => Number(value || 0).toLocaleString('zh-CN');
const ago = seconds => {
  if (!seconds) return '尚未连接';
  const diff = Math.max(0, Date.now() / 1000 - seconds);
  return diff < 60 ? '刚刚' : diff < 3600 ? `${Math.floor(diff / 60)} 分钟前` : diff < 86400 ? `${Math.floor(diff / 3600)} 小时前` : new Date(seconds * 1000).toLocaleString('zh-CN', {hour12: false});
};
const statusLabel = {online: '在线', waiting: '待接入', offline: '离线', disabled: '已停用'};

function apply() {
  const shell = $('shell');
  shell.dataset.page = view.page;
  shell.dataset.scope = view.scope;
  document.querySelectorAll('main [data-page]').forEach(node => {
    const pages = node.dataset.page.split(' ');
    node.hidden = !pages.includes(view.page) || (!!node.dataset.scope && node.dataset.scope !== view.scope);
  });
  document.querySelectorAll('.menu-item').forEach(item => {
    const active = item.dataset.target === view.page;
    item.classList.toggle('active', active);
    item.setAttribute('aria-selected', String(active));
  });
  document.title = `${PAGES[view.page]} · LovelyLivelog`;
  if (location.hash.slice(1) !== view.page) history.replaceState(null, '', '#' + view.page);
  try { localStorage.setItem(KEY, JSON.stringify(view)); } catch { /* Optional preference. */ }
  renderServers();
  renderServerHeading();
  document.dispatchEvent(new CustomEvent('view-change', {detail: {...view}}));
}

export function navigate(page) {
  if (!(page in PAGES) || page === view.page) return;
  view.page = page;
  apply();
  window.scrollTo({top: 0});
}

// Choosing a source from the sidebar shows its logs unless a source page is already open.
export function selectSource(scope, agent = '') {
  const page = SOURCE_PAGES.includes(view.page) ? view.page : 'logs';
  if (scope === view.scope && agent === view.agent && page === view.page) return;
  Object.assign(view, {scope, agent: scope === 'server' ? agent : view.agent, page});
  apply();
}

function serverButton(agent) {
  const id = agent?.id || '';
  const button = document.createElement('button');
  button.type = 'button';
  const selected = view.scope === 'server' && view.agent === id;
  button.className = `site-button${selected ? ' selected' : ''}`;
  button.setAttribute('aria-pressed', String(selected));
  const dot = document.createElement('span');
  dot.className = `site-dot${!agent ? ' all' : agent.status === 'online' ? '' : ' stopped'}`;
  const content = document.createElement('span');
  const name = document.createElement('span'); name.className = 'site-name';
  const subtitle = document.createElement('span'); subtitle.className = 'site-type';
  if (agent) {
    name.textContent = agent.name;
    subtitle.textContent = `${statusLabel[agent.status] || agent.status} · ${agent.metadata.hostname || '等待首次上传'}`;
  } else {
    name.textContent = '全部服务器';
    subtitle.textContent = `${overview?.online || 0} / ${agents.length} 在线 · ${number(overview?.total)} 条日志`;
  }
  content.append(name, subtitle);
  button.append(dot, content);
  button.addEventListener('click', () => selectSource('server', id));
  return button;
}

function renderServers() {
  const list = $('server-list');
  $('server-count').textContent = agents.length;
  if (!overview) return;
  const query = $('site-search').value.toLocaleLowerCase();
  const matches = agents.filter(agent => `${agent.name} ${agent.metadata.hostname || ''}`.toLocaleLowerCase().includes(query));
  const items = matches.map(serverButton);
  if (agents.length && !query) items.unshift(serverButton(null));
  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'muted sidebar-empty';
    if (agents.length) empty.textContent = '没有匹配的服务器';
    else {
      empty.append('尚未接入服务器 · ');
      const link = document.createElement('button');
      link.type = 'button'; link.className = 'text-button accent'; link.textContent = '立即接入';
      link.addEventListener('click', () => navigate('agents'));
      empty.append(link);
    }
    items.push(empty);
  }
  list.replaceChildren(...items);
}

function renderServerHeading() {
  if (!overview) return;
  const agent = agents.find(item => item.id === view.agent);
  const queue = list => list.reduce((sum, item) => sum + Number(item.metadata.queueDepth || 0), 0);
  if (agent) {
    $('server-title').textContent = agent.name;
    $('server-subtitle').textContent = `${agent.metadata.hostname || '等待代理首次上传'} · 最后心跳 ${ago(agent.last_seen)}`;
    $('server-state').textContent = (statusLabel[agent.status] || agent.status).toUpperCase();
    $('server-state').classList.toggle('stopped', agent.status !== 'online');
    $('server-metric-total').textContent = number(agent.count);
    $('server-metric-online').textContent = statusLabel[agent.status] || agent.status;
    $('server-metric-online-hint').textContent = `最后心跳 ${ago(agent.last_seen)}`;
    $('server-metric-ai').textContent = number(agent.ai?.analyzed);
    $('server-metric-ai-hint').textContent = `待分析 ${number(agent.ai?.pending)} · 攻击 ${number(agent.ai?.attacks)}`;
    $('server-metric-queue').textContent = number(queue([agent]));
  } else {
    $('server-title').textContent = '全部服务器';
    $('server-subtitle').textContent = agents.length ? `${agents.length} 台服务器 · ${overview.online} 台在线` : '尚未接入服务器，在“服务器接入”中添加。';
    $('server-state').textContent = '';
    $('server-metric-total').textContent = number(overview.total);
    $('server-metric-online').textContent = `${overview.online} / ${agents.length}`;
    $('server-metric-online-hint').textContent = '最近 90 秒有心跳';
    $('server-metric-ai').textContent = number(agents.reduce((sum, item) => sum + Number(item.ai?.analyzed || 0), 0));
    $('server-metric-ai-hint').textContent = `攻击判断 ${number(agents.reduce((sum, item) => sum + Number(item.ai?.attacks || 0), 0))}`;
    $('server-metric-queue').textContent = number(queue(agents));
  }
  $('server-metric-online').classList.toggle('accent', agent ? agent.status === 'online' : overview.online > 0);
}

document.addEventListener('hub-overview', event => {
  overview = event.detail;
  agents = overview.agents;
  // A removed server falls back to the combined view.
  if (view.agent && !agents.some(agent => agent.id === view.agent)) { view.agent = ''; apply(); return; }
  renderServers();
  renderServerHeading();
});
document.querySelectorAll('.menu-item').forEach(item => item.addEventListener('click', () => navigate(item.dataset.target)));
$('site-list').addEventListener('click', event => { if (event.target.closest('.site-button')) selectSource('website'); });
$('site-search').addEventListener('input', renderServers);
$('sidebar-add-agent').addEventListener('click', () => { navigate('agents'); $('add-agent').click(); });
for (const id of ['hub-agent-filter', 'hub-ai-agent-filter']) {
  $(id).addEventListener('change', () => selectSource('server', $(id).value));
}
window.addEventListener('hashchange', () => navigate(location.hash.slice(1)));

apply();
