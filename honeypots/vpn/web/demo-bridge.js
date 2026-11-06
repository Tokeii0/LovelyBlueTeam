// Browser-only adapter for the original WebView UI. No native host bridge.
(() => {
  const state = { state: 'idle', network: '隔离演示', config: { proxy: '' } };
  let generation = 0;
  const update = values => { Object.assign(state, values); window.ui?.state({ ...state }); };
  const post = async (path, body) => {
    const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error(data.error || '演示请求失败');
    return data;
  };
  window.demoSend = async (command, extra = {}) => {
    if (command === 'ready') {
      if (window.ui) { window.ui.init({ version: '1.0.0-demo', appName: 'Lovely VPN · 演示' }); update({}); }
      if (window.nav) window.nav.init({ title: '合成资源导航', user: '示例用户', ip: '192.0.2.10', resources: [
        { name: 'HIS 演示', desc: '仅展示，不连接业务系统', group: '临床业务', icon: 'his', url: '' },
        { name: 'LIS 演示', desc: '合成检验接口', group: '医技系统', icon: 'lis', url: '' },
        { name: 'OA 演示', desc: '合成办公入口', group: '办公协同', icon: 'oa', url: '' }
      ] });
    } else if (command === 'login') {
      try { const result = await post('/api/login', { user: extra.jobId, password: extra.password }); window.ui.loginResult(result); }
      catch (err) { window.ui.loginResult({ ok: false, error: err.message }); }
      finally { document.getElementById('pwd').value = ''; }
    } else if (command === 'toggle') {
      const current = ++generation;
      if (state.state !== 'idle') { update({ state: 'idle', ip: '', since: 0 }); return; }
      update({ state: 'busy', error: '' });
      try {
        const data = await post('/api/connect', { scenario: 'demo' });
        if (current === generation) update({ state: 'connected', user: data.user, ip: data.ip, since: Date.now() });
      } catch (err) { if (current === generation) update({ state: 'idle', error: err.message }); }
    } else if (command === 'nav') { window.open('/resources', '_blank', 'noopener'); }
    else if (command === 'save') { state.config.proxy = '演示模式'; window.ui.saved({ ok: true }); }
    // Resource cards are illustrative. Window controls and "open" are no-ops.
  };
})();
