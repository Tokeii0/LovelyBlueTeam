(() => {
  'use strict';
  const screen = document.querySelector('#auth-screen');
  const content = document.querySelector('#site-content');
  const input = document.querySelector('#access-password');
  const error = document.querySelector('#auth-error');
  const toggle = document.querySelector('#password-toggle');
  toggle.onclick = () => {
    const visible = input.type === 'password';
    input.type = visible ? 'text' : 'password';
    toggle.setAttribute('aria-pressed', String(visible));
  };
  document.querySelector('#auth-form').onsubmit = async event => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('[type="submit"]');
    button.disabled = true;
    error.textContent = '';
    try {
      const response = await fetch('/api/login', { method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: 'demo', password: input.value }) });
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error('请使用演示口令 demo。');
      screen.hidden = true;
      content.hidden = false;
    } catch (err) { error.textContent = err.message || '服务暂不可用'; }
    finally { input.value = ''; input.type = 'password'; button.disabled = false; }
  };
  document.querySelector('.logout-button').onclick = () => {
    content.hidden = true; screen.hidden = false; input.focus();
  };
})();
