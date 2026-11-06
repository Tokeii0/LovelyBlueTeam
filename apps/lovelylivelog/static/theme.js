// Loaded synchronously in <head> so the saved theme applies before first paint.
(() => {
  const KEY = 'onepanel-theme', choices = ['system', 'light', 'dark'];
  const root = document.documentElement;
  const media = window.matchMedia('(prefers-color-scheme: light)');
  let choice = 'system';
  try { choice = localStorage.getItem(KEY) || 'system'; } catch { /* Theme still follows the system. */ }
  if (!choices.includes(choice)) choice = 'system';

  function apply() {
    root.dataset.theme = choice === 'system' ? (media.matches ? 'light' : 'dark') : choice;
    root.dataset.themeChoice = choice;
    document.querySelectorAll('[data-theme-option]').forEach(button => {
      const active = button.dataset.themeOption === choice;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
  }
  function set(next) {
    choice = choices.includes(next) ? next : 'system';
    try { localStorage.setItem(KEY, choice); } catch { /* Applies for this page only. */ }
    apply();
  }

  media.addEventListener('change', () => { if (choice === 'system') apply(); });
  window.onepanelTheme = {
    get: () => choice,
    set,
    cycle() { set(choices[(choices.indexOf(choice) + 1) % choices.length]); return choice; },
  };
  apply();
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-theme-option]').forEach(button =>
      button.addEventListener('click', () => set(button.dataset.themeOption)));
    apply();
  });
})();
