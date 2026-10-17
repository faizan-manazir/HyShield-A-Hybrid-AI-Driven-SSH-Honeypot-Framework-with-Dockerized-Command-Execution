(() => {
  'use strict';
  const KEY = 'hyshield.appearance.v1';
  const defaults = { theme: 'dark', accent: 'cyan', density: 'comfortable' };
  const valid = {
    theme: ['dark', 'light', 'system'],
    accent: ['cyan', 'blue', 'violet', 'green'],
    density: ['comfortable', 'compact']
  };
  let prefs = { ...defaults };
  try {
    const saved = JSON.parse(localStorage.getItem(KEY) || '{}');
    for (const key of Object.keys(valid)) {
      if (valid[key].includes(saved[key])) prefs[key] = saved[key];
    }
  } catch (_) { /* Private browsing/storage restrictions fall back to defaults. */ }

  const systemDark = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  function apply() {
    const resolved = prefs.theme === 'system' ? (systemDark && systemDark.matches ? 'dark' : 'light') : prefs.theme;
    document.body.dataset.theme = resolved;
    document.body.dataset.accent = prefs.accent;
    document.body.dataset.density = prefs.density;
    document.querySelectorAll('[data-theme-choice]').forEach((button) => {
      button.setAttribute('aria-pressed', String(button.dataset.themeChoice === prefs.theme));
    });
    document.querySelectorAll('[data-accent-choice]').forEach((button) => {
      button.setAttribute('aria-pressed', String(button.dataset.accentChoice === prefs.accent));
    });
    document.querySelectorAll('[data-density-choice]').forEach((button) => {
      button.setAttribute('aria-pressed', String(button.dataset.densityChoice === prefs.density));
    });
  }
  function persist(message) {
    try {
      localStorage.setItem(KEY, JSON.stringify(prefs));
      const status = document.getElementById('appearance-status');
      if (status) status.textContent = message || 'Preferences saved in this browser.';
    } catch (_) {
      const status = document.getElementById('appearance-status');
      if (status) status.textContent = 'Preferences apply for this session, but browser storage is unavailable.';
    }
  }
  document.addEventListener('click', (event) => {
    const theme = event.target.closest('[data-theme-choice]');
    const accent = event.target.closest('[data-accent-choice]');
    const density = event.target.closest('[data-density-choice]');
    const reset = event.target.closest('#reset-appearance');
    if (theme) { prefs.theme = theme.dataset.themeChoice; apply(); persist(); }
    if (accent) { prefs.accent = accent.dataset.accentChoice; apply(); persist(); }
    if (density) { prefs.density = density.dataset.densityChoice; apply(); persist(); }
    if (reset) {
      prefs = { ...defaults };
      apply();
      persist('Appearance reset to defaults.');
    }
  });
  if (systemDark && systemDark.addEventListener) {
    systemDark.addEventListener('change', () => { if (prefs.theme === 'system') apply(); });
  }
  apply();
})();