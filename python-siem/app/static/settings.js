(() => {
  'use strict';

  document.addEventListener('submit', async (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;

    const action = new URL(form.action, window.location.href);
    if (action.origin !== window.location.origin) return;
    if (!['/settings', '/settings/purge'].includes(action.pathname)) return;

    event.preventDefault();
    if (!form.reportValidity()) return;

    const button = event.submitter || form.querySelector('button[type="submit"], button:not([type])');
    const originalText = button?.textContent || '';
    if (button) {
      button.disabled = true;
      button.textContent = 'Saving…';
    }

    try {
      const response = await fetch(action.href, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
          'Accept': 'text/html',
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        },
        body: new URLSearchParams(new FormData(form)).toString()
      });

      if (response.redirected) {
        window.location.assign(response.url);
        return;
      }

      const type = response.headers.get('content-type') || '';
      if (type.includes('text/html')) {
        const html = await response.text();
        const parsed = new DOMParser().parseFromString(html, 'text/html');
        const main = parsed.querySelector('main');
        const current = document.querySelector('main');
        if (main && current) {
          current.replaceWith(main);
          const notice = main.querySelector('[role="alert"]');
          if (notice) notice.scrollIntoView({ block: 'center' });
          return;
        }
      }

      showError(`Settings could not be saved (HTTP ${response.status}).`);
    } catch (_error) {
      showError('Could not save settings. Check that the SIEM server is running, then try again.');
    } finally {
      if (button && button.isConnected) {
        button.disabled = false;
        button.textContent = originalText;
      }
    }
  });

  function showError(message) {
    let alert = document.querySelector('[data-settings-error]');
    if (!alert) {
      alert = document.createElement('div');
      alert.className = 'danger-zone';
      alert.setAttribute('role', 'alert');
      alert.setAttribute('data-settings-error', '');
      document.querySelector('.page-head')?.after(alert);
    }
    if (alert) alert.textContent = message;
  }
})();
