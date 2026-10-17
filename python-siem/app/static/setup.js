(() => {
  'use strict';

  document.addEventListener('submit', async (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || form.getAttribute('action') !== '/setup') return;
    event.preventDefault();
    if (!form.reportValidity()) return;

    const button = form.querySelector('button[type="submit"]');
    const originalText = button?.textContent || 'Create Super Admin';
    if (button) {
      button.disabled = true;
      button.textContent = 'Creating account…';
    }

    try {
      const response = await fetch(form.action, {
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

      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('text/html')) {
        const html = await response.text();
        const parsed = new DOMParser().parseFromString(html, 'text/html');
        const replacement = parsed.querySelector('main');
        const current = document.querySelector('main');
        if (replacement && current) {
          current.replaceWith(replacement);
          return;
        }
      }

      const message = (await response.text()).trim() || `Setup failed (HTTP ${response.status}).`;
      showError(message);
    } catch (_error) {
      showError('Could not submit setup. Check that the SIEM server is running, then try again.');
    } finally {
      if (button && button.isConnected) {
        button.disabled = false;
        button.textContent = originalText;
      }
    }
  });

  function showError(message) {
    let alert = document.querySelector('[data-setup-error]');
    if (!alert) {
      alert = document.createElement('div');
      alert.className = 'danger-zone';
      alert.setAttribute('role', 'alert');
      alert.setAttribute('data-setup-error', '');
      document.querySelector('form')?.before(alert);
    }
    if (alert) alert.textContent = message;
  }
})();
