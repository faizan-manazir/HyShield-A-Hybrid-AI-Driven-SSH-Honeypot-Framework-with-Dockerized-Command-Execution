(() => {
  'use strict';

  // Use fetch for HTML form POSTs so local browser submissions use the page's
  // normal same-origin context. Keep server-side Origin validation enabled.
  document.addEventListener('submit', async (event) => {
    if (event.defaultPrevented) return;
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const method = (form.method || 'get').toUpperCase();
    if (method !== 'POST') return;

    const action = new URL(form.action || window.location.href, window.location.href);
    if (action.origin !== window.location.origin) return;
    if (action.pathname.startsWith('/api/')) return;
    // Alert resolution has a dedicated JSON/AJAX handler in app.js.
    if (/^\/alerts\/[^/]+\/close$/.test(action.pathname)) return;

    event.preventDefault();
    if (!form.reportValidity()) return;

    const button = event.submitter || form.querySelector('button[type="submit"], button:not([type])');
    const originalText = button?.textContent || '';
    if (button) {
      button.disabled = true;
      button.textContent = 'Please wait…';
    }

    try {
      const data = new FormData(form);
      if (event.submitter?.name) data.append(event.submitter.name, event.submitter.value);
      const response = await fetch(action.href, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
          'Accept': 'text/html',
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        },
        body: new URLSearchParams(data).toString()
      });

      // The server's normal post/redirect/get flow remains authoritative.
      // Fetch follows redirects and receives any same-origin session cookie;
      // then navigate the top-level page to the final destination.
      if (response.redirected) {
        window.location.assign(response.url);
        return;
      }

      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('text/html')) {
        const html = await response.text();
        document.open();
        document.write(html);
        document.close();
        return;
      }

      const detail = (await response.text()).trim();
      showError(detail || `Request failed (HTTP ${response.status}).`);
    } catch (_error) {
      showError('The request could not be completed. Check the server connection and try again.');
    } finally {
      if (button?.isConnected) {
        button.disabled = false;
        button.textContent = originalText;
      }
    }
  });

  function showError(message) {
    let notice = document.querySelector('[data-form-transport-error]');
    if (!notice) {
      notice = document.createElement('div');
      notice.className = 'danger-zone';
      notice.setAttribute('role', 'alert');
      notice.setAttribute('data-form-transport-error', '');
      (document.querySelector('main') || document.body).prepend(notice);
    }
    notice.textContent = message;
  }
})();
