(() => {
  const form = document.getElementById('file_create');
  const files = document.getElementById('files');
  const button = document.getElementById('submit');
  const panel = document.getElementById('upload-progress');
  const meter = document.getElementById('upload-meter');
  const percent = document.getElementById('upload-percent');
  const status = document.getElementById('upload-status');
  const confirmation = document.getElementById('upload-confirmation');
  if (!form || !files || !button || button.form !== form || !panel || !meter || !percent || !status ||
      !confirmation || !confirmation.elements || typeof window.FormData !== 'function' ||
      typeof window.XMLHttpRequest !== 'function') return;

  const endpoint = window.location.origin + '/file';
  const receipt = confirmation.elements.namedItem('receipt');
  const csrf = confirmation.elements.namedItem('_csrf');
  let active = null;

  function canConfirm() {
    return confirmation.isConnected && confirmation.action === endpoint + '/confirmation' &&
      confirmation.method === 'post' && typeof confirmation.submit === 'function' &&
      receipt && receipt.form === confirmation && !receipt.disabled &&
      csrf && csrf.form === confirmation && !csrf.disabled && csrf.value;
  }

  function updateProgress(event) {
    if (event.lengthComputable && Number.isFinite(event.total) && event.total > 0 &&
        Number.isFinite(event.loaded) && event.loaded >= 0) {
      const value = Math.floor(100 * Math.min(event.loaded, event.total) / event.total);
      meter.value = value;
      percent.textContent = value + '%';
    } else {
      meter.removeAttribute('value');
      percent.textContent = '';
    }
  }

  form.addEventListener('submit', (event) => {
    if (event.defaultPrevented) return;
    if (active) {
      event.preventDefault();
      return;
    }
    if (!canConfirm()) return;

    const selection = files.files;
    let request;
    let body;
    try {
      request = new window.XMLHttpRequest();
      if (!request.upload || !('onprogress' in request.upload)) return;
      body = new window.FormData(form);
      // Some browsers need upload listeners before open().
      request.upload.onprogress = (progress) => {
        if (active === request) updateProgress(progress);
      };
      request.upload.onload = (progress) => {
        if (active !== request) return;
        updateProgress(progress);
        status.textContent = 'Preparing your secure link…';
      };
      request.open('POST', endpoint);
      request.responseType = 'json';
      request.setRequestHeader('Accept', 'application/json');
    } catch {
      // No bytes have been sent. Let the browser submit the original form.
      return;
    }

    event.preventDefault();
    active = request;
    button.disabled = true;
    receipt.value = '';
    meter.hidden = false;
    meter.removeAttribute('value');
    percent.textContent = '';
    panel.hidden = false;
    status.textContent = 'Uploading files…';

    function fail(message) {
      if (active !== request) return;
      active = null;
      button.disabled = false;
      receipt.value = '';
      meter.hidden = true;
      percent.textContent = '';
      status.textContent = message;
    }

    request.onerror = request.onabort = request.ontimeout = () => {
      fail('The upload was interrupted. Check your connection before trying again.');
    };
    request.onload = () => {
      if (active !== request) return;
      const result = request.response;
      if (request.status < 200 || request.status >= 300) {
        const reason = result && typeof result.error === 'string' && result.error.trim();
        const code = result && result.code;
        const inlineError = (request.status === 400 && code === 'file_name_error') ||
          ((request.status === 400 || request.status === 403) && code === 'form_verification_failed');
        if (request.responseURL === endpoint && reason && inlineError) {
          if (code === 'form_verification_failed') {
            const token = request.getResponseHeader('X-CSRF-Token');
            if (token && /^[A-Za-z0-9_-]{32}$/.test(token)) {
              const uploadCSRF = form.elements.namedItem('_csrf');
              if (uploadCSRF && uploadCSRF.form === form) uploadCSRF.value = token;
              if (csrf && csrf.form === confirmation) csrf.value = token;
            }
          }
          // An error from an earlier selection must never replace its successor's alert.
          const current = files.files === selection;
          const handled = current && !form.dispatchEvent(new CustomEvent('file-upload-error', {
            detail: { code, message: reason }, cancelable: true
          }));
          fail(current && !handled ? reason : '');
          if (!current || handled) panel.hidden = true;
          return;
        }
        fail(reason || 'The server could not accept the upload (HTTP ' + request.status + ').');
        if (request.responseURL === endpoint && (request.status === 400 || request.status === 413) &&
            reason && result.code === 'file_selection_limit' && files.files === selection) {
          const warning = new CustomEvent('file-selection-limit', { detail: reason, cancelable: true });
          if (!form.dispatchEvent(warning)) panel.hidden = true;
        }
        return;
      }
      if (request.responseURL !== endpoint || !result || typeof result.receipt !== 'string' ||
          !result.receipt.trim() || !canConfirm()) {
        fail('The server response could not be used to open the confirmation page.');
        return;
      }
      receipt.value = result.receipt;
      status.textContent = 'Opening confirmation…';
      try {
        confirmation.submit();
      } catch {
        fail('The confirmation page could not be opened.');
      }
    };
    try {
      request.send(body);
    } catch {
      fail('The upload could not be sent.');
    }
  });

  window.addEventListener('pageshow', (event) => {
    if (active && !event.persisted) return;
    const previous = active;
    active = null;
    if (previous) previous.abort();
    if (receipt) receipt.value = '';
    button.disabled = false;
    panel.hidden = true;
    status.textContent = '';
    percent.textContent = '';
    meter.removeAttribute('value');
  });
})();
