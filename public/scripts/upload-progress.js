(() => {
  const form = document.getElementById('file_create');
  const button = document.getElementById('submit');
  const panel = document.getElementById('upload-progress');
  const meter = document.getElementById('upload-meter');
  const percent = document.getElementById('upload-percent');
  const status = document.getElementById('upload-status');
  const confirmation = document.getElementById('upload-confirmation');
  if (!form || !button || button.form !== form || !panel || !meter || !percent || !status ||
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
        fail(reason || 'The server could not accept the upload (HTTP ' + request.status + ').');
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
