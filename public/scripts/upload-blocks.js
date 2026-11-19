(() => {
  'use strict';
  const get = id => document.getElementById(id);
  const start = get('upload-blocks-start');
  const sessionAPI = window.OkuruBlockSession;
  if (!start || !sessionAPI || !window.tus?.Upload || !window.fetch ||
      !window.crypto?.randomUUID || !window.AbortController || window.location.protocol !== 'https:') return;

  const form = get('file_create');
  const regular = get('submit');
  const cancel = get('upload-blocks-cancel');
  const resume = get('upload-blocks-resume');
  const panel = get('upload-progress');
  const meter = get('upload-meter');
  const percent = get('upload-percent');
  const status = get('upload-status');
  const confirmation = get('upload-confirmation');
  const receiptField = confirmation.elements.namedItem('receipt');
  const csrfField = confirmation.elements.namedItem('_csrf');
  const filesInput = get('files');
  const controls = [regular, filesInput, get('password'), get('ttl'), get('ttlViews'), get('deletable')];
  let config;
  let session;
  let operation;
  let discovery;

  function display(message, bytes, total) {
    panel.hidden = false;
    status.textContent = message;
    meter.hidden = false;
    if (Number.isSafeInteger(bytes) && Number.isSafeInteger(total)) {
      const progress = total === 0 ? 100 : Math.floor(100 * bytes / total);
      meter.value = progress;
      percent.textContent = progress + '%';
    } else {
      meter.removeAttribute('value');
      percent.textContent = '';
    }
    if (session && ['recover', 'complete', 'done'].includes(session.phase)) cancel.hidden = true;
  }

  function controlsDuringTransfer(locked) {
    for (const control of controls) control.disabled = locked;
    start.hidden = locked || !config;
    start.disabled = regular.disabled;
    cancel.hidden = !locked;
    resume.hidden = true;
  }

  function canConfirm() {
    return confirmation.isConnected && confirmation.action === window.location.origin + '/file/confirmation' &&
      confirmation.method === 'post' && typeof confirmation.submit === 'function' &&
      receiptField?.form === confirmation && !receiptField.disabled &&
      csrfField?.form === confirmation && !csrfField.disabled && csrfField.value;
  }

  function reset() {
    operation?.abort();
    operation = null;
    session = null;
    receiptField.value = '';
    controlsDuringTransfer(false);
  }

  async function discover() {
    discovery?.abort();
    discovery = new AbortController();
    const signal = discovery.signal;
    try {
      const offered = await sessionAPI.bootstrap(signal);
      if (signal.aborted) return;
      config = offered;
      start.hidden = false;
      start.disabled = regular.disabled;
    } catch { /* The regular form remains available. */ }
  }

  function showFailure(error) {
    const terminal = error.status === 404 || error.status === 410;
    if (terminal) {
      reset();
      display('This resumable session is no longer available. Select a new upload to start again.');
      start.focus();
      return;
    }
    const recovering = ['complete', 'recover', 'done'].includes(session.phase);
    const canRetry = recovering || error.transient || error.status === 403;
    const message = error.code === 'part_limit' ? 'The chunk limit was reached. Cancel this session before starting another.' :
      error.message || 'The transfer could not be completed.';
    display(message);
    resume.textContent = recovering ? 'Recover confirmation' : 'Resume upload';
    resume.hidden = !canRetry;
    cancel.hidden = recovering;
    if (!resume.hidden) resume.focus();
    else if (!cancel.hidden) cancel.focus();
  }

  async function run() {
    if (!session || operation) return;
    const current = session;
    const controller = new AbortController();
    operation = controller;
    resume.hidden = true;
    try {
      const receipt = await current.run(controller.signal);
      if (controller.signal.aborted || session !== current) return;
      if (!canConfirm()) throw Error('The confirmation page could not be opened.');
      receiptField.value = receipt;
      display('Opening confirmation…', current.total, current.total);
      confirmation.submit();
    } catch (error) {
      if (!controller.signal.aborted && session === current) showFailure(error);
    } finally {
      if (operation === controller) operation = null;
    }
  }

  start.addEventListener('click', () => {
    if (!config || session || regular.disabled || !form.reportValidity() || !canConfirm()) return;
    // Use the existing multipart filename, count and size validation.
    filesInput.dispatchEvent(new Event('change'));
    if (filesInput.getAttribute('aria-invalid') === 'true') { filesInput.focus(); return; }
    const files = Array.from(filesInput.files);
    if (!files.length) { filesInput.focus(); return; }
    const slider = Number(get('ttl').value);
    const options = { ttl_seconds: slider <= 24 ? slider * 3600 : (slider - 23) * 86400,
      views: Number(get('ttlViews').value), deletable: get('deletable').checked };
    if (get('password').value) options.password = get('password').value;
    try { session = new sessionAPI.Session(files, options, config, display); }
    catch (error) { display(error.message); return; }
    controlsDuringTransfer(true);
    receiptField.value = '';
    cancel.focus();
    void run();
  });

  resume.addEventListener('click', run);
  cancel.addEventListener('click', async () => {
    if (!session || cancel.disabled || ['complete', 'recover', 'done'].includes(session.phase)) return;
    const current = session;
    operation?.abort();
    const controller = new AbortController();
    operation = controller;
    cancel.disabled = true;
    resume.hidden = true;
    display('Cancelling upload…');
    try {
      await current.cancel(controller.signal);
      if (controller.signal.aborted || session !== current) return;
      reset();
      display('Upload cancelled.');
      start.focus();
    } catch (error) {
      if (!controller.signal.aborted && session === current) {
        if (current.phase === 'recover' || error.status === 404 || error.status === 410) showFailure(error);
        else {
          display('Cancellation could not be confirmed. Resume the upload or try cancelling again.');
          resume.textContent = 'Resume upload';
          resume.hidden = false;
          resume.focus();
        }
      }
    } finally {
      if (operation === controller) operation = null;
      cancel.disabled = false;
    }
  });

  // Pressing Enter or a second submit while transferring must never create another share.
  form.addEventListener('submit', event => { if (session) event.preventDefault(); }, true);
  new MutationObserver(() => { start.disabled = regular.disabled; }).observe(regular, { attributes: true, attributeFilter: ['disabled'] });
  window.addEventListener('pagehide', () => {
    discovery?.abort();
    if (session) reset();
    config = null;
    start.hidden = true;
  });
  window.addEventListener('pageshow', event => { if (event.persisted) void discover(); });
  void discover();
})();
