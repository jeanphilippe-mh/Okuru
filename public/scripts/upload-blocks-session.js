(() => {
  'use strict';
  const { TransferError, request, httpError, sendFile } = window.OkuruBlockTransport;
  const base = '/api/v2/uploads';
  const maxParts = 2048;

  async function json(path, method, options, statuses) {
    const response = await request(path, method, options);
    if (!statuses.includes(response.status)) throw await httpError(response);
    if (!/^application\/json\b/i.test(response.headers.get('Content-Type') || '')) {
      throw new TransferError('The server returned an unreadable transfer response.');
    }
    try { return { data: await response.json(), headers: response.headers }; }
    catch { throw new TransferError('The transfer response was incomplete.', 0); }
  }

  async function bootstrap(signal) {
    const { data, headers } = await json(base + '/bootstrap', 'GET', { signal }, [200]);
    const csrf = headers.get('X-CSRF-Token');
    if (!csrf || !Array.isArray(data?.modes) || !data.modes.includes('blocks') ||
        !Number.isSafeInteger(data.max_patch_bytes) || data.max_patch_bytes < 1 ||
        !Number.isSafeInteger(data.max_total_bytes) || data.max_total_bytes < 1) {
      throw new TransferError('Resumable uploads are currently unavailable.');
    }
    return { csrf, chunkSize: data.max_patch_bytes, limit: data.max_total_bytes };
  }

  function wait(ms, signal) {
    return new Promise((resolve, reject) => {
      const abort = () => { clearTimeout(timer); reject(new DOMException('Upload stopped', 'AbortError')); };
      const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve(); }, ms);
      if (signal.aborted) return abort();
      signal.addEventListener('abort', abort, { once: true });
    });
  }

  class Session {
    constructor(files, manifest, config, display) {
      this.files = files;
      this.display = display;
      this.csrf = config.csrf;
      this.chunkSize = config.chunkSize;
      this.total = files.reduce((sum, f) => sum + f.size, 0);
      if (this.total > config.limit) throw new TransferError('Selected files exceed the resumable upload limit.');
      this.offsets = files.map(() => 0);
      this.parts = 0;
      this.checkBudget();
      this.id = window.crypto.randomUUID();
      const random = window.crypto.getRandomValues(new Uint8Array(32));
      this.secret = btoa(String.fromCharCode(...random)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      this.path = base + '/' + this.id;
      this.manifest = JSON.stringify({ ...manifest, mode: 'blocks', files: files.map(f => ({ name: f.name, size: f.size })) });
      this.index = 0;
      this.notBefore = 0;
      this.phase = 'prepare';
      this.pending = null;
      this.receipt = '';
    }

    checkBudget() {
      const remaining = this.files.reduce((sum, f, i) => sum + Math.ceil((f.size - this.offsets[i]) / this.chunkSize), 0);
      if (this.parts + remaining > maxParts) {
        throw new TransferError('This upload needs too many chunks. Start a new upload with fewer or smaller files.', null, 'part_limit');
      }
    }

    auth(signal) { return { csrf: this.csrf, secret: this.secret, signal }; }

    async prepare(signal) {
      this.display('Preparing resumable upload…');
      const { data } = await json(base, 'POST', { ...this.auth(signal), body: this.manifest,
        headers: { 'Content-Type': 'application/json', 'Idempotency-Key': this.id } }, [200, 201]);
      if (!data || data.id !== this.id || data.mode !== 'blocks' || data.status_url !== this.path ||
          data.result_url !== this.path + '/result' || !Array.isArray(data.files) || data.files.length !== this.files.length ||
          !this.files.every((f, i) => {
            const item = data.files[i];
            return item && item.index === i && item.name === f.name && item.size === f.size &&
              item.upload_url === this.path + '/files/' + i;
          })) throw new TransferError('The server did not confirm this file manifest.');
      this.phase = 'send';
    }

    async send(signal) {
      const i = this.index;
      const report = () => {
        const bytes = this.offsets.reduce((sum, value) => sum + value, 0);
        this.display('Server confirmed ' + bytes.toLocaleString() + ' of ' + this.total.toLocaleString() + ' bytes.', bytes, this.total);
      };
      report();
      await sendFile(this.files[i], this.path + '/files/' + i, {
        ...this.auth(signal), chunkSize: this.chunkSize, checkBudget: () => this.checkBudget(),
        sending: (start, end) => {
          if (start !== this.offsets[i]) throw new TransferError('The server returned a conflicting position.');
          this.pending = end;
        },
        confirmed: offset => {
          if (offset !== this.offsets[i]) {
            if (offset !== this.pending) throw new TransferError('The server returned an unexpected file position.');
            this.offsets[i] = offset;
            this.parts++;
          }
          this.pending = null;
          report();
        },
      });
      if (this.offsets[i] !== this.files[i].size) throw new TransferError('The server has not confirmed the entire file.');
      this.index++;
      if (this.index === this.files.length) this.phase = 'complete';
    }

    accept(data) {
      const receipt = data && data.confirmation_receipt;
      if (typeof receipt !== 'string' || !receipt.trim() || receipt.length > 8192) {
        throw new TransferError('The server did not provide a usable confirmation receipt.');
      }
      this.receipt = receipt;
      this.phase = 'done';
    }

    async complete(signal) {
      this.display('Preparing your secure link…', this.total, this.total);
      // Set recovery before issuing the mutation. A lost response can conceal a successful publication.
      this.phase = 'recover';
      const { data } = await json(this.path + '/complete', 'POST', this.auth(signal), [200, 201]);
      this.accept(data);
    }

    async recover(signal) {
      this.display('Retrieving your upload confirmation…', this.total, this.total);
      try {
        const { data } = await json(this.path + '/result', 'GET', this.auth(signal), [200]);
        this.accept(data);
        return;
      } catch (error) {
        if (error.status !== 409 || error.code !== 'not_ready') throw error;
      }
      const { data } = await json(this.path, 'GET', this.auth(signal), [200]);
      if (data?.state === 'finalizing' || data?.state === 'ready') {
        throw new TransferError('Publication is still in progress.', 503, '', 1000);
      }
      if (!['open', 'receiving'].includes(data?.state) ||
          data.measure !== 'file_bytes_confirmed' || data.bytes !== this.total || data.total !== this.total) {
        throw new TransferError('The upload state does not allow finalization.');
      }
      await this.complete(signal);
    }

    async run(signal) {
      let consecutive = 0;
      let lastParts = this.parts;
      let refreshedCSRF = false;
      while (this.phase !== 'done') {
        if (signal.aborted) throw new DOMException('Upload stopped', 'AbortError');
        const delay = this.notBefore - Date.now();
        if (delay > 60_000) throw new TransferError('The server asks you to resume later.', 429, '', delay);
        if (delay > 0) await wait(delay, signal);
        try {
          if (this.phase === 'prepare') await this.prepare(signal);
          else if (this.phase === 'send') await this.send(signal);
          else if (this.phase === 'complete') await this.complete(signal);
          else await this.recover(signal);
          consecutive = 0;
        } catch (error) {
          if (signal.aborted) throw error;
          if (error.status === 403 && !refreshedCSRF) {
            refreshedCSRF = true;
            this.csrf = (await bootstrap(signal)).csrf;
            continue;
          }
          if (error.code === 'part_limit') throw new TransferError('The session reached its chunk limit. Start a new upload.', 409, 'part_limit');
          const shrink = this.phase === 'send' && error.status === 413;
          const reconcile = this.phase === 'send' && error.status === 409;
          if (shrink) {
            if (this.chunkSize === 1) throw new TransferError('The server cannot accept a one-byte upload chunk.');
            this.chunkSize = Math.max(1, Math.floor(this.chunkSize / 2));
          }
          if (!(shrink || reconcile || error.transient)) throw error;
          if (lastParts !== this.parts) { consecutive = 0; lastParts = this.parts; }
          this.notBefore = Date.now() + Math.max(error.retryAfter || 0, [1000, 3000, 5000][consecutive] || 0);
          if (++consecutive > 3) throw new TransferError('Automatic retries stopped. Resume to try again.', 0);
          this.display('Waiting to resume the transfer…');
        }
      }
      return this.receipt;
    }

    async cancel(signal) {
      const response = await request(this.path, 'DELETE', this.auth(signal));
      if (response.status === 204) return;
      const failure = await httpError(response);
      if (failure.status === 409) {
        // A PATCH holding the session lock and publication can both yield 409.
        const { data } = await json(this.path, 'GET', this.auth(signal), [200]);
        if (data?.state === 'finalizing' || data?.state === 'ready') this.phase = 'recover';
      }
      throw failure;
    }
  }
  window.OkuruBlockSession = Object.freeze({ bootstrap, Session });
})();
