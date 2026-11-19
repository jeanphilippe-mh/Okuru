(() => {
  'use strict';

  class TransferError extends Error {
    constructor(message, status = null, code = '', retryAfter = 0) {
      super(message);
      this.status = status;
      this.code = code;
      this.retryAfter = retryAfter;
    }
    get transient() {
      return this.status === 0 || [408, 423, 425, 429, 500, 502, 503, 504].includes(this.status);
    }
  }

  function retryDelay(value) {
    if (!value) return 0;
    if (/^\d+$/.test(value)) return Number(value) * 1000;
    const date = Date.parse(value);
    return Number.isFinite(date) ? Math.max(0, date - Date.now()) : 0;
  }

  // API callers supply paths constructed from locally generated IDs and indexes.
  function request(path, method, { csrf, secret, headers = {}, body, signal } = {}) {
    const origin = window.location.origin;
    const target = new URL(path, origin);
    if (target.protocol !== 'https:' || target.origin !== origin || path !== target.pathname ||
        !target.pathname.startsWith('/api/v2/uploads')) {
      throw new TransferError('The server returned an invalid transfer address.');
    }
    headers = new Headers(headers);
    headers.set('Accept', 'application/json');
    if (secret) headers.set('Authorization', 'Bearer ' + secret);
    if (csrf && !['HEAD', 'GET'].includes(method)) headers.set('X-CSRF-Token', csrf);
    return window.fetch(target.href, { method, headers, body, signal, cache: 'no-store',
      credentials: 'same-origin', mode: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer' })
      .catch(() => {
        if (signal && signal.aborted) throw new DOMException('Upload stopped', 'AbortError');
        throw new TransferError('The connection was interrupted.', 0);
      });
  }

  async function httpError(response) {
    let code = '';
    if (/^application\/json\b/i.test(response.headers.get('Content-Type') || '')) {
      try {
        const data = await response.json();
        if (typeof data.code === 'string') code = data.code;
      } catch { /* A proxy can return an incomplete response. */ }
    }
    return new TransferError('The server returned HTTP ' + response.status + '.', response.status,
      code, retryDelay(response.headers.get('Retry-After')));
  }

  function integerHeader(headers, name) {
    const value = headers.get(name);
    if (!/^(0|[1-9]\d*)$/.test(value) || !Number.isSafeInteger(Number(value))) {
      throw new TransferError('The server returned an invalid transfer position.');
    }
    return Number(value);
  }

  // tus reads its offset with parseInt and accepts any 2xx. Validate the full
  // Okuru response before tus is allowed to treat a chunk as acknowledged.
  async function sendFile(file, path, options) {
    const { secret, csrf, signal, chunkSize, confirmed, checkBudget } = options;
    const fullURL = window.location.origin + path;
    let failure;
    const httpStack = {
      getName: () => 'Okuru Fetch',
      createRequest(method, url) {
        if (url !== fullURL || (method !== 'HEAD' && method !== 'PATCH')) {
          throw new TransferError('Unexpected resumable upload request.');
        }
        const headers = new Headers();
        return {
          getMethod: () => method, getURL: () => url,
          setHeader: (key, value) => headers.set(key, value), getHeader: key => headers.get(key),
          setProgressHandler() {}, // Only acknowledged offsets count.
          getUnderlyingObject: () => null,
          async send(body) {
            try {
              signal.throwIfAborted();
              if (headers.get('Tus-Resumable') !== '1.0.0') throw new TransferError('Unsupported transfer version.');
              let end;
              if (method === 'PATCH') {
                const offset = integerHeader(headers, 'Upload-Offset');
                if (!body || !Number.isSafeInteger(body.size) || body.size <= 0 || body.size > chunkSize ||
                    body.size > file.size - offset || headers.get('Content-Type') !== 'application/offset+octet-stream') {
                  throw new TransferError('Invalid binary chunk.');
                }
                checkBudget();
                end = offset + body.size;
                options.sending(offset, end);
              }
              const response = await request(path, method, { headers, secret, csrf, signal, body });
              if (!response.ok) throw await httpError(response);
              if (response.status !== (method === 'HEAD' ? 200 : 204) ||
                  response.headers.get('Tus-Resumable') !== '1.0.0') {
                throw new TransferError('The server returned an unexpected transfer response.');
              }
              const offset = integerHeader(response.headers, 'Upload-Offset');
              if (offset > file.size || (method === 'PATCH' && offset !== end) ||
                  (method === 'HEAD' && integerHeader(response.headers, 'Upload-Length') !== file.size)) {
                throw new TransferError('The server confirmed an inconsistent file size or position.');
              }
              confirmed(offset);
              return { getStatus: () => response.status, getHeader: key => response.headers.get(key),
                getBody: () => '', getUnderlyingObject: () => response };
            } catch (error) {
              failure = error;
              throw error;
            }
          },
          abort: () => Promise.resolve(),
        };
      },
    };
    return new Promise((resolve, reject) => {
      const upload = new window.tus.Upload(file, {
        uploadUrl: fullURL, endpoint: null, protocol: 'tus-v1', httpStack, chunkSize,
        parallelUploads: 1, retryDelays: null, storeFingerprintForResuming: false,
        fingerprint: async () => null, metadata: {},
        onSuccess: resolve,
        onError: () => reject(failure || new TransferError('The selected file could not be read.')),
      });
      upload.start();
    });
  }

  window.OkuruBlockTransport = Object.freeze({ TransferError, request, httpError, sendFile });
})();
