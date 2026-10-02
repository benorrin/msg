// HTTP + WebSocket client for the msg API (see docs/API.md).

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function call(method, path, body) {
  const init = { method, credentials: 'same-origin', headers: {} };
  if (body instanceof Uint8Array) {
    init.body = body;
    init.headers['Content-Type'] = 'application/octet-stream';
  } else if (body !== undefined) {
    init.body = JSON.stringify(body);
    init.headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, init);
  if (res.status === 204) return null;
  const isJSON = (res.headers.get('Content-Type') || '').startsWith('application/json');
  const data = isJSON ? await res.json() : null;
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || res.statusText);
  return data;
}

export const api = {
  register: (b) => call('POST', '/api/register', b),
  login: (b) => call('POST', '/api/login', b),
  logout: () => call('POST', '/api/logout'),
  me: () => call('GET', '/api/me'),
  users: () => call('GET', '/api/users'),
  grant: (username, env) => call('POST', `/api/users/${encodeURIComponent(username)}/grant`, env),
  channels: () => call('GET', '/api/channels'),
  entries: (ch, { before = 0, after = 0, limit = 50 } = {}) =>
    call('GET', `/api/channels/${ch}/entries?before=${before}&after=${after}&limit=${limit}`),
  send: (req) => call('POST', '/api/entries', req),
  read: (ch, upto) => call('POST', `/api/channels/${ch}/read`, { upto }),
  putBlob: (bytes) => call('PUT', '/api/blobs', bytes),
  async getBlob(id) {
    const res = await fetch(`/api/blobs/${id}`, { credentials: 'same-origin' });
    if (!res.ok) throw new ApiError(res.status, 'could not fetch file');
    return res.arrayBuffer();
  },
};

// Socket keeps one WebSocket open, reconnecting with backoff. request() sends
// a frame and resolves when the server acks it, so callers can fall back to
// HTTP if the socket is down. Server-pushed events go to onEvent.
export class Socket {
  constructor({ onEvent, onStatus }) {
    this.onEvent = onEvent;
    this.onStatus = onStatus;
    this.pending = new Map();
    this.seq = 0;
    this.attempt = 0;
    this.ws = null;
    this.rtt = null;
    this.closed = false;
    this.wasOpen = false;
  }

  get open() {
    return this.ws && this.ws.readyState === WebSocket.OPEN;
  }

  connect() {
    this.closed = false;
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws`);
    this.ws = ws;
    ws.onopen = () => {
      const reconnect = this.wasOpen;
      this.wasOpen = true;
      this.attempt = 0;
      this.onStatus({ online: true, reconnect });
      this.beat();
    };
    ws.onmessage = (ev) => {
      let m;
      try { m = JSON.parse(ev.data); } catch { return; }
      if (m.op === 'pong') {
        this.rtt = performance.now() - this.pingAt;
        clearTimeout(this.deadTimer);
        this.onStatus({ online: true, rtt: this.rtt });
        return;
      }
      if ((m.op === 'ack' || m.op === 'error') && m.rid && this.pending.has(m.rid)) {
        const p = this.pending.get(m.rid);
        this.pending.delete(m.rid);
        clearTimeout(p.timer);
        if (m.op === 'ack') p.resolve(m);
        else { const e = new ApiError(400, m.error); e.fromServer = true; p.reject(e); }
        return;
      }
      this.onEvent(m);
    };
    ws.onclose = () => {
      clearTimeout(this.beatTimer);
      clearTimeout(this.deadTimer);
      for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new Error('socket closed')); }
      this.pending.clear();
      this.onStatus({ online: false });
      if (this.closed) return;
      const delay = Math.min(10000, 300 * 2 ** this.attempt++) * (0.7 + Math.random() * 0.6);
      setTimeout(() => !this.closed && this.connect(), delay);
    };
  }

  // Application-level ping: gives us a live latency reading and notices dead
  // connections that the browser has not yet reported.
  beat() {
    if (!this.open) return;
    this.pingAt = performance.now();
    this.ws.send(JSON.stringify({ op: 'ping', rid: 'p' }));
    this.deadTimer = setTimeout(() => this.ws && this.ws.close(), 8000);
    this.beatTimer = setTimeout(() => this.beat(), 15000);
  }

  request(op, payload, timeout = 8000) {
    if (!this.open) return Promise.reject(new Error('offline'));
    const rid = String(++this.seq);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(rid); reject(new Error('timeout')); }, timeout);
      this.pending.set(rid, { resolve, reject, timer });
      this.ws.send(JSON.stringify({ op, rid, ...payload }));
    });
  }

  // Fire-and-forget frame (e.g. read marks).
  notify(op, payload) {
    if (this.open) this.ws.send(JSON.stringify({ op, ...payload }));
  }

  close() {
    this.closed = true;
    if (this.ws) this.ws.close();
  }
}

// ---- tiny IndexedDB key/value store for non-extractable CryptoKeys ----

function idb() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open('msg', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function tx(mode, fn) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const t = db.transaction('kv', mode);
    const req = fn(t.objectStore('kv'));
    t.oncomplete = () => { db.close(); resolve(req && req.result); };
    t.onerror = t.onabort = () => { db.close(); reject(t.error); };
  });
}

export const kv = {
  get: (k) => tx('readonly', (s) => s.get(k)).catch(() => undefined),
  set: (k, v) => tx('readwrite', (s) => s.put(v, k)),
  clear: () => tx('readwrite', (s) => s.clear()).catch(() => {}),
};
