import {
  deriveFromPassword, createIdentity, unwrapIdentity, fingerprint, newChannelKey, importChannelKey,
  sealKey, unsealKey, signGrant, verifyGrant, encryptEntry, decryptEntry, encryptBlob, decryptBlob, randomId,
} from './crypto.js';
import { api, Socket, kv } from './net.js';
import { h, linkify, extractUrls, stripUrls, safeUrl, hostOf, fmtSize, fmtTime } from './util.js';

const $ = (id) => document.getElementById(id);
const IMG_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp']);
const AUTO_PREVIEW_MAX = 3 * 1024 * 1024;

const S = {
  me: null,
  keys: null, // { encPriv, signPriv }: non-extractable CryptoKeys
  chRaw: null, // raw channel key, kept so we can seal it for newcomers
  chKey: null,
  epoch: 1,
  maxFile: 25 << 20,
  users: new Map(),
  pins: {},
  chan: new Map(), // id -> channel state
  order: [],
  active: null,
  sock: null,
  entered: false,
};

// ---------- small UI utilities ----------

function show(which) {
  for (const id of ['auth', 'pending', 'app']) $(id).hidden = id !== which;
}

let toastTimer;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 3500);
}

function openDialog(...nodes) {
  const d = $('dlg');
  d.replaceChildren(...nodes);
  if (!d.open) d.showModal();
}
const closeDialog = () => $('dlg').open && $('dlg').close();

const nameOf = (id) => (S.users.get(id) || {}).username || `user ${id}`;

// ---------- auth ----------

let mode = 'login';
function setMode(m) {
  mode = m;
  $('tab-login').setAttribute('aria-selected', m === 'login');
  $('tab-register').setAttribute('aria-selected', m === 'register');
  $('f-pass2-row').hidden = m !== 'register';
  $('f-pass2').required = m === 'register';
  $('auth-note').hidden = m !== 'register';
  $('f-pass').autocomplete = m === 'register' ? 'new-password' : 'current-password';
  $('auth-submit').textContent = m === 'register' ? 'Create account' : 'Sign in';
  $('auth-err').hidden = true;
}
$('tab-login').onclick = () => setMode('login');
$('tab-register').onclick = () => setMode('register');

function showAuth(unlockFor) {
  show('auth');
  setMode('login');
  if (unlockFor) {
    $('f-user').value = unlockFor;
    $('f-pass').focus();
  }
}

$('auth-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const err = $('auth-err');
  const btn = $('auth-submit');
  err.hidden = true;
  const username = $('f-user').value.trim().toLowerCase();
  const pass = $('f-pass').value;
  if (mode === 'register' && pass !== $('f-pass2').value) {
    err.textContent = 'Passwords do not match.';
    err.hidden = false;
    return;
  }
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = mode === 'register' ? 'Generating keys…' : 'Unlocking…';
  try {
    const { auth, wrapKey } = await deriveFromPassword(username, pass);
    let keys;
    if (mode === 'register') {
      const id = await createIdentity(wrapKey);
      keys = await unwrapIdentity(wrapKey, id.wrapped);
      // If we turn out to be the first user we are the channel's creator, so
      // this is its key. The server ignores the envelope for everyone else.
      const sealed = await sealKey(id.encPub, newChannelKey());
      const sig = await signGrant(keys.signPriv, username, 1, sealed);
      await api.register({
        username, auth, enc_pub: id.encPub, sign_pub: id.signPub, wrapped_keys: id.wrapped,
        bootstrap: { epoch: 1, sealed, sig },
      });
    } else {
      const r = await api.login({ username, auth });
      keys = await unwrapIdentity(wrapKey, r.wrapped_keys);
    }
    $('f-pass').value = $('f-pass2').value = '';
    try { await kv.set('identity', { username, keys }); } catch { /* keys stay in memory only */ }
    await start(keys);
  } catch (e) {
    err.textContent = e.message || 'Something went wrong.';
    err.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
});

async function signOut() {
  try { await api.logout(); } catch { /* ignore */ }
  await kv.clear();
  if (S.sock) S.sock.close();
  location.reload();
}
$('btn-out').onclick = signOut;
$('pending-out').onclick = signOut;

// ---------- boot ----------

async function start(keysInMemory) {
  let me;
  try {
    me = await api.me();
  } catch (e) {
    if (e.status !== 401) toast('Cannot reach the server.');
    return showAuth();
  }
  let keys = keysInMemory;
  if (!keys) {
    const stored = await kv.get('identity');
    if (stored && stored.username === me.user.username) keys = stored.keys;
  }
  if (!keys) return showAuth(me.user.username); // session is valid but keys are not on this device
  S.keys = keys;
  S.me = me.user;
  S.epoch = me.epoch;
  S.maxFile = me.max_file_bytes;
  S.pins = JSON.parse(localStorage.getItem('pins:' + S.me.id) || '{}');

  if (!S.sock) connectSocket();
  if (!me.user.member) {
    $('pending-fp').textContent = await fingerprint(me.user.enc_pub, me.user.sign_pub);
    return show('pending');
  }
  await unlockChannel(me.envelope, me.granter);
  await enterApp();
}

async function unlockChannel(env, granter) {
  const ok = await verifyGrant(granter.sign_pub, env.sig, S.me.username, env.epoch, env.sealed);
  if (!ok) throw new Error('The channel key grant has an invalid signature.');
  S.chRaw = await unsealKey(S.keys.encPriv, S.me.enc_pub, env.sealed);
  S.chKey = await importChannelKey(S.chRaw);
  S.granter = granter;
}

async function enterApp() {
  if (S.entered) return;
  S.entered = true;
  show('app');
  $('me-name').textContent = S.me.username;
  const [users, channels] = await Promise.all([api.users(), api.channels()]);
  for (const u of users) S.users.set(u.id, u);
  await checkPins(users);
  S.order = channels.map((c) => c.id);
  for (const c of channels) S.chan.set(c.id, makeChannel(c));
  renderSidebar();
  updatePending();
  window.addEventListener('hashchange', route);
  document.addEventListener('visibilitychange', onVisible);
  await route();
}

// ---------- key pinning (trust on first use) ----------

async function checkPins(users) {
  await Promise.all(users.map(async (u) => {
    u.fp = await fingerprint(u.enc_pub, u.sign_pub);
    const pinned = S.pins[u.username];
    if (!pinned) S.pins[u.username] = u.fp;
    else u.keyChanged = pinned !== u.fp;
  }));
  localStorage.setItem('pins:' + S.me.id, JSON.stringify(S.pins));
}

// ---------- websocket ----------

function connectSocket() {
  S.sock = new Socket({ onEvent, onStatus });
  S.sock.connect();
}

function onStatus(st) {
  const el = $('net');
  el.classList.toggle('online', !!st.online);
  if (!st.online) el.textContent = 'offline, retrying…';
  else if (st.rtt != null) el.textContent = `connected · ${Math.round(st.rtt)} ms`;
  else el.textContent = 'connected';
  if (st.online && st.reconnect && S.entered) catchUp().catch(() => {});
}

async function onEvent(m) {
  switch (m.op) {
    case 'hello':
      // A grant can land between loading /api/me and the socket opening.
      if (m.member && !S.me.member && !S.entered) return start(S.keys);
      return;
    case 'entry': return onEntry(m.entry);
    case 'user': return onUser(m.user);
    case 'granted':
      if (S.entered) return;
      S.me.member = true;
      await unlockChannel(m.envelope, m.granter);
      toast(`${m.granter.username} let you in`);
      return enterApp();
  }
}

async function onUser(u) {
  const old = S.users.get(u.id);
  S.users.set(u.id, { ...old, ...u });
  await checkPins([S.users.get(u.id)]);
  updatePending();
  if (!old && !u.member) toast(`${u.username} is waiting to join`);
  if ($('dlg').open && $('dlg').dataset.kind === 'members') showMembers();
}

async function catchUp() {
  const [users, channels] = await Promise.all([api.users(), api.channels()]);
  for (const u of users) S.users.set(u.id, { ...S.users.get(u.id), ...u });
  await checkPins(users);
  for (const c of channels) {
    const ch = S.chan.get(c.id);
    if (ch) { ch.meta.unread = c.unread; ch.meta.last_id = c.last_id; }
  }
  renderSidebar();
  updatePending();
  for (const ch of S.chan.values()) {
    if (!ch.loaded) continue;
    for (;;) {
      const es = await api.entries(ch.meta.id, { after: ch.newest(), limit: 200 });
      await Promise.all(es.map((e) => ingest(e)));
      if (es.length < 200) break;
    }
  }
  const act = S.chan.get(S.active);
  if (act && visible()) markRead(act);
}

// ---------- channels ----------

const HEADS = {
  stream: ['# main', 'Everyone sees this. Links and files you share here are also filed in links and files.'],
  links: ['Links', 'Links shared in main are filed here automatically. Posting here is quiet: main is not notified.'],
  bookmarks: ['Bookmarks', 'Things worth keeping, with titles and tags. Quiet: main is not notified.'],
  files: ['Files', 'Files shared in main are filed here automatically. Posting here is quiet: main is not notified.'],
};

function makeChannel(meta) {
  const kind = meta.kind;
  const list = h('div', { class: 'list' });
  const more = h('button', { class: 'more small', type: 'button', hidden: true }, 'Load older');
  const empty = h('div', { class: 'empty', hidden: true }, kind === 'stream' ? 'No messages yet. Say hello.' : 'Nothing here yet.');
  const el = h('div', { class: 'view ' + (kind === 'stream' ? 'stream' : 'side'), hidden: true },
    ...(kind === 'stream' ? [more, list, empty] : [list, empty, more]));
  $('views').append(el);
  const ch = {
    meta, kind, el, list, more, empty,
    byId: new Map(), byCid: new Map(),
    loaded: false, exhausted: false, composer: null,
    newest() {
      let n = 0;
      for (const id of this.byId.keys()) if (id > n) n = id;
      return n;
    },
    oldest() {
      let o = Infinity;
      for (const id of this.byId.keys()) if (id < o) o = id;
      return o === Infinity ? 0 : o;
    },
  };
  more.onclick = () => loadOlder(ch);
  return ch;
}

function renderSidebar() {
  const ul = $('channels');
  ul.replaceChildren();
  let sideHeader = false;
  for (const id of S.order) {
    const ch = S.chan.get(id);
    if (ch.kind !== 'stream' && !sideHeader) {
      ul.append(h('li', { class: 'group' }, 'Side channels'));
      sideHeader = true;
    }
    const n = ch.meta.unread;
    ul.append(h('li', {},
      h('button', { type: 'button', 'aria-current': id === S.active, onclick: () => (location.hash = '#/' + id) },
        h('span', { class: 'name' }, (ch.kind === 'stream' ? '# ' : '') + ch.meta.name),
        n > 0 ? h('span', { class: 'badge' + (ch.kind === 'stream' ? ' loud' : '') }, n > 99 ? '99+' : String(n)) : null)));
  }
  const mainUnread = [...S.chan.values()].filter((c) => c.kind === 'stream').reduce((a, c) => a + c.meta.unread, 0);
  document.title = (mainUnread ? `(${mainUnread}) ` : '') + 'msg';
}

async function route() {
  const id = location.hash.replace(/^#\//, '');
  await switchTo(S.chan.has(id) ? id : S.order[0]);
}

async function switchTo(id) {
  const ch = S.chan.get(id);
  if (S.active) S.chan.get(S.active).el.hidden = true;
  S.active = id;
  ch.el.hidden = false;
  const [title, sub] = HEADS[ch.kind] || [ch.meta.name, ''];
  $('head-title').textContent = title;
  renderHeadSub(sub);
  if (!ch.composer) ch.composer = buildComposer(ch);
  $('composer').replaceChildren(ch.composer);
  renderSidebar();
  if (!ch.loaded) await loadInitial(ch);
  else if (ch.kind === 'stream') scrollEnd(ch);
  markRead(ch);
}

function renderHeadSub(sub) {
  const changed = [...S.users.values()].filter((u) => u.keyChanged);
  $('head-sub').replaceChildren(sub,
    ...changed.map((u) => h('span', { class: 'error' }, ` ⚠ ${u.username}'s keys changed since you first saw them; their messages are marked unverified.`)));
}

async function loadInitial(ch) {
  ch.loaded = true; // from here on live events are ingested too
  const es = await api.entries(ch.meta.id, { limit: 50 });
  ch.exhausted = es.length < 50;
  await Promise.all(es.map((e) => ingest(e)));
  updateChrome(ch);
  if (ch.kind === 'stream') scrollEnd(ch);
}

async function loadOlder(ch) {
  const before = ch.oldest();
  ch.more.disabled = true;
  try {
    const es = await api.entries(ch.meta.id, { before, limit: 50 });
    ch.exhausted = es.length < 50;
    const v = ch.el;
    const prev = v.scrollHeight - v.scrollTop;
    await Promise.all(es.map((e) => ingest(e)));
    if (ch.kind === 'stream') v.scrollTop = v.scrollHeight - prev;
  } finally {
    ch.more.disabled = false;
    updateChrome(ch);
  }
}

function updateChrome(ch) {
  ch.more.hidden = ch.exhausted || !ch.loaded;
  ch.empty.hidden = !ch.loaded || ch.list.children.length > 0;
}

const scrollEnd = (ch) => (ch.el.scrollTop = ch.el.scrollHeight);

// ---------- entries ----------

async function ingest(e) {
  const ch = S.chan.get(e.channel);
  if (!ch || !ch.loaded) return;
  let rec = ch.byId.get(e.id);
  if (rec && !rec.pending) return;
  rec = ch.byCid.get(e.cid) || rec || {};
  rec.pending = false;
  rec.entry = e;
  ch.byId.set(e.id, rec); // claim the id synchronously so a racing duplicate is dropped
  ch.byCid.set(e.cid, rec);
  try {
    const author = S.users.get(e.author_id);
    const { obj, verified } = await decryptEntry(S.chKey, e, author && !author.keyChanged ? author.sign_pub : null);
    rec.obj = obj;
    rec.verified = verified;
  } catch {
    rec.obj = null;
  }
  place(ch, rec);
}

// (Re)builds a record's element and puts it where its id says it belongs:
// oldest-first in the stream, newest-first in side channels.
function place(ch, rec) {
  const stream = ch.kind === 'stream';
  const v = ch.el;
  const nearEnd = v.scrollHeight - v.scrollTop - v.clientHeight < 140;
  const el = rec.obj === null ? lockedEl(rec) : stream ? messageEl(rec) : ch.kind === 'files' ? fileCardEl(ch, rec) : linkCardEl(ch, rec);
  const id = rec.entry ? rec.entry.id : Infinity;
  el.dataset.id = id;
  if (rec.el) rec.el.remove();
  rec.el = el;
  const kids = ch.list.children;
  let placed = false;
  if (stream) {
    for (let i = kids.length - 1; i >= 0 && !placed; i--) {
      if (+kids[i].dataset.id < id) { kids[i].after(el); placed = true; }
    }
    if (!placed) ch.list.prepend(el);
  } else {
    for (let i = 0; i < kids.length && !placed; i++) {
      if (+kids[i].dataset.id < id) { kids[i].before(el); placed = true; }
    }
    if (!placed) ch.list.append(el);
  }
  updateChrome(ch);
  const mine = rec.pending || (rec.entry && rec.entry.author_id === S.me.id);
  if (stream && !ch.el.hidden && (nearEnd || mine)) scrollEnd(ch);
}

function lockedEl(rec) {
  return h('div', { class: 'msg' }, h('div', { class: 'muted' }, '🔒 This entry could not be decrypted.'));
}

function metaLine(rec, extra) {
  const e = rec.entry;
  const author = rec.pending ? S.me.username : nameOf(e.author_id);
  return h('div', { class: 'meta' },
    h('span', { class: 'who' }, author),
    h('span', {}, rec.pending ? (rec.status === 'failed' ? 'failed' : 'sending…') : fmtTime(e.created_at)),
    rec.pending || rec.verified ? null : h('span', { class: 'warn', title: "The sender's signature could not be verified" }, '⚠ unverified'),
    extra);
}

function originLink(rec) {
  const id = rec.entry && rec.entry.origin_id;
  if (!id) return null;
  return h('a', { href: '#/main', class: 'small', onclick: (ev) => { ev.preventDefault(); jumpToMain(id); } }, 'from main ↗');
}

async function jumpToMain(id) {
  location.hash = '#/main';
  await route();
  const el = S.chan.get('main').list.querySelector(`[data-id="${id}"]`);
  if (!el) return toast('That message is further back in main.');
  el.scrollIntoView({ block: 'center' });
  el.classList.remove('flash');
  void el.offsetWidth;
  el.classList.add('flash');
}

function messageEl(rec) {
  const o = rec.obj;
  const mine = rec.pending || rec.entry.author_id === S.me.id;
  const filed = [];
  if (extractUrls(o.text || '').length) filed.push('links');
  if ((o.files || []).length) filed.push('files');
  return h('div', { class: 'msg' + (mine ? ' mine' : '') + (rec.pending ? ' pending' : '') },
    metaLine(rec, rec.status === 'failed' ? h('button', { class: 'small', type: 'button', onclick: () => rec.retry() }, 'Retry') : null),
    o.text ? h('div', { class: 'body' }, linkify(o.text)) : null,
    (o.files || []).length ? h('div', { class: 'attachments' }, ...o.files.map((f) => fileBlock(f))) : null,
    !rec.pending && filed.length
      ? h('div', { class: 'sent-to' }, 'also filed in ', ...filed.flatMap((c, i) => [i ? ' · ' : '', h('a', { href: '#/' + c }, c)]))
      : null);
}

function linkCardEl(ch, rec) {
  const o = rec.obj;
  const href = safeUrl(o.url);
  const title = o.title || (href ? hostOf(href) : o.url);
  const bookmark = ch.kind === 'bookmarks';
  return h('div', { class: 'card-item' },
    metaLine(rec, originLink(rec)),
    h('div', { class: 'title' }, href ? h('a', { href, target: '_blank', rel: 'noopener noreferrer nofollow' }, title) : title),
    h('div', { class: 'url' }, href || o.url),
    o.note ? h('div', { class: 'note' }, o.note) : null,
    (o.tags || []).length ? h('div', { class: 'tags' }, ...o.tags.map((t) => h('span', { class: 'tag' }, t))) : null,
    h('div', { class: 'actions' },
      bookmark ? null : h('button', { class: 'small', type: 'button', onclick: () => postSide('bookmarks', { v: 1, kind: 'bookmark', url: o.url, title: o.title || '', note: '', tags: [] }, 'Saved to bookmarks') }, 'Bookmark'),
      h('button', { class: 'small', type: 'button', onclick: () => shareToMain({ text: (o.title ? o.title + '\n' : '') + o.url, files: [] }) }, 'Share in main')));
}

function fileCardEl(ch, rec) {
  const o = rec.obj;
  return h('div', { class: 'card-item' },
    metaLine(rec, originLink(rec)),
    fileBlock(o),
    o.note ? h('div', { class: 'note' }, o.note) : null,
    h('div', { class: 'actions' },
      h('button', { class: 'small', type: 'button', onclick: () => shareToMain({ text: o.note || '', files: [pickFile(o)] }) }, 'Share in main')));
}

const pickFile = (o) => ({ blob: o.blob, name: o.name, mime: o.mime, size: o.size });

// ---------- files ----------

async function fetchPlain(f) {
  return decryptBlob(S.chKey, await api.getBlob(f.blob));
}

function fileBlock(f) {
  const box = h('div', { class: 'file' });
  const img = h('div', {});
  const isImg = IMG_TYPES.has(f.mime);
  const preview = async (btn) => {
    if (btn) btn.disabled = true;
    try {
      const url = URL.createObjectURL(new Blob([await fetchPlain(f)], { type: f.mime }));
      const im = h('img', { alt: f.name, loading: 'lazy' });
      im.onload = () => URL.revokeObjectURL(url);
      im.src = url;
      img.replaceChildren(im);
      if (btn) btn.remove();
    } catch {
      toast('Could not open ' + f.name);
      if (btn) btn.disabled = false;
    }
  };
  const actions = h('div', { class: 'actions' });
  if (f.uploading) {
    actions.append(h('span', { class: 'muted small' }, 'uploading…'));
  } else {
    actions.append(h('button', { class: 'small', type: 'button', onclick: (ev) => download(f, ev.currentTarget) }, 'Download'));
    if (isImg && f.size > AUTO_PREVIEW_MAX) {
      actions.prepend(h('button', { class: 'small', type: 'button', onclick: (ev) => preview(ev.currentTarget) }, 'Preview'));
    }
  }
  box.append(h('div', { class: 'fname' }, '📄 ' + f.name, h('span', { class: 'muted small' }, '  ' + fmtSize(f.size))), img, actions);
  if (!f.uploading && isImg && f.size <= AUTO_PREVIEW_MAX) preview();
  return box;
}

async function download(f, btn) {
  btn.disabled = true;
  try {
    // Octet-stream, never the real type: a shared HTML/SVG file must not run in our origin.
    const url = URL.createObjectURL(new Blob([await fetchPlain(f)], { type: 'application/octet-stream' }));
    const a = h('a', { href: url, download: f.name.replace(/[\\/]/g, '_') });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  } catch {
    toast('Download failed');
  } finally {
    btn.disabled = false;
  }
}

async function uploadFile(file) {
  if (file.size > S.maxFile) throw new Error(`${file.name} is larger than ${fmtSize(S.maxFile)}`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const { id } = await api.putBlob(await encryptBlob(S.chKey, bytes));
  return { blob: id, name: file.name, mime: file.type || 'application/octet-stream', size: file.size };
}

// ---------- sending ----------

async function build({ channel, cid, obj }) {
  const meta = { channel, epoch: S.epoch, authorId: S.me.id };
  const { ct, sig } = await encryptEntry(S.chKey, S.keys.signPriv, meta, obj);
  return { channel, cid, epoch: S.epoch, ct, sig };
}

// WebSocket first (no per-message HTTP overhead); HTTP if the socket is down.
// Both are idempotent on cid, so a retry after an ambiguous failure is safe.
async function transmit(payload) {
  let res;
  try {
    res = await S.sock.request('send', payload);
  } catch (e) {
    if (e.fromServer) throw e;
    res = await api.send(payload);
  }
  return res.entries;
}

async function sendSpecs(primary, mirrorSpecs = []) {
  const built = await Promise.all([primary, ...mirrorSpecs].map(build));
  const entries = await transmit({ ...built[0], mirrors: built.slice(1) });
  await Promise.all(entries.map((e) => ingest(e)));
}

async function postMain(text, files) {
  const ch = S.chan.get('main');
  const cid = randomId();
  const rec = {
    pending: true, status: 'sending', cid,
    obj: { v: 1, text, files: files.map((f) => ({ name: f.name, size: f.size, mime: f.type, uploading: true })) },
  };
  ch.byCid.set(cid, rec);
  place(ch, rec);

  rec.retry = async () => {
    rec.status = 'sending';
    place(ch, rec);
    try {
      rec.uploaded = rec.uploaded || (await Promise.all(files.map(uploadFile)));
      const urls = extractUrls(text);
      // Anything linkable or attachable is also filed in the matching side
      // channel, in the same transaction as the message itself.
      const mirrors = [
        ...urls.map((url, i) => ({
          channel: 'links', cid: `${cid}-l${i}`,
          obj: { v: 1, kind: 'link', url, title: '', note: stripUrls(text).slice(0, 200) },
        })),
        ...rec.uploaded.map((f, i) => ({ channel: 'files', cid: `${cid}-f${i}`, obj: { v: 1, kind: 'file', ...f, note: '' } })),
      ];
      await sendSpecs({ channel: 'main', cid, obj: { v: 1, text, files: rec.uploaded } }, mirrors);
    } catch (e) {
      rec.status = 'failed';
      place(ch, rec);
      toast(e.message || 'Send failed');
    }
  };
  rec.retry();
}

// Share an existing side-channel item into main. Not re-filed (it already
// lives in a side channel), so no mirrors.
async function shareToMain({ text, files }) {
  try {
    await sendSpecs({ channel: 'main', cid: randomId(), obj: { v: 1, text, files } });
    toast('Shared in main');
  } catch (e) {
    toast(e.message || 'Could not share');
  }
}

// A quiet post: stored in one side channel, nothing goes to main.
async function postSide(channel, obj, okMsg) {
  try {
    await sendSpecs({ channel, cid: randomId(), obj });
    if (okMsg) toast(okMsg);
    return true;
  } catch (e) {
    toast(e.message || 'Could not post');
    return false;
  }
}

// ---------- composers ----------

function buildComposer(ch) {
  return { stream: streamComposer, links: linkComposer, bookmarks: linkComposer, files: fileComposer }[ch.kind](ch);
}

function streamComposer(ch) {
  let files = [];
  const chips = h('div', { class: 'chips' });
  const ta = h('textarea', { rows: 1, placeholder: 'Message', 'aria-label': 'Message' });
  const picker = h('input', { type: 'file', multiple: true, hidden: true });
  const form = h('form', {});

  const drawChips = () => chips.replaceChildren(...files.map((f, i) =>
    h('span', { class: 'chip' }, '📎 ' + f.name + ' ', h('span', { class: 'muted' }, fmtSize(f.size)),
      h('button', { class: 'x', type: 'button', 'aria-label': 'Remove', onclick: () => { files.splice(i, 1); drawChips(); } }, '✕'))));
  ch.addFiles = (list) => {
    for (const f of list) {
      if (f.size > S.maxFile) toast(`${f.name} is larger than ${fmtSize(S.maxFile)}`);
      else files.push(f);
    }
    drawChips();
  };
  const grow = () => { ta.style.height = 'auto'; ta.style.height = Math.min(ta.scrollHeight, window.innerHeight * 0.4) + 'px'; };

  picker.onchange = () => { ch.addFiles([...picker.files]); picker.value = ''; };
  ta.addEventListener('input', grow);
  ta.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); form.requestSubmit(); }
  });
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const text = ta.value.trim();
    if (!text && !files.length) return;
    const f = files;
    files = [];
    ta.value = '';
    grow();
    drawChips();
    postMain(text, f);
  });
  form.append(
    chips,
    h('div', { class: 'row' },
      h('button', { type: 'button', title: 'Attach files', 'aria-label': 'Attach files', onclick: () => picker.click() }, '📎'),
      ta, picker,
      h('button', { class: 'primary', type: 'submit' }, 'Send')),
    h('div', { class: 'hint' }, 'Enter to send, Shift+Enter for a new line. Links and files are also filed in the side channels.'));
  return form;
}

function linkComposer(ch) {
  const bookmark = ch.kind === 'bookmarks';
  const url = h('input', { type: 'url', required: true, placeholder: 'https://…', 'aria-label': 'URL' });
  const title = h('input', { placeholder: 'Title (optional)', 'aria-label': 'Title', maxLength: 200 });
  const tags = bookmark ? h('input', { placeholder: 'Tags, comma separated', 'aria-label': 'Tags' }) : null;
  const note = h('input', { placeholder: 'Note (optional)', 'aria-label': 'Note', maxLength: 500, class: bookmark ? 'wide' : '' });
  const btn = h('button', { class: 'primary', type: 'submit' }, bookmark ? 'Save bookmark' : 'Post link');
  const form = h('form', {},
    h('div', { class: 'fields' }, h('div', { class: 'wide row' }, url, btn), title, tags || note, tags ? note : null),
    h('div', { class: 'hint' }, 'Posted quietly to this channel only. Main is not notified.'));
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const href = safeUrl(url.value);
    if (!href) return toast('Enter an http(s) link');
    btn.disabled = true;
    const obj = { v: 1, kind: bookmark ? 'bookmark' : 'link', url: href, title: title.value.trim(), note: note.value.trim() };
    if (bookmark) obj.tags = tags.value.split(',').map((t) => t.trim()).filter(Boolean).slice(0, 10);
    if (await postSide(ch.meta.id, obj)) form.reset();
    btn.disabled = false;
    url.focus();
  });
  return form;
}

function fileComposer(ch) {
  const picker = h('input', { type: 'file', multiple: true, 'aria-label': 'Files' });
  const note = h('input', { placeholder: 'Note (optional)', 'aria-label': 'Note', maxLength: 500 });
  const btn = h('button', { class: 'primary', type: 'submit' }, 'Upload');
  const form = h('form', {},
    h('div', { class: 'row' }, picker, note, btn),
    h('div', { class: 'hint' }, 'Encrypted in your browser before upload. Posted quietly: main is not notified.'));
  ch.addFiles = (list) => {
    const dt = new DataTransfer();
    for (const f of list) dt.items.add(f);
    picker.files = dt.files;
  };
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const list = [...picker.files];
    if (!list.length) return toast('Choose a file first');
    btn.disabled = true;
    btn.textContent = 'Uploading…';
    let ok = true;
    for (const f of list) {
      try {
        const info = await uploadFile(f);
        ok = (await postSide('files', { v: 1, kind: 'file', ...info, note: note.value.trim() })) && ok;
      } catch (e) {
        ok = false;
        toast(e.message || 'Upload failed');
      }
    }
    if (ok) form.reset();
    btn.disabled = false;
    btn.textContent = 'Upload';
  });
  return form;
}

// Drag and drop / paste anywhere on the pane when the channel takes files.
const pane = $('pane');
pane.addEventListener('dragover', (ev) => {
  const ch = S.chan.get(S.active);
  if (ch && ch.addFiles && ev.dataTransfer && [...ev.dataTransfer.types].includes('Files')) {
    ev.preventDefault();
    pane.classList.add('dropping');
  }
});
pane.addEventListener('dragleave', (ev) => { if (ev.target === pane || !pane.contains(ev.relatedTarget)) pane.classList.remove('dropping'); });
pane.addEventListener('drop', (ev) => {
  pane.classList.remove('dropping');
  const ch = S.chan.get(S.active);
  if (ch && ch.addFiles && ev.dataTransfer.files.length) { ev.preventDefault(); ch.addFiles([...ev.dataTransfer.files]); }
});
document.addEventListener('paste', (ev) => {
  const ch = S.chan.get(S.active);
  if (!ch || !ch.addFiles || !ev.clipboardData.files.length) return;
  ev.preventDefault();
  ch.addFiles([...ev.clipboardData.files]);
});

// ---------- unread / notifications ----------

const visible = () => !document.hidden;

async function onEntry(e) {
  const ch = S.chan.get(e.channel);
  if (!ch) return;
  ch.meta.last_id = Math.max(ch.meta.last_id || 0, e.id);
  await ingest(e);
  if (e.author_id === S.me.id) return;
  if (e.channel === S.active && visible()) return markRead(ch);
  // Side-channel arrivals only get a quiet badge; only the stream counts
  // toward the tab title (see renderSidebar).
  ch.meta.unread++;
  renderSidebar();
}

let readTimer;
function markRead(ch) {
  if (!ch.meta.unread) return;
  const upto = Math.max(ch.newest(), ch.meta.last_id || 0);
  ch.meta.unread = 0;
  renderSidebar();
  clearTimeout(readTimer);
  readTimer = setTimeout(() => {
    if (S.sock.open) S.sock.notify('read', { channel: ch.meta.id, upto });
    else api.read(ch.meta.id, upto).catch(() => {});
  }, 250);
}

function onVisible() {
  const ch = S.chan.get(S.active);
  if (ch && visible()) markRead(ch);
}

// ---------- members ----------

function updatePending() {
  const n = [...S.users.values()].filter((u) => !u.member).length;
  const b = $('pending-badge');
  b.hidden = n === 0;
  b.textContent = n;
  b.classList.toggle('loud', n > 0);
}

$('btn-members').onclick = () => showMembers();

async function approve(u) {
  const warn = u.keyChanged ? `\n\nWARNING: ${u.username}'s keys changed since you first saw them.` : '';
  if (!confirm(`Give ${u.username} access to every message?\n\nTheir key fingerprint:\n${u.fp}\n\nCheck it matches what they see on their screen.${warn}`)) return;
  try {
    const sealed = await sealKey(u.enc_pub, S.chRaw);
    const sig = await signGrant(S.keys.signPriv, u.username, S.epoch, sealed);
    await api.grant(u.username, { epoch: S.epoch, sealed, sig });
    toast(`${u.username} can now read and post`);
  } catch (e) {
    toast(e.message || 'Could not approve');
  }
}

function showMembers() {
  const users = [...S.users.values()].sort((a, b) => a.id - b.id);
  const row = (u) => h('div', { class: 'member' },
    h('div', { class: 'info' },
      h('div', {}, h('strong', {}, u.username), u.id === S.me.id ? ' (you)' : '', u.member ? '' : h('span', { class: 'muted' }, ' · waiting')),
      h('code', { class: 'small muted' }, u.fp || ''),
      u.keyChanged ? h('div', { class: 'error small' }, '⚠ keys changed since first seen') : null),
    u.member ? null : h('button', { class: 'primary small', type: 'button', onclick: () => approve(u) }, 'Approve'));
  openDialog(
    h('h2', {}, 'Members'),
    h('p', { class: 'muted small' }, 'Compare fingerprints with people over another channel (in person, a call) to be sure no one is impersonating them.'),
    ...users.map(row),
    S.granter && S.granter.id !== S.me.id ? h('p', { class: 'muted small' }, `You were admitted by ${S.granter.username}.`) : null,
    h('div', { class: 'actions' }, h('button', { type: 'button', onclick: closeDialog }, 'Close')));
  $('dlg').dataset.kind = 'members';
}
$('dlg').addEventListener('close', () => delete $('dlg').dataset.kind);

// ---------- go ----------

start().catch((e) => {
  console.error(e);
  toast(e.message || 'Failed to start');
  showAuth();
});
