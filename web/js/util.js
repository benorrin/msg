// DOM and formatting helpers. User content is only ever inserted as text
// nodes or as href values that have passed safeUrl().

export function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k in el) el[k] = v;
    else el.setAttribute(k, v);
  }
  el.append(...kids.flat().filter((k) => k != null && k !== false));
  return el;
}

// Returns a normalised href for http(s) URLs, or null for anything else
// (javascript:, data:, etc.).
export function safeUrl(s) {
  try {
    const u = new URL(String(s).trim());
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}

const URL_RE = /https?:\/\/[^\s<>"'`]+/g;

function trimUrl(u) {
  // Drop trailing sentence punctuation; keep a closing paren only if balanced.
  for (;;) {
    const last = u[u.length - 1];
    if (/[.,;:!?'"\]}]/.test(last)) u = u.slice(0, -1);
    else if (last === ')' && (u.match(/\(/g) || []).length < (u.match(/\)/g) || []).length) u = u.slice(0, -1);
    else return u;
  }
}

export function extractUrls(text) {
  const seen = new Set();
  for (const m of text.matchAll(URL_RE)) {
    const href = safeUrl(trimUrl(m[0]));
    if (href) seen.add(href);
  }
  return [...seen].slice(0, 8);
}

// Text with every URL removed and whitespace collapsed: the "note" that
// accompanies a link filed from a chat message.
export function stripUrls(text) {
  return text.replace(URL_RE, ' ').replace(/\s+/g, ' ').trim();
}

export function linkify(text) {
  const frag = document.createDocumentFragment();
  let last = 0;
  for (const m of text.matchAll(URL_RE)) {
    const raw = trimUrl(m[0]);
    const href = safeUrl(raw);
    if (!href) continue;
    frag.append(text.slice(last, m.index));
    frag.append(h('a', { href, target: '_blank', rel: 'noopener noreferrer nofollow' }, raw));
    last = m.index + raw.length;
  }
  frag.append(text.slice(last));
  return frag;
}

export function hostOf(href) {
  try { return new URL(href).hostname.replace(/^www\./, ''); } catch { return href; }
}

export function fmtSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
  return (n / 1073741824).toFixed(1) + ' GB';
}

export function fmtTime(ms) {
  const d = new Date(ms);
  const t = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (d.toDateString() === new Date().toDateString()) return t;
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + t;
}
