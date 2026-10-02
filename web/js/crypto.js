// All cryptography happens here, in the browser, via WebCrypto. The server
// only ever receives public keys, ciphertext, and a password-wrapped copy of
// the private keys. See docs/API.md for the wire formats.

const te = new TextEncoder();
const td = new TextDecoder();
const subtle = crypto.subtle;

const PBKDF2_ITER = 600_000;
const EC = { name: 'ECDH', namedCurve: 'P-256' };
const ES = { name: 'ECDSA', namedCurve: 'P-256' };
const SIG = { name: 'ECDSA', hash: 'SHA-256' };

export const b64u = {
  enc(buf) {
    const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  dec(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};

const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
export const randomId = () => b64u.enc(rand(12));

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// ---- password -> (auth secret, wrapping key) ----

// One slow PBKDF2 pass yields a root key; HKDF splits it into the secret sent
// to the server for login and a key that never leaves the browser and wraps
// the private keys. The server therefore cannot unwrap them.
export async function deriveFromPassword(username, password) {
  const pw = await subtle.importKey('raw', te.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const root = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', iterations: PBKDF2_ITER, salt: te.encode('msg/v1/user/' + username.toLowerCase()) },
    pw, 256);
  const hk = await subtle.importKey('raw', root, 'HKDF', false, ['deriveBits', 'deriveKey']);
  const info = (s) => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(s) });
  const [auth, wrapKey] = await Promise.all([
    subtle.deriveBits(info('msg/v1/auth'), hk, 256),
    subtle.deriveKey(info('msg/v1/wrap'), hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
  ]);
  return { auth: b64u.enc(auth), wrapKey };
}

// ---- identity keys ----

// Returns the public halves (base64url, for the server) and the wrapped
// private keys (opaque JSON string, for the server to store).
export async function createIdentity(wrapKey) {
  const [encKP, signKP] = await Promise.all([
    subtle.generateKey(EC, true, ['deriveBits']),
    subtle.generateKey(ES, true, ['sign', 'verify']),
  ]);
  const [encPub, signPub, encPriv, signPriv] = await Promise.all([
    subtle.exportKey('raw', encKP.publicKey),
    subtle.exportKey('raw', signKP.publicKey),
    subtle.exportKey('pkcs8', encKP.privateKey),
    subtle.exportKey('pkcs8', signKP.privateKey),
  ]);
  const iv = rand(12);
  const plain = te.encode(JSON.stringify({ enc: b64u.enc(encPriv), sign: b64u.enc(signPriv) }));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode('msg/v1/identity') }, wrapKey, plain);
  return {
    encPub: b64u.enc(encPub),
    signPub: b64u.enc(signPub),
    wrapped: JSON.stringify({ v: 1, kdf: 'pbkdf2-sha256/' + PBKDF2_ITER, iv: b64u.enc(iv), ct: b64u.enc(ct) }),
  };
}

// Unwraps and re-imports the private keys as non-extractable CryptoKeys, so
// page script can use them but never read the raw bytes back out.
export async function unwrapIdentity(wrapKey, wrapped) {
  const w = JSON.parse(wrapped);
  let plain;
  try {
    plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: b64u.dec(w.iv), additionalData: te.encode('msg/v1/identity') }, wrapKey, b64u.dec(w.ct));
  } catch {
    throw new Error('could not unlock keys');
  }
  const k = JSON.parse(td.decode(plain));
  const [encPriv, signPriv] = await Promise.all([
    subtle.importKey('pkcs8', b64u.dec(k.enc), EC, false, ['deriveBits']),
    subtle.importKey('pkcs8', b64u.dec(k.sign), ES, false, ['sign']),
  ]);
  return { encPriv, signPriv };
}

// Short human-comparable digest of a user's public keys.
export async function fingerprint(encPub, signPub) {
  const d = new Uint8Array(await subtle.digest('SHA-256', concat(b64u.dec(encPub), b64u.dec(signPub))));
  const hex = [...d.subarray(0, 10)].map((x) => x.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{4}/g).join(' ');
}

// ---- channel key sealing (ECIES-style, signed by the granter) ----

async function hkdfAes(secret, info, usages) {
  const hk = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(info) },
    hk, { name: 'AES-GCM', length: 256 }, false, usages);
}

export const newChannelKey = () => rand(32);

export async function importChannelKey(raw) {
  return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

// sealed = ephemeralPub(65) || iv(12) || AES-GCM(shared, channelKey)
export async function sealKey(recipientEncPub, rawKey) {
  const eph = await subtle.generateKey(EC, true, ['deriveBits']);
  const rb = b64u.dec(recipientEncPub);
  const recip = await subtle.importKey('raw', rb, EC, false, []);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: recip }, eph.privateKey, 256);
  const aes = await hkdfAes(shared, 'msg/v1/seal', ['encrypt']);
  const iv = rand(12);
  const ephPub = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: rb }, aes, rawKey));
  return b64u.enc(concat(ephPub, iv, ct));
}

export async function unsealKey(encPriv, myEncPub, sealed) {
  const b = b64u.dec(sealed);
  const ephPub = await subtle.importKey('raw', b.subarray(0, 65), EC, false, []);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: ephPub }, encPriv, 256);
  const aes = await hkdfAes(shared, 'msg/v1/seal', ['decrypt']);
  const raw = await subtle.decrypt(
    { name: 'AES-GCM', iv: b.subarray(65, 77), additionalData: b64u.dec(myEncPub) }, aes, b.subarray(77));
  return new Uint8Array(raw);
}

const grantMsg = (username, epoch, sealed) => te.encode(`msg/v1/grant\n${username}\n${epoch}\n${sealed}`);

export async function signGrant(signPriv, username, epoch, sealed) {
  return b64u.enc(await subtle.sign(SIG, signPriv, grantMsg(username, epoch, sealed)));
}

export async function verifyGrant(granterSignPub, sig, username, epoch, sealed) {
  const k = await importVerifyKey(granterSignPub);
  return subtle.verify(SIG, k, b64u.dec(sig), grantMsg(username, epoch, sealed));
}

// ---- entries ----

const verifyKeys = new Map();
async function importVerifyKey(signPub) {
  let k = verifyKeys.get(signPub);
  if (!k) {
    k = subtle.importKey('raw', b64u.dec(signPub), ES, false, ['verify']);
    verifyKeys.set(signPub, k);
  }
  return k;
}

// The AAD binds each ciphertext to its channel, key epoch and author, so the
// server cannot replay an entry elsewhere or under another name.
const aadOf = (channel, epoch, authorId) => `msg/v1/entry|${channel}|${epoch}|${authorId}`;

export async function encryptEntry(chKey, signPriv, { channel, epoch, authorId }, obj) {
  const iv = rand(12);
  const aad = aadOf(channel, epoch, authorId);
  const ct = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: te.encode(aad) }, chKey, te.encode(JSON.stringify(obj))));
  const ctB = b64u.enc(concat(iv, ct));
  const sig = await subtle.sign(SIG, signPriv, te.encode(aad + '|' + ctB));
  return { ct: ctB, sig: b64u.enc(sig) };
}

// Returns { obj, verified }. verified is false if the signature does not
// match the author's pinned signing key (or the key is unknown).
export async function decryptEntry(chKey, entry, authorSignPub) {
  const aad = aadOf(entry.channel, entry.epoch, entry.author_id);
  const b = b64u.dec(entry.ct);
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv: b.subarray(0, 12), additionalData: te.encode(aad) }, chKey, b.subarray(12));
  let verified = false;
  if (authorSignPub) {
    try {
      verified = await subtle.verify(SIG, await importVerifyKey(authorSignPub), b64u.dec(entry.sig), te.encode(aad + '|' + entry.ct));
    } catch { /* leave unverified */ }
  }
  return { obj: JSON.parse(td.decode(plain)), verified };
}

// ---- file blobs ----

export async function encryptBlob(chKey, bytes) {
  const iv = rand(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode('msg/v1/blob') }, chKey, bytes);
  return concat(iv, new Uint8Array(ct));
}

export async function decryptBlob(chKey, buf) {
  const b = new Uint8Array(buf);
  return subtle.decrypt({ name: 'AES-GCM', iv: b.subarray(0, 12), additionalData: te.encode('msg/v1/blob') }, chKey, b.subarray(12));
}
