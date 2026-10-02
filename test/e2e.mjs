// End-to-end check of the browser crypto (web/js/crypto.js) against a running
// server. Usage: node test/e2e.mjs http://localhost:8080   (fresh database!)
import * as C from '../web/js/crypto.js';
import assert from 'node:assert/strict';

const base = process.argv[2] || 'http://localhost:8080';
async function call(method, path, token, body) {
  const res = await fetch(base + path, {
    method,
    headers: { ...(token && { Authorization: 'Bearer ' + token }), ...(body && !(body instanceof Uint8Array) && { 'Content-Type': 'application/json' }) },
    body: body instanceof Uint8Array ? body : body && JSON.stringify(body),
  });
  const data = (res.headers.get('content-type') || '').includes('json') ? await res.json() : await res.arrayBuffer();
  return { status: res.status, data };
}
const ok = (r, want = 200) => { assert.equal(r.status, want, JSON.stringify(r.data)); return r.data; };

async function signUp(name, pw) {
  const { auth, wrapKey } = await C.deriveFromPassword(name, pw);
  const id = await C.createIdentity(wrapKey);
  const keys = await C.unwrapIdentity(wrapKey, id.wrapped);
  const sealed = await C.sealKey(id.encPub, C.newChannelKey());
  const sig = await C.signGrant(keys.signPriv, name, 1, sealed);
  const r = ok(await call('POST', '/api/register', null, {
    username: name, auth, enc_pub: id.encPub, sign_pub: id.signPub, wrapped_keys: id.wrapped, bootstrap: { epoch: 1, sealed, sig },
  }), 201);
  return { name, token: r.token, keys, granted: r.granted, user: r.user };
}

async function unlock(u) {
  const me = ok(await call('GET', '/api/me', u.token));
  assert.ok(me.envelope, `${u.name} has no envelope`);
  assert.ok(await C.verifyGrant(me.granter.sign_pub, me.envelope.sig, u.name, me.envelope.epoch, me.envelope.sealed), 'grant signature');
  const raw = await C.unsealKey(u.keys.encPriv, me.user.enc_pub, me.envelope.sealed);
  return { raw, key: await C.importChannelKey(raw), me: me.user };
}

const alice = await signUp('alice', 'correct horse battery');
assert.equal(alice.granted, true, 'first user bootstraps the channel');
const a = await unlock(alice);

const bob = await signUp('bob', 'another long password');
assert.equal(bob.granted, false, 'second user is pending');
assert.equal((await call('GET', '/api/channels', bob.token)).status, 403);

// Alice approves Bob.
const users = ok(await call('GET', '/api/users', alice.token));
const bobPub = users.find((u) => u.username === 'bob');
const sealed = await C.sealKey(bobPub.enc_pub, a.raw);
ok(await call('POST', '/api/users/bob/grant', alice.token, { epoch: 1, sealed, sig: await C.signGrant(alice.keys.signPriv, 'bob', 1, sealed) }));
const b = await unlock(bob);
assert.deepEqual(b.raw, a.raw, 'both members hold the same channel key');
console.log('✓ join + approve: bob recovered the channel key');

// Messages round-trip, with a link mirrored into the links channel.
const meta = (channel) => ({ channel, epoch: 1, authorId: a.me.id });
const main = await C.encryptEntry(a.key, alice.keys.signPriv, meta('main'), { v: 1, text: 'look https://example.com/x', files: [] });
const link = await C.encryptEntry(a.key, alice.keys.signPriv, meta('links'), { v: 1, kind: 'link', url: 'https://example.com/x' });
const sent = ok(await call('POST', '/api/entries', alice.token, {
  channel: 'main', cid: 'e2e-main-000001', epoch: 1, ...main, mirrors: [{ channel: 'links', cid: 'e2e-main-000001-l0', epoch: 1, ...link }],
}), 201);
assert.equal(sent.entries.length, 2);

const aliceUser = users.find((u) => u.username === 'alice');
const got = ok(await call('GET', '/api/channels/main/entries', bob.token));
assert.equal(got.length, 1);
const dec = await C.decryptEntry(b.key, got[0], aliceUser.sign_pub);
assert.equal(dec.obj.text, 'look https://example.com/x');
assert.equal(dec.verified, true, 'signature verifies against the author');
const gl = ok(await call('GET', '/api/channels/links/entries', bob.token));
assert.equal(gl[0].origin_id, got[0].id);
assert.equal((await C.decryptEntry(b.key, gl[0], aliceUser.sign_pub)).obj.url, 'https://example.com/x');
console.log('✓ message + mirrored link decrypt and verify');

// Tampering: the server cannot move an entry between channels or authors.
await assert.rejects(C.decryptEntry(b.key, { ...got[0], channel: 'links' }, aliceUser.sign_pub), 'channel swap');
await assert.rejects(C.decryptEntry(b.key, { ...got[0], author_id: 999 }, aliceUser.sign_pub), 'author swap');
const bobPubKey = users.find((u) => u.username === 'bob').sign_pub;
assert.equal((await C.decryptEntry(b.key, got[0], bobPubKey)).verified, false, 'wrong signer is flagged');
console.log('✓ tampering is detected');

// Files.
const payload = crypto.getRandomValues(new Uint8Array(50_000));
const up = ok(await call('PUT', '/api/blobs', alice.token, await C.encryptBlob(a.key, payload)), 201);
const back = await call('GET', '/api/blobs/' + up.id, bob.token);
assert.deepEqual(new Uint8Array(await C.decryptBlob(b.key, back.data)), payload);
console.log('✓ encrypted file round trip');

// Login derives the same auth secret and unlocks the same keys; a wrong password cannot.
const { auth, wrapKey } = await C.deriveFromPassword('alice', 'correct horse battery');
const login = ok(await call('POST', '/api/login', null, { username: 'alice', auth }));
await C.unwrapIdentity(wrapKey, login.wrapped_keys);
const bad = await C.deriveFromPassword('alice', 'wrong password!!');
assert.equal((await call('POST', '/api/login', null, { username: 'alice', auth: bad.auth })).status, 401);
await assert.rejects(C.unwrapIdentity(bad.wrapKey, login.wrapped_keys));
assert.notEqual(auth, bad.auth);
console.log('✓ login and key unwrapping');

console.log('all good');
