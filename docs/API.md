# API

JSON over HTTP plus a WebSocket for live traffic. The server is a blind relay: every
payload below marked *(ciphertext)* is produced by the client. `web/js/crypto.js` is the
reference implementation of the crypto; `test/e2e.mjs` shows a full flow.

Encodings: **base64url, unpadded** everywhere. Public keys are raw uncompressed P-256 points
(65 bytes). Signatures are WebCrypto-style raw `r||s` (64 bytes).

## Auth

Browsers get an `HttpOnly; SameSite=Strict` cookie `sid`. Other clients use the `token`
returned by register/login as `Authorization: Bearer <token>`. Sessions last 30 days.
State-changing requests with a foreign `Origin` header are refused.

| Method & path | Body → Response |
|---|---|
| `POST /api/register` | `{username, auth, enc_pub, sign_pub, wrapped_keys, bootstrap:{epoch,sealed,sig}}` → `201 {user, granted, token}` |
| `POST /api/login` | `{username, auth}` → `{user, wrapped_keys, envelope?, granter?, token}` |
| `POST /api/logout` | → `204` |
| `GET /api/me` | → `{user, epoch, max_file_bytes, envelope?, granter?}` |

- `username`: 3–32 of `a-z 0-9 _ -` (case-insensitive).
- `auth`: 32 bytes derived client-side (see below); never the password.
- `bootstrap` is honoured only for the very first user (they create the channel key);
  for everyone else it is ignored and `granted` is `false`.
- Login is rate limited (HTTP 429).

### Key derivation

```
root     = PBKDF2-SHA256(NFKC(password), salt="msg/v1/user/"+lower(username), 600000, 32 bytes)
auth     = HKDF-SHA256(root, salt="", info="msg/v1/auth", 32 bytes)
wrap_key = HKDF-SHA256(root, salt="", info="msg/v1/wrap") → AES-256-GCM
wrapped_keys = JSON {v:1, kdf, iv, ct}; ct = AES-GCM(wrap_key, iv, aad="msg/v1/identity",
               JSON{enc: pkcs8(ECDH priv), sign: pkcs8(ECDSA priv)} base64url)
```

## Membership

A new user has no channel key (`member:false`) until a member seals it for them. Pending users
can call `/api/me` and open the WebSocket, and nothing else.

| Method & path | Body → Response |
|---|---|
| `GET /api/users` | → `[{id, username, enc_pub, sign_pub, member}]` |
| `POST /api/users/{username}/grant` | `{epoch, sealed, sig}` → `{user}`; `409` if they already have access |

```
sealed = eph_pub(65) || iv(12) || AES-GCM(key=HKDF(ECDH(eph_priv, recipient_enc_pub), info="msg/v1/seal"),
                                          iv, aad=recipient_enc_pub, plaintext=channel_key(32))     # 125 bytes
sig    = ECDSA-SHA256(granter_sign_priv, "msg/v1/grant\n"+recipient_username+"\n"+epoch+"\n"+sealed)
```

Recipients must verify `sig` against the `granter` returned with their envelope.

## Channels and entries

Channels: `main` (kind `stream`), `links`, `bookmarks`, `files`.

| Method & path | Notes |
|---|---|
| `GET /api/channels` | `[{id, name, kind, unread, last_id}]` |
| `GET /api/channels/{id}/entries?before=ID&after=ID&limit=50` | ascending. Newest page by default; `before` pages back, `after` catches up (limit ≤ 200) |
| `POST /api/channels/{id}/read` | `{upto}`, marks read |
| `POST /api/entries` | send, below |

Entry: `{id, channel, author_id, epoch, cid, ct, sig, origin_id?, created_at}`.

```
aad = "msg/v1/entry|"+channel+"|"+epoch+"|"+author_id
ct  = base64url( iv(12) || AES-256-GCM(channel_key, iv, aad, utf8(JSON)) )
sig = ECDSA-SHA256(author_sign_priv, aad+"|"+ct)
```

Plaintext JSON, by channel:

```
main:      {v:1, text, files:[{blob,name,mime,size}]}
links:     {v:1, kind:"link", url, title, note}
bookmarks: {v:1, kind:"bookmark", url, title, note, tags:[...]}
files:     {v:1, kind:"file", blob, name, mime, size, note}
```

### Sending, and quiet side posts

```json
POST /api/entries
{ "channel":"main", "cid":"<8-64 chars [A-Za-z0-9_-]>", "epoch":1, "ct":"…", "sig":"…",
  "mirrors":[ {"channel":"links","cid":"…","epoch":1,"ct":"…","sig":"…"} ] }
→ 201 {"entries":[ …primary first, then mirrors… ]}
```

- **Main + mirrors:** a main message may carry up to 16 `mirrors`, which must target side
  channels. They are stored in the same transaction and get `origin_id` = the main entry's id.
  The client decides what to mirror (URLs → `links`, attachments → `files`) because only it
  can read the plaintext.
- **Quiet post:** send with `channel` = a side channel and no mirrors. Nothing is written to
  main and no main event fires.
- `cid` makes sends idempotent per author: retrying returns the stored entries and does not
  re-broadcast.
- Limits: `ct` ≤ 90,000 chars; `epoch` must be current (1).

## Files

`PUT /api/blobs` (body: raw bytes, ≤ `max_file_bytes`) → `201 {id, size}`;
`GET /api/blobs/{id}`. Bytes are `iv(12) || AES-GCM(channel_key, iv, aad="msg/v1/blob", file)`.
Put the returned `id` in the entry's `blob` field. Blob responses are `immutable`-cacheable.

## WebSocket

`GET /ws` (cookie or bearer header, same-origin). Text frames of JSON.

Client → server:

```
{"op":"send","rid":"1", …same fields as POST /api/entries…}   → {"op":"ack","rid":"1","entries":[…]}
{"op":"read","channel":"links","upto":123}
{"op":"ping","rid":"p"}                                       → {"op":"pong","rid":"p"}
```

Errors reply `{"op":"error","rid":"1","error":"…"}`.

Server → client:

```
{"op":"hello","member":true}
{"op":"entry","entry":{…},"notify":true}   // notify is true only for the stream (main) channel
{"op":"user","user":{…}}                   // someone registered or was approved
{"op":"granted","envelope":{…},"granter":{…}}   // you were approved while connected
```

Slow consumers are disconnected rather than buffered without bound; on reconnect, fetch
`entries?after=<last id>` per channel to catch up.
