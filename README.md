# msg

A small, fast, end-to-end encrypted group chat for the web, with an HTTP/WebSocket API.

There is one main chat channel, plus **side channels** for links, bookmarks and files:

- A link or file shared in **main** is automatically filed in the matching side channel.
- You can post to a side channel **directly**, and main is never notified. Found something
  cool that isn't worth interrupting everyone for? Drop it in *links* or *bookmarks*.
- Only main raises a badge in the tab title; side channels get a quiet count in the sidebar.

## Run it

```sh
go run ./cmd/msgd                 # http://localhost:8080, data in ./data
go run ./cmd/msgd -addr :8443 -tls-cert cert.pem -tls-key key.pem
```

Flags: `-addr`, `-data`, `-max-file-mb` (25), `-tls-cert/-tls-key`, `-trust-proxy`
(honour `X-Forwarded-*` behind a reverse proxy).

The browser's WebCrypto API only works in a **secure context**: `localhost`, or HTTPS.
Anywhere else, serve it over TLS (built-in flags, or a reverse proxy with `-trust-proxy`).

The first account to sign up creates the channel. Everyone after that is *pending* until an
existing member approves them from **Members** (this is what hands them the channel key).

## Tests

```sh
go test -race ./...                       # server, WebSocket, validation, latency report
go run ./cmd/msgd -addr :18080 -data /tmp/e2e &   # then, against that fresh server:
node test/e2e.mjs http://localhost:18080  # the real browser crypto against the real server
```

## How the encryption works

Everything is generated and used in the browser (WebCrypto). The server stores only public
keys, ciphertext and a password-wrapped blob it cannot open.

| Thing | How |
|---|---|
| Identity | Per user: ECDH P-256 (key agreement) and ECDSA P-256 (signing) keypairs, made at sign-up |
| Password | PBKDF2-SHA256 (600k) → HKDF into an **auth secret** (sent to the server, which stores an argon2id hash) and a **wrap key** (never leaves the browser) |
| Private keys | AES-GCM-wrapped with the wrap key; the server keeps the blob so you can sign in anywhere |
| Channel key | One random AES-256-GCM key. Each member holds it sealed to their ECDH public key, signed by whoever granted it |
| Messages | AES-GCM under the channel key; AAD binds channel + epoch + author; each entry is ECDSA-signed |
| Files | AES-GCM in the browser before upload; the server stores opaque bytes |

What the server does see: who posts, to which channel, when, ciphertext sizes, and which
side-channel entries came from which main message. It cannot read content, forge a member's
messages, or move an entry between channels or authors without it being detected.

### Things worth knowing

- **Forgotten password = lost keys.** There is deliberately no reset.
- **Verify fingerprints.** The server distributes public keys, so a malicious server could
  substitute one when someone is approved. Members dialog shows each fingerprint; compare
  them out-of-band. The browser also pins keys on first sight and warns if they change.
- **No forward secrecy / key rotation yet.** One channel key serves all history. Every
  envelope and entry carries an `epoch`, so rotation (e.g. when removing a member) can be
  added without a format change. Removing members isn't implemented.
- **No link previews.** Fetching a URL's title would mean the server (or a third party)
  learns what you shared. Add a title yourself when posting to *links* or *bookmarks*.
- Message deletion and editing are not implemented.

## Latency

- Sends go over the already-open WebSocket and are acknowledged by the same socket. Over
  loopback the server acks in ~0.3 ms (p99 ~1.5 ms), including the SQLite commit.
- The UI shows your own message immediately and reconciles on ack; retries are idempotent.
- SQLite in WAL mode with a dedicated writer and a reader pool; sessions are cached in memory.
- The client is plain ES modules (~62 KB, ~19 KB gzipped), no framework or build step, embedded in the binary, precompressed and ETagged.
- Uploaded ciphertext is cached immutably by the browser.
- Live round-trip time is shown in the sidebar.

## Layout

```
cmd/msgd/          entry point
internal/store/    SQLite persistence
internal/server/   HTTP + WebSocket API, auth, hub
web/               browser client (embedded)
docs/API.md        wire formats for building other clients
test/e2e.mjs       crypto interop test
```
