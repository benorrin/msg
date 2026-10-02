package server_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/coder/websocket"

	"msg/internal/server"
	"msg/internal/store"
)

var b64 = base64.RawURLEncoding.EncodeToString

func randB64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return b64(b)
}

func pubKey(t *testing.T) string {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return b64(k.PublicKey().Bytes())
}

type env struct {
	t   *testing.T
	ts  *httptest.Server
	max int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv, err := server.New(server.Config{DataDir: dir, MaxFileBytes: 1024}, st, fstest.MapFS{"index.html": {Data: []byte("<html>")}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &env{t: t, ts: ts}
}

// do performs a JSON request and decodes the reply into a generic map.
func (e *env) do(method, path, token string, body any) (int, any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(mustJSON(body))
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var out any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func (e *env) register(name string, first bool) (token string, granted bool) {
	e.t.Helper()
	code, out := e.do("POST", "/api/register", "", map[string]any{
		"username": name, "auth": randB64(32), "enc_pub": pubKey(e.t), "sign_pub": pubKey(e.t),
		"wrapped_keys": `{"v":1}`,
		"bootstrap":    map[string]any{"epoch": 1, "sealed": randB64(125), "sig": randB64(64)},
	})
	if code != 201 {
		e.t.Fatalf("register %s: %d %v", name, code, out)
	}
	return obj(out)["token"].(string), obj(out)["granted"].(bool)
}

func entry(ch, cid string) map[string]any {
	return map[string]any{"channel": ch, "cid": cid, "epoch": 1, "ct": randB64(60), "sig": randB64(64)}
}

func (e *env) dial(token string) *websocket.Conn {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(e.ts.URL, "http")+"/ws", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { c.CloseNow() })
	return c
}

func next(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	var m map[string]any
	json.Unmarshal(data, &m)
	return m
}

func noMore(t *testing.T, c *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, data, err := c.Read(ctx); err == nil {
		t.Fatalf("unexpected frame: %s", data)
	}
}

func TestJoinApproveAndChannels(t *testing.T) {
	e := newEnv(t)

	alice, granted := e.register("alice", true)
	if !granted {
		t.Fatal("first user should be granted the bootstrap key")
	}
	wa := e.dial(alice)
	if m := next(t, wa); m["op"] != "hello" || m["member"] != true {
		t.Fatalf("alice hello: %v", m)
	}

	// Second user is pending: bootstrap envelope is ignored, content is refused.
	bob, granted := e.register("bob", true)
	if granted {
		t.Fatal("second user must not self-grant")
	}
	if m := next(t, wa); m["op"] != "user" {
		t.Fatalf("alice should hear about bob: %v", m)
	}
	if code, _ := e.do("GET", "/api/channels", bob, nil); code != 403 {
		t.Fatalf("pending user channels: %d", code)
	}
	if code, _ := e.do("POST", "/api/entries", bob, entry("main", "bob-cid-0001")); code != 403 {
		t.Fatalf("pending user send: %d", code)
	}
	if code, _ := e.do("GET", "/api/me", bob, nil); code != 200 {
		t.Fatalf("pending user /me: %d", code)
	}
	wb := e.dial(bob)
	if m := next(t, wb); m["member"] != false {
		t.Fatalf("bob hello: %v", m)
	}

	// Duplicate names and unauthenticated access.
	if code, _ := e.do("POST", "/api/register", "", map[string]any{"username": "ALICE"}); code != 400 && code != 409 {
		t.Fatalf("dup register: %d", code)
	}
	if code, _ := e.do("GET", "/api/users", "", nil); code != 401 {
		t.Fatalf("anon users: %d", code)
	}

	// Alice approves Bob; Bob's open socket is promoted live.
	grant := map[string]any{"epoch": 1, "sealed": randB64(125), "sig": randB64(64)}
	if code, out := e.do("POST", "/api/users/bob/grant", alice, grant); code != 200 {
		t.Fatalf("grant: %d %v", code, out)
	}
	if code, _ := e.do("POST", "/api/users/bob/grant", alice, grant); code != 409 {
		t.Fatalf("second grant must conflict: %d", code)
	}
	if m := next(t, wb); m["op"] != "granted" {
		t.Fatalf("bob should be told: %v", m)
	}
	// Everyone who is now a member, Bob included, hears the roster change.
	if m := next(t, wb); m["op"] != "user" {
		t.Fatalf("bob roster event: %v", m)
	}
	next(t, wa)

	// A main message with a link and a file mirrored into the side channels.
	body := entry("main", "cid-main-0001")
	body["mirrors"] = []any{entry("links", "cid-main-0001-l0"), entry("files", "cid-main-0001-f0")}
	code, out := e.do("POST", "/api/entries", alice, body)
	if code != 201 {
		t.Fatalf("send: %d %v", code, out)
	}
	entries := obj(out)["entries"].([]any)
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(entries))
	}
	mainID := entries[0].(map[string]any)["id"].(float64)
	for _, x := range entries[1:] {
		if x.(map[string]any)["origin_id"] != mainID {
			t.Fatalf("mirror origin_id mismatch: %v", x)
		}
	}
	notified := map[string]bool{}
	for i := 0; i < 3; i++ {
		m := next(t, wb)
		notified[m["entry"].(map[string]any)["channel"].(string)] = m["notify"].(bool)
	}
	if !notified["main"] || notified["links"] || notified["files"] {
		t.Fatalf("only main may notify: %v", notified)
	}

	// Retrying the same cid is idempotent.
	_, again := e.do("POST", "/api/entries", alice, body)
	if obj(again)["entries"].([]any)[0].(map[string]any)["id"] != mainID {
		t.Fatal("retry created a duplicate")
	}
	noMore(t, wb) // and a retry must not be broadcast a second time
	_, list := e.do("GET", "/api/channels/main/entries", bob, nil)
	if n := len(list.([]any)); n != 1 {
		t.Fatalf("main should hold exactly 1 entry, has %d", n)
	}
}

func TestQuietSidePostAndValidation(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.register("alice", true)
	wa := e.dial(alice)
	next(t, wa)

	// Direct side post, over the websocket.
	ctx := context.Background()
	f := entry("bookmarks", "bookmark-cid-1")
	f["op"], f["rid"] = "send", "r1"
	wa.Write(ctx, websocket.MessageText, mustJSON(f))
	var gotAck, gotEntry bool
	for i := 0; i < 2; i++ {
		m := next(t, wa)
		switch m["op"] {
		case "ack":
			gotAck = m["rid"] == "r1"
		case "entry":
			gotEntry = m["notify"] == false && m["entry"].(map[string]any)["channel"] == "bookmarks"
		}
	}
	if !gotAck || !gotEntry {
		t.Fatalf("ack=%v quiet entry=%v", gotAck, gotEntry)
	}
	if _, out := e.do("GET", "/api/channels/main/entries", alice, nil); len(out.([]any)) != 0 {
		t.Fatal("a side post must not appear in main")
	}
	if _, out := e.do("GET", "/api/channels/bookmarks/entries", alice, nil); len(out.([]any)) != 1 {
		t.Fatal("side post missing from bookmarks")
	}

	// Validation.
	bad := entry("links", "side-with-mirror-1")
	bad["mirrors"] = []any{entry("files", "m-1-xxxxxxxx")}
	cases := []struct {
		name string
		body map[string]any
	}{
		{"mirrors on a side channel", bad},
		{"mirror into main", func() map[string]any {
			b := entry("main", "mirror-main-01")
			b["mirrors"] = []any{entry("main", "mirror-main-02")}
			return b
		}()},
		{"unknown channel", entry("nope", "unknown-chan-01")},
		{"short cid", entry("main", "x")},
		{"stale epoch", func() map[string]any { b := entry("main", "stale-epoch-01"); b["epoch"] = 9; return b }()},
		{"bad signature", func() map[string]any { b := entry("main", "bad-sig-000001"); b["sig"] = "abc"; return b }()},
	}
	for _, c := range cases {
		if code, _ := e.do("POST", "/api/entries", alice, c.body); code < 400 || code >= 500 {
			t.Errorf("%s: want 4xx, got %d", c.name, code)
		}
	}

	// Cross-origin writes are refused even with credentials.
	req, _ := http.NewRequest("POST", e.ts.URL+"/api/entries", bytes.NewReader(mustJSON(entry("main", "cross-origin-01"))))
	req.Header.Set("Authorization", "Bearer "+alice)
	req.Header.Set("Origin", "https://evil.example")
	res, _ := http.DefaultClient.Do(req)
	if res.StatusCode != 403 {
		t.Errorf("cross-origin: %d", res.StatusCode)
	}
}

func TestBlobs(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.register("alice", true)

	put := func(n int) (*http.Response, map[string]any) {
		req, _ := http.NewRequest("PUT", e.ts.URL+"/api/blobs", bytes.NewReader(make([]byte, n)))
		req.Header.Set("Authorization", "Bearer "+alice)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		return res, out
	}
	res, out := put(500)
	if res.StatusCode != 201 {
		t.Fatalf("put: %d", res.StatusCode)
	}
	if res, _ := put(5000); res.StatusCode != 413 {
		t.Fatalf("oversize: %d", res.StatusCode)
	}
	req, _ := http.NewRequest("GET", e.ts.URL+"/api/blobs/"+out["id"].(string), nil)
	req.Header.Set("Authorization", "Bearer "+alice)
	get, _ := http.DefaultClient.Do(req)
	b, _ := io.ReadAll(get.Body)
	if get.StatusCode != 200 || len(b) != 500 || !strings.Contains(get.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("get: %d len=%d cc=%q", get.StatusCode, len(b), get.Header.Get("Cache-Control"))
	}
	req, _ = http.NewRequest("GET", e.ts.URL+"/api/blobs/../../etc/passwd", nil)
	req.Header.Set("Authorization", "Bearer "+alice)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode == 200 {
		t.Fatal("path traversal served a file")
	}
}

func TestLoginAndLogout(t *testing.T) {
	e := newEnv(t)
	e.do("POST", "/api/register", "", map[string]any{
		"username": "alice", "auth": strings.Repeat("A", 43), "enc_pub": pubKey(t), "sign_pub": pubKey(t),
		"wrapped_keys": `{"v":1,"ct":"x"}`,
		"bootstrap":    map[string]any{"epoch": 1, "sealed": randB64(125), "sig": randB64(64)},
	})
	if code, _ := e.do("POST", "/api/login", "", map[string]any{"username": "alice", "auth": strings.Repeat("B", 43)}); code != 401 {
		t.Fatalf("wrong pw: %d", code)
	}
	if code, _ := e.do("POST", "/api/login", "", map[string]any{"username": "nobody", "auth": strings.Repeat("A", 43)}); code != 401 {
		t.Fatalf("unknown user: %d", code)
	}
	code, res := e.do("POST", "/api/login", "", map[string]any{"username": "alice", "auth": strings.Repeat("A", 43)})
	out := obj(res)
	if code != 200 || out["wrapped_keys"] == nil || out["envelope"] == nil || out["granter"] == nil {
		t.Fatalf("login: %d %v", code, out)
	}
	tok := out["token"].(string)
	if code, _ := e.do("GET", "/api/me", tok, nil); code != 200 {
		t.Fatalf("me: %d", code)
	}
	e.do("POST", "/api/logout", tok, nil)
	if code, _ := e.do("GET", "/api/me", tok, nil); code != 401 {
		t.Fatalf("me after logout: %d", code)
	}
}

// TestSendLatency reports (does not assert) how long a WebSocket send takes to
// be acknowledged and to reach another member, on loopback.
func TestSendLatency(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.register("alice", true)
	bob, _ := e.register("bob", true)
	e.do("POST", "/api/users/bob/grant", alice, map[string]any{"epoch": 1, "sealed": randB64(125), "sig": randB64(64)})
	wa, wb := e.dial(alice), e.dial(bob)
	next(t, wa)
	next(t, wb)

	const n = 300
	var ack, deliver []time.Duration
	for i := 0; i < n; i++ {
		f := entry("main", "lat-"+randB64(9))
		f["op"], f["rid"] = "send", "x"
		start := time.Now()
		wa.Write(context.Background(), websocket.MessageText, mustJSON(f))
		var gotAck, gotDeliver bool
		for !(gotAck && gotDeliver) {
			if m := next(t, wa); m["op"] == "ack" {
				ack = append(ack, time.Since(start))
				gotAck = true
			}
			if !gotDeliver {
				next(t, wb)
				deliver = append(deliver, time.Since(start))
				gotDeliver = true
			}
		}
	}
	pct := func(d []time.Duration, p float64) time.Duration {
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		return d[int(float64(len(d)-1)*p)]
	}
	t.Logf("%d sends  ack p50=%v p99=%v   delivered-to-peer p50=%v p99=%v",
		n, pct(ack, .5), pct(ack, .99), pct(deliver, .5), pct(deliver, .99))
}
