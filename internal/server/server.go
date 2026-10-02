// Package server exposes the JSON/WebSocket API and serves the web client.
package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"msg/internal/store"
)

type Config struct {
	DataDir      string
	MaxFileBytes int64
	TrustProxy   bool // honour X-Forwarded-For / X-Forwarded-Proto
}

type Server struct {
	cfg  Config
	st   *store.Store
	hub  *hub
	web  map[string]*asset
	mux  *http.ServeMux
	blob string

	loginIP, loginUser, registerIP *limiter

	sessMu sync.RWMutex
	sess   map[string]*session
}

type session struct {
	user store.User
	exp  time.Time
}

func New(cfg Config, st *store.Store, webFS fs.FS) (*Server, error) {
	s := &Server{
		cfg:        cfg,
		st:         st,
		hub:        newHub(),
		mux:        http.NewServeMux(),
		blob:       filepath.Join(cfg.DataDir, "blobs"),
		loginIP:    newLimiter(30, time.Minute),
		loginUser:  newLimiter(10, time.Minute),
		registerIP: newLimiter(10, time.Hour),
		sess:       map[string]*session{},
	}
	if err := os.MkdirAll(s.blob, 0o700); err != nil {
		return nil, err
	}
	var err error
	if s.web, err = loadAssets(webFS); err != nil {
		return nil, err
	}
	s.routes()
	go func() {
		for range time.Tick(time.Hour) {
			st.PurgeSessions(context.Background())
		}
	}()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.secure(s.mux)
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	m.HandleFunc("POST /api/register", s.handleRegister)
	m.HandleFunc("POST /api/login", s.handleLogin)
	m.HandleFunc("POST /api/logout", s.handleLogout)

	m.HandleFunc("GET /api/me", s.auth(s.handleMe, false))
	m.HandleFunc("GET /api/users", s.auth(s.handleUsers, true))
	m.HandleFunc("POST /api/users/{username}/grant", s.auth(s.handleGrant, true))
	m.HandleFunc("GET /api/channels", s.auth(s.handleChannels, true))
	m.HandleFunc("GET /api/channels/{id}/entries", s.auth(s.handleEntries, true))
	m.HandleFunc("POST /api/channels/{id}/read", s.auth(s.handleRead, true))
	m.HandleFunc("POST /api/entries", s.auth(s.handleSend, true))
	m.HandleFunc("PUT /api/blobs", s.auth(s.handlePutBlob, true))
	m.HandleFunc("GET /api/blobs/{id}", s.auth(s.handleGetBlob, true))

	m.HandleFunc("GET /ws", s.handleWS)
	m.HandleFunc("GET /", s.handleStatic)
}

// ---- middleware ----

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; " +
	"connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// secure applies security headers and a same-origin check on state-changing
// requests (defence in depth on top of SameSite=Strict cookies).
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && !sameOrigin(o, r.Host) {
				writeErr(w, http.StatusForbidden, "cross-origin request refused")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(origin, host string) bool {
	i := strings.Index(origin, "://")
	return i >= 0 && strings.EqualFold(origin[i+3:], host)
}

type authedHandler func(w http.ResponseWriter, r *http.Request, u store.User)

// auth resolves the session (cookie or bearer token). When memberOnly is set,
// users who have not yet been granted the channel key are refused.
func (s *Server) auth(h authedHandler, memberOnly bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, _, err := s.userFromRequest(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		if memberOnly && !u.Member {
			writeErr(w, http.StatusForbidden, "waiting for a member to approve your account")
			return
		}
		h(w, r, u)
	}
}

func tokenFromRequest(r *http.Request) string {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimPrefix(a, "Bearer ")
	}
	if c, err := r.Cookie("sid"); err == nil {
		return c.Value
	}
	return ""
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// userFromRequest looks the session up in an in-memory cache first; sessions
// are only revoked through this process, so the cache is authoritative.
func (s *Server) userFromRequest(r *http.Request) (store.User, string, error) {
	tok := tokenFromRequest(r)
	if tok == "" {
		return store.User{}, "", store.ErrNotFound
	}
	th := hashToken(tok)
	s.sessMu.RLock()
	c := s.sess[th]
	s.sessMu.RUnlock()
	if c != nil && time.Now().Before(c.exp) {
		return c.user, th, nil
	}
	u, err := s.st.SessionUser(r.Context(), th)
	if err != nil {
		return u, th, err
	}
	s.sessMu.Lock()
	s.sess[th] = &session{user: u, exp: time.Now().Add(10 * time.Minute)}
	s.sessMu.Unlock()
	return u, th, nil
}

// markMember updates cached sessions after a grant.
func (s *Server) markMember(userID int64) {
	s.sessMu.Lock()
	for _, c := range s.sess {
		if c.user.ID == userID {
			c.user.Member = true
		}
	}
	s.sessMu.Unlock()
}

func (s *Server) dropSession(th string) {
	s.sessMu.Lock()
	delete(s.sess, th)
	s.sessMu.Unlock()
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			return strings.TrimSpace(strings.Split(f, ",")[0])
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *Server) isSecure(r *http.Request) bool {
	return r.TLS != nil || (s.cfg.TrustProxy && r.Header.Get("X-Forwarded-Proto") == "https")
}

// ---- JSON helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func internalErr(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

func queryInt(r *http.Request, key string, def int64) int64 {
	if v, err := strconv.ParseInt(r.URL.Query().Get(key), 10, 64); err == nil && v >= 0 {
		return v
	}
	return def
}

// ---- static assets (embedded, precompressed, ETagged) ----

type asset struct {
	body, gz []byte
	etag     string
	ctype    string
}

func loadAssets(fsys fs.FS) (map[string]*asset, error) {
	out := map[string]*asset{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(p, ".go") {
			return err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		a := &asset{body: b, etag: `"` + hex.EncodeToString(sum[:8]) + `"`, ctype: mime.TypeByExtension(path.Ext(p))}
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		zw.Write(b)
		zw.Close()
		if buf.Len() < len(b) {
			a.gz = buf.Bytes()
		}
		out[p] = a
		return nil
	})
	return out, err
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if p == "" || p == "." {
		p = "index.html"
	}
	a := s.web[p]
	if a == nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("ETag", a.etag)
	h.Set("Cache-Control", "no-cache") // always revalidate; 304s are cheap
	h.Set("Vary", "Accept-Encoding")
	if a.ctype != "" {
		h.Set("Content-Type", a.ctype)
	}
	if r.Header.Get("If-None-Match") == a.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body := a.body
	if a.gz != nil && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		h.Set("Content-Encoding", "gzip")
		body = a.gz
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.Write(body)
}
