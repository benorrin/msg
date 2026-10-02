package server

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"msg/internal/store"
)

const sessionTTL = 30 * 24 * time.Hour

var usernameRe = regexp.MustCompile(`^[a-z0-9_-]{3,32}$`)

var b64 = base64.RawURLEncoding

// Argon2id over the client-derived auth secret. The secret is already the
// output of a 600k-round PBKDF2 and never equals the key that wraps the
// user's private keys, so these parameters favour login latency.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
)

func hashAuth(auth string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	h := argon2.IDKey([]byte(auth), salt, argonTime, argonMemory, argonThreads, 32)
	return b64.EncodeToString(salt) + "$" + b64.EncodeToString(h)
}

func verifyAuth(stored, auth string) bool {
	salt, hash, ok := strings.Cut(stored, "$")
	if !ok {
		return false
	}
	sb, err1 := b64.DecodeString(salt)
	hb, err2 := b64.DecodeString(hash)
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(auth), sb, argonTime, argonMemory, argonThreads, 32)
	return subtle.ConstantTimeCompare(got, hb) == 1
}

// dummyHash lets login spend the same time for unknown usernames.
var dummyHash = hashAuth("dummy")

// decodeLen checks that s is base64url for exactly n bytes.
func decodeLen(s string, n int) bool {
	b, err := b64.DecodeString(s)
	return err == nil && len(b) == n
}

// validPoint checks that s is a valid uncompressed P-256 public point.
func validPoint(s string) bool {
	b, err := b64.DecodeString(s)
	if err != nil {
		return false
	}
	_, err = ecdh.P256().NewPublicKey(b)
	return err == nil
}

const (
	authLen   = 32
	sigLen    = 64
	sealedLen = 65 + 12 + 32 + 16 // ephemeral pub + iv + 256-bit key + GCM tag
)

type envelopeReq struct {
	Epoch  int    `json:"epoch"`
	Sealed string `json:"sealed"`
	Sig    string `json:"sig"`
}

func (e *envelopeReq) valid() bool {
	return e.Epoch == store.CurrentEpoch && decodeLen(e.Sealed, sealedLen) && decodeLen(e.Sig, sigLen)
}

// startSession sets the cookie used by the web client and returns the same
// token for API clients to send as "Authorization: Bearer <token>".
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID int64) (string, error) {
	raw := make([]byte, 32)
	rand.Read(raw)
	tok := b64.EncodeToString(raw)
	exp := time.Now().Add(sessionTTL)
	if err := s.st.CreateSession(r.Context(), hashToken(tok), userID, exp); err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name: "sid", Value: tok, Path: "/", Expires: exp,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.isSecure(r),
	})
	return tok, nil
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string       `json:"username"`
		Auth        string       `json:"auth"`
		EncPub      string       `json:"enc_pub"`
		SignPub     string       `json:"sign_pub"`
		WrappedKeys string       `json:"wrapped_keys"`
		Bootstrap   *envelopeReq `json:"bootstrap"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.registerIP.allow(s.clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "too many sign-ups, try later")
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Username))
	switch {
	case !usernameRe.MatchString(name):
		writeErr(w, http.StatusBadRequest, "username must be 3-32 characters: a-z 0-9 _ -")
		return
	case !decodeLen(req.Auth, authLen), !validPoint(req.EncPub), !validPoint(req.SignPub),
		len(req.WrappedKeys) == 0, len(req.WrappedKeys) > 4096:
		writeErr(w, http.StatusBadRequest, "malformed key material")
		return
	case req.Bootstrap != nil && !req.Bootstrap.valid():
		writeErr(w, http.StatusBadRequest, "malformed bootstrap envelope")
		return
	}

	var boot *store.Envelope
	if req.Bootstrap != nil {
		boot = &store.Envelope{Sealed: req.Bootstrap.Sealed, Sig: req.Bootstrap.Sig}
	}
	u, granted, err := s.st.Register(r.Context(), name, hashAuth(req.Auth), req.EncPub, req.SignPub, req.WrappedKeys, boot)
	if errors.Is(err, store.ErrUsernameTaken) {
		writeErr(w, http.StatusConflict, "that username is taken")
		return
	}
	if err != nil {
		internalErr(w, err)
		return
	}
	tok, err := s.startSession(w, r, u.ID)
	if err != nil {
		internalErr(w, err)
		return
	}
	// Tell existing members someone is waiting for the key.
	if !granted {
		s.hub.toMembers(mustJSON(map[string]any{"op": "user", "user": u}))
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": u, "granted": granted, "token": tok})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Auth     string `json:"auth"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Username))
	if !s.loginIP.allow(s.clientIP(r)) || !s.loginUser.allow(name) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, try again in a minute")
		return
	}
	u, hash, wrapped, err := s.st.Credentials(r.Context(), name)
	if errors.Is(err, store.ErrNotFound) {
		verifyAuth(dummyHash, req.Auth)
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	if err != nil {
		internalErr(w, err)
		return
	}
	if !verifyAuth(hash, req.Auth) {
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	tok, err := s.startSession(w, r, u.ID)
	if err != nil {
		internalErr(w, err)
		return
	}
	resp := map[string]any{"user": u, "wrapped_keys": wrapped, "token": tok}
	s.addEnvelope(r.Context(), resp, u)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if tok := tokenFromRequest(r); tok != "" {
		th := hashToken(tok)
		s.st.DeleteSession(r.Context(), th)
		s.dropSession(th)
	}
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

// addEnvelope adds the user's sealed channel key and the granter's identity
// (needed to verify the grant signature) when the user is a member.
func (s *Server) addEnvelope(ctx context.Context, resp map[string]any, u store.User) {
	env, err := s.st.Envelope(ctx, u.ID)
	if err != nil || env == nil {
		return
	}
	resp["envelope"] = env
	if env.GrantedBy == u.ID {
		resp["granter"] = u
	} else if g, err := s.st.UserByID(ctx, env.GrantedBy); err == nil {
		resp["granter"] = g
	}
}
