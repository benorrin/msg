package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"msg/internal/store"
)

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func badReq(msg string) error { return &apiError{http.StatusBadRequest, msg} }

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, u store.User) {
	resp := map[string]any{"user": u, "epoch": store.CurrentEpoch, "max_file_bytes": s.cfg.MaxFileBytes}
	s.addEnvelope(r.Context(), resp, u)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, u store.User) {
	users, err := s.st.ListUsers(r.Context())
	if err != nil {
		internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

// handleGrant stores the channel key sealed for another user. Any member may
// do this; it is how new accounts are admitted.
func (s *Server) handleGrant(w http.ResponseWriter, r *http.Request, u store.User) {
	var req envelopeReq
	if !readJSON(w, r, &req) {
		return
	}
	if !req.valid() {
		writeErr(w, http.StatusBadRequest, "malformed envelope")
		return
	}
	target, err := s.st.UserByName(r.Context(), strings.ToLower(r.PathValue("username")))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such user")
		return
	}
	if err != nil {
		internalErr(w, err)
		return
	}
	env, err := s.st.Grant(r.Context(), target.ID, u.ID, req.Sealed, req.Sig)
	if errors.Is(err, store.ErrAlreadyMember) {
		writeErr(w, http.StatusConflict, "user already has access")
		return
	}
	if err != nil {
		internalErr(w, err)
		return
	}
	target.Member = true
	s.markMember(target.ID)
	s.hub.promote(target.ID)
	s.hub.toUser(target.ID, mustJSON(map[string]any{"op": "granted", "envelope": env, "granter": u}))
	s.hub.toMembers(mustJSON(map[string]any{"op": "user", "user": target}))
	writeJSON(w, http.StatusOK, map[string]any{"user": target})
}

func (s *Server) handleChannels(w http.ResponseWriter, r *http.Request, u store.User) {
	chs, err := s.st.Channels(r.Context(), u.ID)
	if err != nil {
		internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, chs)
}

func (s *Server) handleEntries(w http.ResponseWriter, r *http.Request, u store.User) {
	limit := int(queryInt(r, "limit", 50))
	if limit < 1 || limit > 200 {
		limit = 50
	}
	es, err := s.st.Entries(r.Context(), r.PathValue("id"), queryInt(r, "before", 0), queryInt(r, "after", 0), limit)
	if errors.Is(err, store.ErrBadChannel) {
		writeErr(w, http.StatusNotFound, "unknown channel")
		return
	}
	if err != nil {
		internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, es)
}

func (s *Server) handleRead(w http.ResponseWriter, r *http.Request, u store.User) {
	var req struct {
		Upto int64 `json:"upto"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.st.MarkRead(r.Context(), u.ID, r.PathValue("id"), req.Upto); err != nil {
		if errors.Is(err, store.ErrBadChannel) {
			writeErr(w, http.StatusNotFound, "unknown channel")
			return
		}
		internalErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- sending ----

type entryReq struct {
	Channel string `json:"channel"`
	CID     string `json:"cid"`
	Epoch   int    `json:"epoch"`
	CT      string `json:"ct"`
	Sig     string `json:"sig"`
}

type sendReq struct {
	entryReq
	// Mirrors are copies filed into side channels (e.g. a link or file seen
	// in a main-channel message). They are stored atomically with the primary.
	Mirrors []entryReq `json:"mirrors"`
}

const (
	maxCT      = 90_000 // base64 chars, ~64 KiB of ciphertext
	maxMirrors = 16
)

var cidRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

func (e *entryReq) toNew() (store.NewEntry, error) {
	switch {
	case !cidRe.MatchString(e.CID):
		return store.NewEntry{}, badReq("bad cid")
	case e.Epoch != store.CurrentEpoch:
		return store.NewEntry{}, badReq("stale key epoch")
	case len(e.CT) < 40 || len(e.CT) > maxCT || !isB64(e.CT):
		return store.NewEntry{}, badReq("bad ciphertext")
	case !decodeLen(e.Sig, sigLen):
		return store.NewEntry{}, badReq("bad signature")
	}
	return store.NewEntry{Channel: e.Channel, Epoch: e.Epoch, CID: e.CID, CT: e.CT, Sig: e.Sig}, nil
}

func isB64(s string) bool {
	_, err := b64.DecodeString(s)
	return err == nil
}

// send validates, stores and fans out an entry plus its mirrors. It is the
// single path used by both the HTTP API and the WebSocket "send" op.
func (s *Server) send(ctx context.Context, u store.User, req *sendReq) ([]store.Entry, error) {
	kind, err := s.st.ChannelKind(req.Channel)
	if err != nil {
		return nil, &apiError{http.StatusNotFound, "unknown channel"}
	}
	primary, err := req.toNew()
	if err != nil {
		return nil, err
	}
	if len(req.Mirrors) > 0 && kind != store.KindStream {
		return nil, badReq("only main-channel messages can carry mirrors")
	}
	if len(req.Mirrors) > maxMirrors {
		return nil, badReq("too many mirrors")
	}
	mirrors := make([]store.NewEntry, 0, len(req.Mirrors))
	for i := range req.Mirrors {
		m := &req.Mirrors[i]
		mk, err := s.st.ChannelKind(m.Channel)
		if err != nil || mk == store.KindStream {
			return nil, badReq("mirrors must target a side channel")
		}
		ne, err := m.toNew()
		if err != nil {
			return nil, err
		}
		mirrors = append(mirrors, ne)
	}

	entries, err := s.st.AddEntries(ctx, u.ID, primary, mirrors)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Dup {
			continue
		}
		k, _ := s.st.ChannelKind(e.Channel)
		// Only the stream channel notifies. Side-channel entries, including
		// mirrors of a main message, arrive quietly.
		s.hub.toMembers(mustJSON(map[string]any{"op": "entry", "entry": e, "notify": k == store.KindStream}))
	}
	return entries, nil
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request, u store.User) {
	var req sendReq
	if !readJSON(w, r, &req) {
		return
	}
	entries, err := s.send(r.Context(), u, &req)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) {
			writeErr(w, ae.status, ae.msg)
		} else {
			internalErr(w, err)
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"entries": entries})
}
