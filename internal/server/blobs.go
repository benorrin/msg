package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"msg/internal/store"
)

var blobIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Uploaded bytes are ciphertext the client produced; the server stores them
// opaquely under a random id.
func (s *Server) handlePutBlob(w http.ResponseWriter, r *http.Request, u store.User) {
	// 28 bytes covers the IV and GCM tag the client adds.
	limit := s.cfg.MaxFileBytes + 28
	if r.ContentLength > limit {
		writeErr(w, http.StatusRequestEntityTooLarge, "file too large")
		return
	}
	idb := make([]byte, 16)
	rand.Read(idb)
	id := hex.EncodeToString(idb)

	tmp, err := os.CreateTemp(s.blob, "up-*")
	if err != nil {
		internalErr(w, err)
		return
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename

	n, err := io.Copy(tmp, http.MaxBytesReader(w, r.Body, limit))
	if err == nil {
		err = tmp.Close()
	} else {
		tmp.Close()
	}
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		writeErr(w, http.StatusRequestEntityTooLarge, "file too large")
		return
	}
	if err != nil {
		internalErr(w, err)
		return
	}
	if n < 28 {
		writeErr(w, http.StatusBadRequest, "empty upload")
		return
	}
	if err := os.Rename(tmp.Name(), filepath.Join(s.blob, id)); err != nil {
		internalErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "size": n})
}

func (s *Server) handleGetBlob(w http.ResponseWriter, r *http.Request, u store.User) {
	id := r.PathValue("id")
	if !blobIDRe.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(s.blob, id))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		internalErr(w, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	// Ids are random and content is immutable: let the browser keep the
	// ciphertext so reopening a file never hits the network.
	h.Set("Cache-Control", "private, max-age=31536000, immutable")
	if r.Method == http.MethodHead {
		return
	}
	io.Copy(w, f)
}
