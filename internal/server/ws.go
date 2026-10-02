package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"msg/internal/store"
)

// wsFrame is any client -> server frame. Unused fields are ignored per op.
//
//	{"op":"send", "rid":"1", "channel":"main", "cid":..., "epoch":1, "ct":..., "sig":..., "mirrors":[...]}
//	{"op":"read", "channel":"links", "upto":123}
//	{"op":"ping", "rid":"2"}
type wsFrame struct {
	Op  string `json:"op"`
	RID string `json:"rid"`
	sendReq
	Upto int64 `json:"upto"`
}

// handleWS upgrades to a WebSocket. Sending over the already-open socket
// saves the per-message HTTP request overhead, and broadcasts reach members
// the instant a transaction commits.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	u, _, err := s.userFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	ws, err := websocket.Accept(w, r, nil) // enforces same-origin
	if err != nil {
		return
	}
	ws.SetReadLimit(1 << 20)
	c := newConn(u.ID, u.Member)
	s.hub.add(c)
	defer s.hub.remove(c)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-c.done; cancel() }()

	// Writer.
	go func() {
		defer ws.CloseNow()
		for {
			select {
			case b := <-c.send:
				wctx, wc := context.WithTimeout(ctx, 10*time.Second)
				err := ws.Write(wctx, websocket.MessageText, b)
				wc()
				if err != nil {
					c.close()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	// Keepalive: detects dead peers and keeps idle proxies from closing us.
	go func() {
		t := time.NewTicker(25 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				pctx, pc := context.WithTimeout(ctx, 10*time.Second)
				err := ws.Ping(pctx)
				pc()
				if err != nil {
					c.close()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	c.push(mustJSON(map[string]any{"op": "hello", "member": u.Member}))

	for {
		_, data, err := ws.Read(ctx)
		if err != nil {
			return // closed or dropped; the client reconnects and catches up
		}
		var f wsFrame
		if err := json.Unmarshal(data, &f); err != nil {
			c.push(mustJSON(map[string]any{"op": "error", "error": "invalid frame"}))
			continue
		}
		s.handleFrame(ctx, c, u, &f)
	}
}

func (s *Server) handleFrame(ctx context.Context, c *conn, u store.User, f *wsFrame) {
	fail := func(err error) {
		msg := "internal error"
		var ae *apiError
		if errors.As(err, &ae) {
			msg = ae.msg
		} else if errors.Is(err, store.ErrBadChannel) {
			msg = "unknown channel"
		} else {
			log.Printf("ws %s: %v", f.Op, err)
		}
		c.push(mustJSON(map[string]any{"op": "error", "rid": f.RID, "error": msg}))
	}
	if f.Op == "ping" {
		c.push(mustJSON(map[string]any{"op": "pong", "rid": f.RID}))
		return
	}
	// Membership may have been granted after this socket opened.
	if !c.member.Load() {
		fail(&apiError{http.StatusForbidden, "waiting for a member to approve your account"})
		return
	}
	switch f.Op {
	case "send":
		entries, err := s.send(ctx, u, &f.sendReq)
		if err != nil {
			fail(err)
			return
		}
		c.push(mustJSON(map[string]any{"op": "ack", "rid": f.RID, "entries": entries}))
	case "read":
		if err := s.st.MarkRead(ctx, u.ID, f.Channel, f.Upto); err != nil {
			fail(err)
		}
	default:
		fail(badReq("unknown op"))
	}
}
