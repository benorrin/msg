package server

import (
	"sync"
	"sync/atomic"
)

// conn is one live WebSocket. Outbound frames are queued on a buffered
// channel; a consumer too slow to keep up is dropped rather than allowed to
// stall the broadcaster. It reconnects and catches up from its cursors.
type conn struct {
	userID int64
	member atomic.Bool
	send   chan []byte
	done   chan struct{}
	once   sync.Once
}

func newConn(userID int64, member bool) *conn {
	c := &conn{userID: userID, send: make(chan []byte, 256), done: make(chan struct{})}
	c.member.Store(member)
	return c
}

func (c *conn) close() { c.once.Do(func() { close(c.done) }) }

// push queues a frame without blocking; returns false if the queue is full.
func (c *conn) push(b []byte) bool {
	select {
	case c.send <- b:
		return true
	default:
		c.close()
		return false
	}
}

type hub struct {
	mu    sync.RWMutex
	conns map[int64]map[*conn]struct{}
}

func newHub() *hub { return &hub{conns: map[int64]map[*conn]struct{}{}} }

func (h *hub) add(c *conn) {
	h.mu.Lock()
	m := h.conns[c.userID]
	if m == nil {
		m = map[*conn]struct{}{}
		h.conns[c.userID] = m
	}
	m[c] = struct{}{}
	h.mu.Unlock()
}

func (h *hub) remove(c *conn) {
	h.mu.Lock()
	if m := h.conns[c.userID]; m != nil {
		delete(m, c)
		if len(m) == 0 {
			delete(h.conns, c.userID)
		}
	}
	h.mu.Unlock()
	c.close()
}

// toMembers sends a frame to every connection whose user holds the channel key.
func (h *hub) toMembers(b []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, m := range h.conns {
		for c := range m {
			if c.member.Load() {
				c.push(b)
			}
		}
	}
}

// toUser sends a frame to all of one user's connections.
func (h *hub) toUser(id int64, b []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.conns[id] {
		c.push(b)
	}
}

// promote flips a user's live connections to member status.
func (h *hub) promote(id int64) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.conns[id] {
		c.member.Store(true)
	}
}
