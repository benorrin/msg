package server

import (
	"sync"
	"time"
)

// limiter is a small fixed-window counter used to slow credential guessing.
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*bucket
}

type bucket struct {
	n     int
	reset time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	l := &limiter{max: max, window: window, hits: map[string]*bucket{}}
	go func() {
		for range time.Tick(window) {
			l.mu.Lock()
			t := time.Now()
			for k, b := range l.hits {
				if t.After(b.reset) {
					delete(l.hits, k)
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
}

// allow records an attempt and reports whether it is within the limit.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := time.Now()
	b := l.hits[key]
	if b == nil || t.After(b.reset) {
		b = &bucket{reset: t.Add(l.window)}
		l.hits[key] = b
	}
	b.n++
	return b.n <= l.max
}
