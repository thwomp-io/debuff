package server

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// The most a scan gets. Requests have their own deadlines, so this only bounds a scan gone wrong.
const scanLimit = 20 * time.Minute

// A press waits this long before answering: a rescan with nothing new takes about 3 seconds, so usually the
// next page already has the result. Longer than this, the scan carries on and the page keeps checking.
const pressWait = 5 * time.Second

// rescanner runs one scan at a time. A second press joins the scan already running.
type rescanner struct {
	base context.Context
	run  func(context.Context) error
	wait time.Duration // how long a press waits; zero means pressWait

	mu      sync.Mutex
	done    chan struct{}
	started time.Time
	failure string
}

func (s *rescanner) start() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done != nil {
		return s.done
	}
	done := make(chan struct{})
	s.done, s.started, s.failure = done, time.Now(), ""
	go func() {
		failure := ""
		defer func() {
			if r := recover(); r != nil {
				failure = fmt.Sprint(r)
			}
			s.mu.Lock()
			s.done, s.failure = nil, failure
			s.mu.Unlock()
			close(done)
		}()
		ctx, cancel := context.WithTimeout(s.base, scanLimit)
		defer cancel()
		if err := s.run(ctx); err != nil {
			failure = err.Error()
		}
	}()
	return done
}

func (s *rescanner) status() (running bool, started time.Time, failure string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.done != nil, s.started, s.failure
}

// handlePress starts or joins a scan. The guard has already checked the session and refused a foreign Origin,
// but it lets an absent Origin through for page loads and local tools. A browser always sends one on a POST, so
// here its absence is refused too: nothing but this page's own button may start a scan.
func (s *rescanner) handlePress(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	back := link(r.PostFormValue("view"), r.PostFormValue("min"), r.PostFormValue("app"))
	wait := s.wait
	if wait == 0 {
		wait = pressWait
	}
	done := s.start() //nolint:contextcheck // the scan outlives this press: it belongs to the server, not the request
	select {
	case <-done:
	case <-time.After(wait):
	case <-r.Context().Done():
	}
	http.Redirect(w, r, back, http.StatusSeeOther) // #nosec G710 -- link builds a path on this site from escaped values
}
