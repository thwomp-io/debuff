// Package fetch is the one network path: a descriptive User-Agent, paced requests, a file cache, and no
// retries into a block. A host that answers 403 or 429 gets no more requests this run.
package fetch

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const maxBody = 64 << 20

// Client fetches for one scan. It isn't safe for concurrent use; a scan runs one request at a time.
type Client struct {
	Dir       string
	UserAgent string
	Interval  time.Duration
	Timeout   time.Duration                               // for one request, reading included. Without it a stalled connection holds the scan
	Retries   []time.Duration                             // the pause before each retry of a GET; nil means one retry with no extra pause
	Hosts     map[string]HostRule                         // a host with its own published limits
	Do        func(*http.Request) (*http.Response, error) // nil means http.DefaultClient

	last    map[string]time.Time     // per host: the pace is a courtesy to each server, not a limit on this scan
	slowed  map[string]time.Duration // a host that pushed back gets a slower pace for the rest of the run
	blocked map[string]string
	timings map[string]*Timing
}

// HostRule is a host's own pace and deadline, where they differ from the client's.
type HostRule struct {
	Pace, Timeout time.Duration
}

// Timing is where one source's time went during a scan. It holds no response content, so it's safe to print.
type Timing struct {
	Source   string
	Requests int
	Failed   int
	Paced    time.Duration // waiting our own turn
	Busy     time.Duration // sending, and reading the answer
	Slowest  time.Duration // the worst single request: an average hides a stall
	Bytes    int64
}

// Timings lists every source this client asked, slowest first.
func (c *Client) Timings() []Timing {
	out := make([]Timing, 0, len(c.timings))
	for _, t := range c.timings {
		out = append(out, *t)
	}
	slices.SortFunc(out, func(a, b Timing) int {
		if a.Busy != b.Busy {
			return cmp.Compare(b.Busy, a.Busy)
		}
		return cmp.Compare(a.Source, b.Source)
	})
	return out
}

// timingSource groups git logs by repository and everything else by host.
func timingSource(u *url.URL) string {
	if repo, _, ok := strings.Cut(u.Path, "/+log"); ok {
		return u.Host + repo
	}
	return u.Host
}

func (c *Client) timing(u *url.URL) *Timing {
	if c.timings == nil {
		c.timings = map[string]*Timing{}
	}
	name := timingSource(u)
	if c.timings[name] == nil {
		c.timings[name] = &Timing{Source: name}
	}
	return c.timings[name]
}

// Status is an HTTP answer other than 200.
type Status struct {
	Code int
	URL  string
}

// Error names the host, not the URL: this text reaches the page, and these URLs run long.
func (s Status) Error() string {
	host := s.URL
	if u, err := url.Parse(s.URL); err == nil && u.Host != "" {
		host = u.Host
	}
	return fmt.Sprintf("HTTP %d from %s", s.Code, host)
}

func (c *Client) wait(ctx context.Context, host string) error {
	if err := pause(ctx, max(c.Interval, c.Hosts[host].Pace, c.slowed[host])-time.Since(c.last[host])); err != nil {
		return err
	}
	if c.last == nil {
		c.last = map[string]time.Time{}
	}
	c.last[host] = time.Now()
	return nil
}

// maxPace is as slow as pushback can make a host. Measured on the Chromium git servers (2026-11-02):
// about 18% of requests failed at one a second, and 1 of 43 at one every three seconds.
const maxPace = 8 * time.Second

// slowDown doubles a host's pace after a server error or a stall.
func (c *Client) slowDown(host string) {
	if c.slowed == nil {
		c.slowed = map[string]time.Duration{}
	}
	c.slowed[host] = min(2*max(c.Interval, c.slowed[host]), maxPace)
}

func pause(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) send(ctx context.Context, method, target string, body []byte) ([]byte, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if why, ok := c.blocked[u.Host]; ok {
		return nil, fmt.Errorf("not asking %s again this run: %s", u.Host, why)
	}
	t := c.timing(u)
	waitStart := time.Now()
	if err := c.wait(ctx, u.Host); err != nil {
		return nil, err
	}
	start := time.Now()
	t.Paced += start.Sub(waitStart)
	t.Requests++
	defer func() {
		took := time.Since(start)
		t.Busy += took
		t.Slowest = max(t.Slowest, took)
	}()
	parent := ctx
	timeout := c.Timeout
	if rule := c.Hosts[u.Host].Timeout; rule > 0 {
		timeout = rule
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	do := c.Do
	if do == nil {
		do = http.DefaultClient.Do
	}
	resp, err := do(req)
	if err != nil {
		t.Failed++
		return nil, c.stalled(parent, ctx, u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		if c.blocked == nil {
			c.blocked = map[string]string{}
		}
		c.blocked[u.Host] = fmt.Sprintf("it answered HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		c.slowDown(u.Host)
	}
	if resp.StatusCode != http.StatusOK {
		t.Failed++
		return nil, Status{resp.StatusCode, target}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	t.Bytes += int64(len(b))
	if err != nil {
		t.Failed++
		return nil, c.stalled(parent, ctx, u, err)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, fmt.Errorf("an empty answer from %s", target)
	}
	return b, nil
}

// Stalled is a request that ran out of time. Like Status it names the host, not the long URL.
type Stalled struct {
	Host  string
	After time.Duration
}

func (s Stalled) Error() string { return fmt.Sprintf("no answer from %s in %s", s.Host, s.After) }

// Unreachable is a connection that failed. The transport's own error names this machine's address, and this text
// can reach the page, so it names only the host.
type Unreachable struct{ Host string }

func (u Unreachable) Error() string { return "the connection to " + u.Host + " failed" }

// stalled tells this request's deadline apart from the whole scan being cancelled.
func (c *Client) stalled(parent, ctx context.Context, u *url.URL, err error) error {
	if ctx.Err() != nil && parent.Err() == nil {
		c.slowDown(u.Host)
		after := c.Timeout
		if rule := c.Hosts[u.Host].Timeout; rule > 0 {
			after = rule
		}
		return Stalled{u.Host, after}
	}
	if parent.Err() == nil {
		c.slowDown(u.Host)
		return Unreachable{u.Host}
	}
	return err
}

// Get fetches, retrying after a pause on a server-side error or a stall: the git servers answer 502 and
// 503 on deep history now and then, and a connection can stop answering at all.
func (c *Client) Get(ctx context.Context, target string) ([]byte, error) {
	retries := c.Retries
	if retries == nil {
		retries = []time.Duration{0}
	}
	b, err := c.send(ctx, http.MethodGet, target, nil)
	for _, d := range retries {
		if !worthRetrying(err) {
			break
		}
		if perr := pause(ctx, d); perr != nil {
			return nil, perr
		}
		if u, perr := url.Parse(target); perr == nil {
			c.timing(u).Paced += d
		}
		b, err = c.send(ctx, http.MethodGet, target, nil)
	}
	return b, err
}

func worthRetrying(err error) bool {
	switch e := err.(type) { //nolint:errorlint // send returns these unwrapped
	case Status:
		return e.Code >= 500
	case Stalled, Unreachable:
		return true
	}
	return false
}

// Post sends a JSON body.
func (c *Client) Post(ctx context.Context, target string, body []byte) ([]byte, error) {
	return c.send(ctx, http.MethodPost, target, body)
}

func (c *Client) path(name string) string {
	return filepath.Join(c.Dir, filepath.FromSlash(name))
}

// Read returns a cached file and its age.
func (c *Client) Read(name string) ([]byte, time.Duration, error) {
	p := c.path(name)
	fi, err := os.Stat(p)
	if err != nil {
		return nil, 0, err
	}
	b, err := os.ReadFile(p) // #nosec G304 -- inside the operator's own cache dir
	return b, time.Since(fi.ModTime()), err
}

// Write stores a cache file atomically, private to the user.
func (c *Client) Write(name string, b []byte) error {
	p := c.path(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Result is cached data, saying how much to trust its age.
type Result struct {
	Body []byte
	Age  time.Duration
	// Stale is the error that stopped a refresh; the body is then an older copy.
	Stale error
}

// Cached answers from the cache inside ttl, else fetches. If the fetch fails and an older copy exists,
// that copy comes back marked Stale, so a caller can say so instead of quietly using old data.
func (c *Client) Cached(ctx context.Context, name string, ttl time.Duration, target string) (Result, error) {
	return c.cached(ctx, name, ttl, func() ([]byte, error) { return c.Get(ctx, target) })
}

// CachedPost is Cached for a POST lookup.
func (c *Client) CachedPost(ctx context.Context, name string, ttl time.Duration, target string, body []byte) (Result, error) {
	return c.cached(ctx, name, ttl, func() ([]byte, error) { return c.Post(ctx, target, body) })
}

func (c *Client) cached(_ context.Context, name string, ttl time.Duration, get func() ([]byte, error)) (Result, error) {
	old, age, readErr := c.Read(name)
	if readErr == nil && age < ttl {
		return Result{Body: old, Age: age}, nil
	}
	b, err := get()
	if err != nil {
		if readErr == nil {
			return Result{Body: old, Age: age, Stale: err}, nil
		}
		return Result{}, err
	}
	if err := c.Write(name, b); err != nil {
		return Result{}, err
	}
	return Result{Body: b}, nil
}

// SafeName makes a cache file name from outside text.
func SafeName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, s)
}
