package fetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fake struct {
	status int
	body   string
	err    error
	calls  []string
}

func (f *fake) do(r *http.Request) (*http.Response, error) {
	f.calls = append(f.calls, r.URL.String()+" ua="+r.Header.Get("User-Agent"))
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{StatusCode: f.status, Body: io.NopCloser(strings.NewReader(f.body))}, nil
}

func client(t *testing.T, f *fake) *Client {
	t.Helper()
	return &Client{Dir: t.TempDir(), UserAgent: "debuff/test", Do: f.do}
}

func TestCachedAnswersFromCacheInsideTTL(t *testing.T) {
	f := &fake{status: 200, body: "one"}
	c := client(t, f)
	ctx := context.Background()
	for range 2 {
		r, err := c.Cached(ctx, "a/b.json", time.Hour, "https://x.test/a")
		if err != nil || string(r.Body) != "one" || r.Stale != nil {
			t.Fatalf("%+v %v", r, err)
		}
	}
	if len(f.calls) != 1 || !strings.Contains(f.calls[0], "ua=debuff/test") {
		t.Fatalf("%v", f.calls)
	}
}

func TestAFailedRefreshReturnsAStaleCopyAndSaysSo(t *testing.T) {
	f := &fake{status: 200, body: "old"}
	c := client(t, f)
	ctx := context.Background()
	if _, err := c.Cached(ctx, "x", time.Hour, "https://x.test/"); err != nil {
		t.Fatal(err)
	}
	f.status = 500
	r, err := c.Cached(ctx, "x", 0, "https://x.test/")
	if err != nil || string(r.Body) != "old" || r.Stale == nil {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestNoCopyAndNoAnswerIsAnError(t *testing.T) {
	c := client(t, &fake{err: errors.New("offline")})
	if _, err := c.Cached(context.Background(), "x", time.Hour, "https://x.test/"); err == nil {
		t.Fatal("want an error")
	}
}

func TestABlockStopsFurtherRequestsToThatHost(t *testing.T) {
	f := &fake{status: 429}
	c := client(t, f)
	ctx := context.Background()
	if _, err := c.Get(ctx, "https://x.test/1"); err == nil {
		t.Fatal("want an error")
	}
	if _, err := c.Get(ctx, "https://x.test/2"); err == nil || !strings.Contains(err.Error(), "not asking") {
		t.Fatal(err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("%d calls", len(f.calls))
	}
	f.status = 200
	f.body = "ok"
	if _, err := c.Get(ctx, "https://other.test/"); err != nil {
		t.Fatal("another host is unaffected:", err)
	}
}

func TestAServerErrorRetriesOnce(t *testing.T) {
	f := &fake{status: 503}
	if _, err := client(t, f).Get(context.Background(), "https://x.test/"); err == nil {
		t.Fatal("want an error")
	}
	if len(f.calls) != 2 {
		t.Fatalf("%d calls", len(f.calls))
	}
}

func TestAnEmptyAnswerIsAnError(t *testing.T) {
	if _, err := client(t, &fake{status: 200, body: "  \n"}).Get(context.Background(), "https://x.test/"); err == nil {
		t.Fatal("an empty 200 must not read as no data")
	}
}

func TestAStatusErrorNamesTheHost(t *testing.T) {
	got := Status{503, "https://git.example/very/long/path?format=JSON&s=abc"}.Error()
	if got != "HTTP 503 from git.example" {
		t.Fatal(got)
	}
}

func TestSafeName(t *testing.T) {
	if got := SafeName("../a b/c.json"); got != ".._a_b_c.json" {
		t.Fatal(got)
	}
}

func TestTimingsGroupGitLogsByRepoAndCountFailures(t *testing.T) {
	c := &Client{Dir: t.TempDir(), UserAgent: "test", Do: func(r *http.Request) (*http.Response, error) {
		code := 200
		if strings.Contains(r.URL.Path, "missing") {
			code = 404
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("hello"))}, nil
	}}
	ctx := context.Background()
	for _, u := range []string{
		"https://git.example/v8/v8/+log/refs/a?format=JSON",
		"https://git.example/v8/v8/+log/refs/b",
		"https://git.example/angle/angle/+log/refs/a",
		"https://api.example/x/y",
		"https://api.example/missing",
	} {
		_, _ = c.Get(ctx, u)
	}
	got := map[string]Timing{}
	for _, tm := range c.Timings() {
		got[tm.Source] = tm
	}
	if len(got) != 3 || got["git.example/v8/v8"].Requests != 2 || got["git.example/v8/v8"].Bytes != 10 {
		t.Fatalf("%+v", got)
	}
	if a := got["api.example"]; a.Requests != 2 || a.Failed != 1 || a.Bytes != 5 {
		t.Fatalf("%+v", a)
	}
}

// A connection that stops answering must not hold the scan: one stall took 238 seconds with no deadline.
func TestAStalledRequestTimesOutAndRetriesOnce(t *testing.T) {
	for _, c := range []struct {
		name       string
		stalls     int32 // how many requests hang
		duringRead bool
		want       string
		wantHits   int32
	}{
		{"recovers on the retry", 1, false, "ok", 2},
		{"a stall while reading the body", 1, true, "ok", 2},
		{"stalls twice", 2, false, "", 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			var hits atomic.Int32
			release := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if hits.Add(1) > c.stalls {
					_, _ = w.Write([]byte("ok"))
					return
				}
				if c.duringRead {
					_, _ = w.Write([]byte("partial"))
					w.(http.Flusher).Flush()
				}
				select {
				case <-release:
				case <-r.Context().Done():
				}
			}))
			defer srv.Close()
			defer close(release)
			client := &Client{Dir: t.TempDir(), UserAgent: "test", Timeout: 100 * time.Millisecond}
			start := time.Now()
			b, err := client.Get(context.Background(), srv.URL+"/a/very/long/path")
			if time.Since(start) > 5*time.Second {
				t.Fatalf("took %s", time.Since(start))
			}
			if hits.Load() != c.wantHits || string(b) != c.want {
				t.Fatalf("hits %d, body %q, err %v", hits.Load(), b, err)
			}
			if c.want == "" {
				var s Stalled
				if !errors.As(err, &s) || strings.Contains(err.Error(), "long/path") {
					t.Fatalf("want a Stalled naming only the host: %v", err)
				}
			}
			if tm := client.Timings(); len(tm) != 1 || tm[0].Failed < 1 || tm[0].Slowest < 100*time.Millisecond {
				t.Fatalf("%+v", tm)
			}
		})
	}
}

func TestCancellingTheScanIsNotAStall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	client := &Client{Dir: t.TempDir(), UserAgent: "test", Timeout: time.Minute}
	_, err := client.Get(ctx, srv.URL)
	var s Stalled
	if err == nil || errors.As(err, &s) {
		t.Fatalf("got %v", err)
	}
}

func TestRetriesFollowTheConfiguredPauses(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c := &Client{Dir: t.TempDir(), UserAgent: "test", Retries: []time.Duration{time.Millisecond, 50 * time.Millisecond}}
	start := time.Now()
	b, err := c.Get(context.Background(), srv.URL)
	if err != nil || string(b) != "ok" || hits.Load() != 3 {
		t.Fatalf("%q %v after %d", b, err, hits.Load())
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("the retries should have paused")
	}
	if got := c.Timings()[0]; got.Failed != 2 || got.Paced < 50*time.Millisecond {
		t.Fatalf("%+v", got)
	}
}

func TestABlockIsNeverRetried(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := &Client{Dir: t.TempDir(), UserAgent: "test", Retries: []time.Duration{0, 0}}
	if _, err := c.Get(context.Background(), srv.URL); err == nil || hits.Load() != 1 {
		t.Fatalf("%v after %d requests", err, hits.Load())
	}
}

func TestPacingIsPerHost(t *testing.T) {
	ok := func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("x"))}, nil
	}
	const pace = time.Second
	c := &Client{Dir: t.TempDir(), UserAgent: "test", Interval: pace, Do: ok}
	ctx := context.Background()
	start := time.Now()
	for _, u := range []string{"https://a.example/1", "https://b.example/1", "https://c.example/1"} {
		if _, err := c.Get(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d >= pace {
		t.Fatalf("three hosts shouldn't wait on each other: %s", d)
	}
	if _, err := c.Get(ctx, "https://a.example/2"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < pace {
		t.Fatalf("a second request to one host must wait its turn: %s", d)
	}
}

func TestAHostThatPushesBackGetsASlowerPaceAlone(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	do := func(r *http.Request) (*http.Response, error) {
		code := 200
		if r.URL.Host == "busy.example" && fail.Swap(false) {
			code = 503
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("x"))}, nil
	}
	c := &Client{Dir: t.TempDir(), UserAgent: "test", Interval: 500 * time.Millisecond, Retries: []time.Duration{0}, Do: do}
	ctx := context.Background()
	start := time.Now()
	if _, err := c.Get(ctx, "https://busy.example/1"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < time.Second {
		t.Fatalf("the retry should wait a doubled pace: %s", d)
	}
	start = time.Now()
	if _, err := c.Get(ctx, "https://calm.example/1"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d >= 500*time.Millisecond {
		t.Fatalf("another host shouldn't slow down: %s", d)
	}
	for range 12 {
		c.slowDown("busy.example")
	}
	if c.slowed["busy.example"] != maxPace {
		t.Fatalf("%s", c.slowed["busy.example"])
	}
}

func TestAHostRuleSetsItsOwnPaceAndDeadline(t *testing.T) {
	arrivals := make(chan time.Time, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		arrivals <- time.Now()
		time.Sleep(60 * time.Millisecond) // longer than the client's own deadline
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	const pace = 400 * time.Millisecond
	c := &Client{Dir: t.TempDir(), UserAgent: "test", Timeout: 10 * time.Millisecond, Hosts: map[string]HostRule{host: {Pace: pace, Timeout: 10 * time.Second}}}
	ctx := context.Background()
	for _, path := range []string{"/1", "/2"} {
		if _, err := c.Get(ctx, srv.URL+path); err != nil {
			t.Fatalf("the host's longer deadline should apply: %v", err)
		}
	}
	// As the server sees it, with room for the scheduler: the pace runs from one request's start to the next.
	if gap := (<-arrivals).Sub(<-arrivals).Abs(); gap < pace-100*time.Millisecond {
		t.Fatalf("the host's pace should apply: %s", gap)
	}
}

func TestADroppedConnectionIsRetriedAndNamesOnlyTheHost(t *testing.T) {
	calls := 0
	c := &Client{Dir: t.TempDir(), UserAgent: "test", Do: func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("read tcp [2601:db8::1]:50703->[2606:db8::2]:443: connection reset by peer")
	}}
	_, err := c.Get(context.Background(), "https://api.example/long/path")
	if calls != 2 {
		t.Fatalf("%d calls", calls)
	}
	var u Unreachable
	if !errors.As(err, &u) || u.Host != "api.example" || strings.Contains(err.Error(), "2601") || strings.Contains(err.Error(), "long/path") {
		t.Fatalf("%v", err)
	}
}
