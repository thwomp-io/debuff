// Package server is the local web console: one embedded page and a health endpoint, loopback only.
//
// Any website can make a browser call a localhost port, so loopback alone isn't a boundary. Host
// checking stops DNS rebinding (the class behind the Playwright MCP bug CVE-2025-9611), Origin
// checking stops cross-site requests, and the CSP means nothing on the page can load or send
// anything remote, even if untrusted advisory text ever got past the template's escaping.
package server

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/thwomp-io/debuff/internal/snapshot"
	"github.com/thwomp-io/debuff/internal/version"
)

//go:embed web/index.html web/style.css
var web embed.FS

const csp = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// updateArgs is what one row of the Updates page needs: the row, and the page state its button depends on.
type updateArgs struct {
	Row                    UpdateRow
	CanAct, Busy, Updating bool
	Filter                 string
}

var page = template.Must(template.New("index.html").Funcs(template.FuncMap{
	"updateArgs": func(r UpdateRow, d pageData) updateArgs {
		return updateArgs{
			Row: r, CanAct: d.CanAct, Busy: d.Upgrading != "" || d.Scanning,
			Updating: r.Formula != "" && slices.Contains(d.UpgradingNames, r.Formula), Filter: d.CurrentFilter,
		}
	},
}).ParseFS(web, "web/index.html"))

// IsLoopback reports whether addr (host:port) binds only to this machine.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// hostAllowed: the Host header must name this machine, on the port we're serving. A rebinding
// attack arrives with the attacker's domain here.
func hostAllowed(hostHeader, port string) bool {
	host, p, err := net.SplitHostPort(hostHeader)
	if err != nil || p != port {
		return false
	}
	// The name an /etc/hosts entry can give this console. Having no dot, it can't be an attacker's domain.
	if host == "localhost" || host == "debuff" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// originAllowed: browsers send Origin on cross-site requests. Absent is a same-origin navigation or
// a local tool; present must be this very console.
func originAllowed(origin, port string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" {
		return false
	}
	return hostAllowed(u.Host, port)
}

// Options is what a server shows. Load reads the newest scan; Demo shows labeled sample data instead.
// Token guards every page but the health check.
type Options struct {
	Load     func() (View, error)
	Rows     []Row
	Apps     map[string]AppFacts
	Previous *Previous
	Pending  []snapshot.Pending
	Demo     bool
	Token    string
	// Scan runs one scan and writes its snapshot. Nil means no rescan button.
	Scan func(context.Context) error
	// LastFailure says how the last scan by anyone failed, if it did: a scheduled one has no other way to reach the page.
	LastFailure func() string
	// Upgrade runs one formula's upgrade, and Open opens an app or an updater. Nil means those buttons do nothing.
	Upgrade func(context.Context, []string) error
	Open    func(context.Context, string) error
	// Icons is the directory of app icons. Empty means no icons are served.
	Icons string
	// Base is what a running scan belongs to. Serve sets it, so shutting down stops the scan.
	Base context.Context
}

const cookieName = "debuff_session"

func tokenMatches(got, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// Handler serves the console for a server listening on port.
func Handler(port string, info version.Info, opt Options) http.Handler {
	mux := http.NewServeMux()
	var scans *rescanner
	if opt.Scan != nil {
		base := opt.Base
		if base == nil {
			base = context.Background()
		}
		scans = &rescanner{base: base, run: opt.Scan}
		mux.HandleFunc("POST /rescan", scans.handlePress)
	}
	load := func() (View, error) {
		if opt.Load != nil {
			return opt.Load()
		}
		return View{Rows: opt.Rows, Apps: opt.Apps, Scanned: opt.Demo, Previous: opt.Previous, Pending: opt.Pending}, nil
	}
	var upgrades *upgrader
	if opt.Upgrade != nil {
		base := opt.Base
		if base == nil {
			base = context.Background()
		}
		upgrades = &upgrader{base: base, run: opt.Upgrade}
		if scans != nil {
			upgrades.after = func() { scans.start() }
		}
	}
	var pressMu sync.Mutex
	var pressNote string
	if opt.Upgrade != nil || opt.Open != nil {
		mux.HandleFunc("POST /update", pressHandler(load, upgrades, opt.Open, func(s string) {
			pressMu.Lock()
			defer pressMu.Unlock()
			pressNote = s
		}))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
			version.Info
		}{"ok", info})
	})
	mux.HandleFunc("GET /style.css", func(w http.ResponseWriter, _ *http.Request) {
		b, err := web.ReadFile("web/style.css")
		if err != nil {
			http.Error(w, "missing asset", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(b)
	})
	if opt.Icons != "" {
		mux.HandleFunc("GET /icon/{id}", func(w http.ResponseWriter, r *http.Request) {
			serveIcon(w, r, opt.Icons)
		})
	}
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		q := r.URL.Query()
		view, err := load()
		if err != nil {
			http.Error(w, "couldn't read the latest scan: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if opt.Demo && q.Get("sample") == "many" {
			view.Rows, view.Apps = DemoMany()
			view.Previous = nil
		}
		data := buildPage(info.Version, q.Get("view"), q.Get("min"), q.Get("app"), opt.Demo, view)
		if scans != nil {
			data.CanScan = true
			var started time.Time
			data.Scanning, started, data.ScanFailure = scans.status()
			if data.Scanning {
				data.ScanStarted = started.Local().Format("3:04:05 PM")
			}
		}
		if data.ScanFailure == "" && opt.LastFailure != nil {
			data.ScanFailure = opt.LastFailure()
		}
		data.CanAct = opt.Upgrade != nil || opt.Open != nil
		if upgrades != nil {
			// While a rescan runs the page keeps reloading itself, so the outcome stays up until that settles.
			data.Upgrading, data.UpgradingNames, data.UpgradeDone, data.PressFailure = upgrades.status(!data.Scanning)
		}
		pressMu.Lock()
		if pressNote != "" {
			data.PressFailure, pressNote = pressNote, ""
		}
		pressMu.Unlock()
		if err := page.Execute(w, data); err != nil {
			_, _ = io.WriteString(w, "render failed")
		}
	})
	return guard(port, opt.Token, mux)
}

var iconID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// serveIcon answers only a content hash, so the request can't name a path. Being named by its content, a
// response never changes, which makes it the one thing on this site worth caching.
func serveIcon(w http.ResponseWriter, r *http.Request, dir string) {
	id := r.PathValue("id")
	if !iconID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(filepath.Join(dir, id+".png")) // #nosec G304 G703 -- id is hex, checked above
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	_, _ = w.Write(b) // #nosec G705 -- a PNG validated at scan time, sent as image/png with nosniff
}

// authorized checks the session cookie; a valid ?token= sets it and redirects, so the token leaves the URL.
func authorized(w http.ResponseWriter, r *http.Request, token string) bool {
	if c, err := r.Cookie(cookieName); err == nil && tokenMatches(c.Value, token) {
		return true
	}
	q := r.URL.Query()
	if !tokenMatches(q.Get("token"), token) {
		http.Error(w, "Debuff needs its token. Run: debuff open", http.StatusUnauthorized)
		return false
	}
	// #nosec G124 -- Secure can't be set: this is plain HTTP on loopback, and browsers disagree on allowing it
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 365 * 24 * 3600,
	})
	q.Del("token")
	// Stay on this site: a path like //evil.example would otherwise read as another host.
	target := "/" + strings.TrimLeft(r.URL.Path, `/\`)
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	http.Redirect(w, r, target, http.StatusSeeOther) // #nosec G710 -- target is forced to a local path above
	return false
}

func guard(port, token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host, port) || !originAllowed(r.Header.Get("Origin"), port) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		// Not no-referrer: under it, browsers send "Origin: null" on this page's own POST, which the guard
		// refuses. This still tells other sites nothing.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if r.URL.Path != "/healthz" && !authorized(w, r, token) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Serve listens on addr until ctx ends. It refuses any address that isn't loopback, and calls
// ready with the bound address (addr may ask for port 0).
func Serve(ctx context.Context, addr string, info version.Info, opt Options, ready func(string)) error {
	if !IsLoopback(addr) {
		return fmt.Errorf("refusing to bind %q: loopback only", addr)
	}
	if opt.Token == "" {
		return errors.New("refusing to serve without a token")
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	bound := ln.Addr().String()
	_, port, err := net.SplitHostPort(bound)
	if err != nil {
		_ = ln.Close()
		return err
	}
	if opt.Base == nil {
		opt.Base = ctx
	}
	srv := &http.Server{
		Handler:           Handler(port, info, opt), //nolint:contextcheck // a rescan after an upgrade belongs to the server, not to one request
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	stopped := make(chan error, 1)
	go func() { // #nosec G118 -- shutdown needs a fresh context: ctx has already ended by then
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stopped <- srv.Shutdown(shutdown) //nolint:contextcheck // ctx has already ended
	}()
	ready(bound)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return <-stopped
}

// HealthURL is where a running server on addr answers.
func HealthURL(addr string) string {
	return "http://" + strings.TrimSpace(addr) + "/healthz"
}
