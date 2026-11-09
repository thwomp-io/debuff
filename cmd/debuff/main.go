// Command debuff is a morning check of this machine's own vulnerability exposure.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/thwomp-io/debuff/internal/fetch"
	"github.com/thwomp-io/debuff/internal/registry"
	"github.com/thwomp-io/debuff/internal/resolve"
	"github.com/thwomp-io/debuff/internal/scan"
	"github.com/thwomp-io/debuff/internal/server"
	"github.com/thwomp-io/debuff/internal/snapshot"
	"github.com/thwomp-io/debuff/internal/state"
	"github.com/thwomp-io/debuff/internal/update"
	"github.com/thwomp-io/debuff/internal/version"
)

const defaultAddr = "127.0.0.1:8737"

var hostRules = map[string]fetch.HostRule{resolve.NVDHost: resolve.NVDRule}

// A log past this moves to name.1 at the end of a scan. These logs hold counts and errors, so this is years of them.
const logLimit = 1 << 20

// How long the sample data's pretend rescan takes: long enough to see the scanning state.
const demoScan = 8 * time.Second

// How long sample data's upgrade pretends to take, so the page's updating state can be seen.
const demoUpgrade = 4 * time.Second

// A normal answer takes about a second. Past this, one is more likely stalled than slow, and the retry
// is the better bet; a stalled scan once sat 238 seconds on one request.
const requestTimeout = 30 * time.Second

// The pause before each retry. An immediate second try mostly met the same 503 and left the scan incomplete.
var requestRetries = []time.Duration{2 * time.Second, 5 * time.Second}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "debuff:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: debuff scan|open|serve|health|version|registry")
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], out)
	case "scan":
		return runScan(args[1:], out)
	case "open":
		return openConsole(args[1:], out)
	case "health":
		return health(args[1:], out)
	case "version":
		return printVersion(args[1:], out)
	case "registry":
		return registryCommand(args[1:], out)
	}
	return fmt.Errorf("unknown command %q (scan, open, serve, health, version, registry)", args[0])
}

// stateDir: the flag, then $DEBUFF_STATE_DIR, then the real one. Rehearsals and tests set one of the
// first two, so nothing they do can reach real data.
func stateDir(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if env := os.Getenv("DEBUFF_STATE_DIR"); env != "" {
		return env, nil
	}
	return state.DefaultDir()
}

func serve(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr, "loopback address to listen on")
	dirFlag := fs.String("state-dir", "", "data directory (default $DEBUFF_STATE_DIR, else ~/.local/state/debuff)")
	demo := fs.Bool("demo", false, "show made-up sample findings, with a banner, to look at the layout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !server.IsLoopback(*addr) {
		return fmt.Errorf("refusing to bind %q: loopback only", *addr)
	}
	dir, err := stateDir(*dirFlag)
	if err != nil {
		return err
	}
	if err := state.Ensure(dir); err != nil {
		return err
	}
	s, err := state.Load(dir)
	if err != nil {
		return err
	}
	info := version.Get()
	s.LastStart, s.LastVersion = time.Now().UTC(), info.Version
	if err := state.Save(dir, s); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	token, err := state.Token(dir)
	if err != nil {
		return err
	}
	opt := server.Options{Demo: *demo, Token: token}
	if *demo {
		opt.Rows, opt.Apps, opt.Previous, opt.Pending = server.DemoRows(), server.DemoApps(), server.DemoPrevious(), server.DemoPending()
		// Nothing is changed or opened; these only exercise the buttons.
		opt.Upgrade = func(ctx context.Context, _ []string) error {
			select {
			case <-time.After(demoUpgrade):
			case <-ctx.Done():
			}
			return nil
		}
		opt.Open = func(context.Context, string) error { return nil }
		opt.Scan = func(ctx context.Context) error { // nothing is scanned; this only exercises the button
			select {
			case <-time.After(demoScan):
			case <-ctx.Done():
			}
			return nil
		}
	} else {
		opt.Load = server.LatestLoader(dir)
		opt.Upgrade, opt.Open = update.Brew, update.Open
		opt.Icons = scan.IconDir(dir)
		opt.LastFailure = func() string {
			r, err := state.LastScan(dir)
			if err != nil {
				return "couldn't read the record of the last scan: " + err.Error()
			}
			return r.Error
		}
		opt.Scan = func(ctx context.Context) error {
			s, _, _, err := scanAndWrite(ctx, dir, nil)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(out, "rescan: %d items, %d findings, %d sources incomplete\n", len(s.Items), len(s.Findings), len(s.Degraded()))
			return nil
		}
	}
	return server.Serve(ctx, *addr, info, opt, func(bound string) {
		_, _ = fmt.Fprintf(out, "debuff %s listening on http://%s state-dir=%s\n", info.Version, bound, dir)
	})
}

// scanAndWrite is one scan, for the command, the schedule and the page's button alike. It records how it went
// and tidies up after itself, so the data directory stays the same size however often it runs.
func scanAndWrite(ctx context.Context, dir string, progress func(string)) (snapshot.Snapshot, string, *fetch.Client, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return snapshot.Snapshot{}, "", nil, err
	}
	v := version.Version()
	cache := &fetch.Client{Dir: filepath.Join(dir, "cache"), UserAgent: "debuff/" + v, Interval: time.Second, Timeout: requestTimeout, Retries: requestRetries, Hosts: hostRules}
	s, err := scan.Run(ctx, scan.Options{Dir: dir, Home: home, Version: v, Cache: cache, Progress: progress})
	path := ""
	if err == nil {
		path, err = scan.Write(dir, s)
	}
	if rerr := state.RecordScan(dir, time.Now(), err); rerr != nil {
		_, _ = fmt.Fprintln(os.Stderr, "debuff: recording the scan:", rerr)
	}
	tidy(dir)
	return s, path, cache, err
}

// tidy is housekeeping, so a failure here is logged and never fails the scan that ran it.
func tidy(dir string) {
	if n, err := snapshot.Prune(dir, time.Now()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "debuff: pruning snapshots:", err)
	} else if n > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "debuff: pruned %d snapshots that added nothing\n", n)
	}
	if err := scan.PruneIcons(dir); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "debuff: pruning icons:", err)
	}
	for _, name := range []string{"serve.log", "scan.log"} {
		if err := state.TrimLog(filepath.Join(dir, name), logLimit); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "debuff: trimming", name+":", err)
		}
	}
}

// runScan scans this machine and writes one snapshot. Findings stay in the data directory; what it
// prints is only counts, so its output is safe to paste or log.
func runScan(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	dirFlag := fs.String("state-dir", "", "data directory (default $DEBUFF_STATE_DIR, else ~/.local/state/debuff)")
	timing := fs.Bool("timing", false, "say where the scan's time went, per source")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := stateDir(*dirFlag)
	if err != nil {
		return err
	}
	if err := state.Ensure(dir); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	started := time.Now()
	s, path, cache, err := scanAndWrite(ctx, dir, func(m string) { fmt.Fprintln(os.Stderr, "  "+m) })
	if err != nil {
		return err
	}
	var exploited int
	for _, f := range s.Findings {
		if f.KEV {
			exploited++
		}
	}
	_, _ = fmt.Fprintf(out, "scanned %d items: %d findings, %d known exploited. Wrote %s\n", len(s.Items), len(s.Findings), exploited, path)
	for _, d := range s.Degraded() {
		_, _ = fmt.Fprintln(out, "incomplete:", d)
	}
	if *timing {
		printTimings(out, time.Since(started), cache.Timings())
	}
	return nil
}

// printTimings is counts and durations only, so like the rest of this output it's safe to paste.
func printTimings(out io.Writer, total time.Duration, timings []fetch.Timing) {
	var paced, busy time.Duration
	_, _ = fmt.Fprintf(out, "%-44s %5s %5s %8s %8s %8s %9s\n", "source", "reqs", "fail", "paced", "busy", "slowest", "KB")
	for _, t := range timings {
		paced, busy = paced+t.Paced, busy+t.Busy
		_, _ = fmt.Fprintf(out, "%-44s %5d %5d %7.1fs %7.1fs %7.1fs %9d\n", t.Source, t.Requests, t.Failed, t.Paced.Seconds(), t.Busy.Seconds(), t.Slowest.Seconds(), t.Bytes/1024)
	}
	other := total - paced - busy
	_, _ = fmt.Fprintf(out, "total %.1fs: %.1fs waiting our turn, %.1fs on the network, %.1fs everything else\n",
		total.Seconds(), paced.Seconds(), busy.Seconds(), other.Seconds())
}

// openConsole opens the console in the browser, signed in.
func openConsole(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr, "address of the running server")
	dirFlag := fs.String("state-dir", "", "data directory")
	printOnly := fs.Bool("print", false, "print the URL instead of opening it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := stateDir(*dirFlag)
	if err != nil {
		return err
	}
	token, err := state.Token(dir)
	if err != nil {
		return err
	}
	target := "http://" + preferredHost(context.Background(), *addr) + "/?token=" + token
	if *printOnly {
		_, err := fmt.Fprintln(out, target)
		return err
	}
	// #nosec G204 -- a fixed tool, given our own loopback URL
	return exec.CommandContext(context.Background(), "/usr/bin/open", target).Run()
}

// preferredHost uses the name `debuff` when an /etc/hosts entry points it at this machine. A sign-in
// cookie belongs to one host name, so opening under the name is what makes a bookmark of it work.
func preferredHost(ctx context.Context, addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, "debuff")
	if err != nil || len(ips) == 0 {
		return addr
	}
	for _, s := range ips {
		if ip := net.ParseIP(s); ip == nil || !ip.IsLoopback() {
			return addr
		}
	}
	return net.JoinHostPort("debuff", port)
}

// health asks a running server, and fails unless it answers ok.
func health(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr, "address of the running server")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.HealthURL(*addr), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- a loopback address the operator chose
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health answered HTTP %d", resp.StatusCode)
	}
	_, err = out.Write(b)
	return err
}

// registryCommand checks that each entry's CVE source really answers: NVD must list CVEs for an old version of the
// product. A product NVD doesn't track answers none, and a wrong name does too, so "none" is what keeps an
// entry unverified. It asks about the shipped list, which isn't what's installed here.
func registryCommand(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "check" {
		return errors.New("usage: debuff registry check [--state-dir DIR]")
	}
	fs := flag.NewFlagSet("registry check", flag.ContinueOnError)
	dirFlag := fs.String("state-dir", "", "data directory")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	dir, err := stateDir(*dirFlag)
	if err != nil {
		return err
	}
	if err := state.Ensure(dir); err != nil {
		return err
	}
	reg, err := registry.Load(dir)
	if err != nil {
		return err
	}
	entries := reg.All()
	slices.SortFunc(entries, func(a, b registry.Entry) int { return strings.Compare(a.Name, b.Name) })
	v := version.Version()
	cache := &fetch.Client{Dir: filepath.Join(dir, "cache"), UserAgent: "debuff/" + v, Interval: time.Second, Timeout: requestTimeout, Retries: requestRetries, Hosts: hostRules}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	bad := 0
	for _, e := range entries {
		if e.CPE == "" {
			continue
		}
		found, _, err := resolve.NVDAffected(ctx, cache, e.CPE, e.Check)
		switch {
		case err != nil:
			bad++
			_, _ = fmt.Fprintf(out, "FAIL  %-22s %s: %v\n", e.Name, e.CPE, err)
		case len(found) == 0:
			bad++
			_, _ = fmt.Fprintf(out, "NONE  %-22s %s at %s: not a usable source\n", e.Name, e.CPE, e.Check)
		default:
			_, _ = fmt.Fprintf(out, "ok    %-22s %s at %s: %d CVEs (verified %s)\n", e.Name, e.CPE, e.Check, len(found), e.Verified)
		}
	}
	if bad > 0 {
		return fmt.Errorf("%d entries didn't check out", bad)
	}
	return nil
}

func printVersion(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	info := version.Get()
	if *asJSON {
		return json.NewEncoder(out).Encode(info)
	}
	_, err := fmt.Fprintln(out, info.Version)
	return err
}
