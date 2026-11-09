package scan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thwomp-io/debuff/internal/collect"
	"github.com/thwomp-io/debuff/internal/fetch"
	"github.com/thwomp-io/debuff/internal/snapshot"
)

// A fake internet: Chrome's feed, Electron's list and notes, OSV, the known-exploited list, EPSS, git.
type world struct {
	failing string
	routes  map[string]string
}

func (w world) do(r *http.Request) (*http.Response, error) {
	u := r.URL.String()
	if w.failing != "" && strings.Contains(u, w.failing) {
		return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	for needle, body := range w.routes {
		if strings.Contains(u, needle) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		}
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func feedEntry(id, date, version, cves string) string {
	return `<entry><id>` + id + `</id><title>Stable Channel Update for Desktop</title><published>` + date + `T00:00:00</published>
<content>updated to ` + version + ` for Mac ` + cves + `</content><link rel="alternate" href="https://example.test/` + id + `"/></entry>`
}

var routes = map[string]string{
	"Desktop%20Update": `<feed>` +
		feedEntry("p3", "2026-10-29", "156.0.8078.79", `[5555555] Critical CVE-2026-76024: Memory corruption in MediaStream. Reported`) +
		feedEntry("p2", "2026-09-08", "153.0.8010.36", `[543557673] Medium CVE-2026-87491: Out of bounds write in V8. Reported [7777777] High CVE-2026-1111: Use after free in Extensions. Reported`) +
		feedEntry("p1", "2020-01-01", "80.0.1000.1", `[8888888] High CVE-2020-0001: Old thing in Blink. Reported`) + `</feed>`,
	"releases.json": `[{"version":"45.0.0","chrome":"156.0.8078.75","v8":"15.6.1.1","date":"2026-10-20"},
		{"version":"44.9.1","chrome":"152.0.7977.167","v8":"15.2.124.43","date":"2026-10-20"},
		{"version":"44.0.0","chrome":"152.0.7977.1","v8":"15.2.1.1","date":"2026-08-01"},
		{"version":"43.0.0","chrome":"150.0.1.1","v8":"15.0.1.1","date":"2026-06-01"}]`,
	"release/v":       `<p>nothing</p>`,
	"api/cask.json":   `[{"token":"chat","version":"8.34.0","artifacts":[{"app":["Chat.app"]}]}]`,
	"known_exploited": `{"vulnerabilities":[{"cveID":"CVE-2026-87491"}]}`,
	"api.first.org":   `{"data":[{"cve":"CVE-2026-76024","epss":"0.25"}]}`,
	"api.osv.dev": `{"vulns":[{"id":"GHSA-x","aliases":["CVE-2026-2222"],"summary":"An Electron bug","published":"2026-10-01T00:00:00Z",
		"database_specific":{"severity":"MODERATE"},"affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"44.10.0"}]}]}]}]}`,
	"chromium/src/+log": ")]}'\n" + `{"log":[{"message":"cut","committer":{"time":"Mon Aug 03 00:00:00 2026"}}]}`,
	"v8/v8/+log":        ")]}'\n" + `{"log":[{"message":"[M152] fix\n\nBug: 543557673","committer":{"time":"Thu Sep 03 18:14:49 2026"}}]}`,
}

func options(t *testing.T, w world) Options {
	t.Helper()
	dir := t.TempDir()
	return Options{
		Dir: dir, Version: "9.9.9", Now: func() time.Time { return time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC) },
		Cache: &fetch.Client{Dir: dir, UserAgent: "t", Do: w.do},
		Runtimes: func(_ context.Context, chromiumOf func(string) string) ([]collect.Runtime, error) {
			return []collect.Runtime{
				{App: "Chat.app", Kind: collect.KindElectron, Electron: "44.9.1", Chromium: chromiumOf("44.9.1")},
				{App: "Playwright chromium-1", Kind: collect.KindBrowser, Chromium: "156.0.8078.4"},
			}, nil
		},
		Brew: func(context.Context) (collect.BrewReport, error) {
			return collect.BrewReport{Checked: 10, Skipped: []string{"a"}, Findings: []collect.BrewFormula{
				{Formula: "brotli", Version: "1", Vulnerabilities: []collect.BrewVuln{{ID: "CVE-2026-3", Severity: "UNKNOWN", Summary: "XS::libbrotli issue"}}},
				{Formula: "poppler", Version: "2", Vulnerabilities: []collect.BrewVuln{{ID: "CVE-2026-4", Severity: "HIGH", Summary: "poppler overflow in Decrypt::hash"}}},
			}}, nil
		},
		Listening: func(context.Context) map[string]bool { return map[string]bool{"poppler": true} },
		Apps: func(context.Context, map[string]bool) ([]collect.App, error) {
			return []collect.App{{Name: "Browser.app", Running: true, Bundle: collect.BundleFacts{Version: "8.0.0"}}}, nil
		},
		Outdated: func(context.Context) ([]collect.Pending, error) {
			return []collect.Pending{{Name: "poppler", Installed: "2", Latest: "3"}, {Name: "uv", Installed: "1", Latest: "2"}}, nil
		},
		System: func(context.Context) ([]collect.Pending, error) {
			return []collect.Pending{{Name: "Browser", Latest: "9.0"}, {Name: "macOS 99", Installed: "98", Latest: "99", Restart: true}}, nil
		},
		AgentTools: func() ([]collect.AgentTool, []string) {
			return []collect.AgentTool{
				{Name: "Agent", Kind: collect.AgentCLI, Version: "1.0.0", Ecosystem: "npm", Pkg: "agent"},
				{Name: "MCP: remote", Kind: collect.AgentMCP, Host: "mcp.example"},
				{Name: "MCP: moving", Kind: collect.AgentMCP, Ecosystem: "npm", Pkg: "moving", Unpinned: true},
			}, nil
		},
	}
}

func find(s snapshot.Snapshot, app, cve string) *snapshot.Finding {
	for i := range s.Findings {
		if s.Findings[i].App == app && s.Findings[i].CVE == cve {
			return &s.Findings[i]
		}
	}
	return nil
}

func TestScanLabelsEachFindingFromItsEvidence(t *testing.T) {
	s, err := Run(context.Background(), options(t, world{routes: routes}))
	if err != nil {
		t.Fatal(err)
	}
	if got := find(s, "Chat.app", "CVE-2026-76024"); got == nil || got.Label != snapshot.Inferred || got.FixedIn != "156.0.8078.79" || got.EPSS != 0.25 {
		t.Fatalf("behind the fix should be Inferred and scored: %+v", got)
	}
	// The spike's false positive: rated exploited, but the fix is on the app's V8 branch.
	if got := find(s, "Chat.app", "CVE-2026-87491"); got != nil {
		t.Fatalf("a fix on the engine branch must clear it: %+v", got)
	}
	// The same CVE on a browser with no engine evidence is older-than-fix... unless it's past it.
	if got := find(s, "Chat.app", "CVE-2026-1111"); got == nil || !got.Absent {
		t.Fatalf("a Chrome-only component should be hidden, not dropped: %+v", got)
	}
	if got := find(s, "Chat.app", "CVE-2026-2222"); got == nil || got.Label != snapshot.Confirmed || got.Severity != "Medium" || got.FixedIn != "44.10.0" {
		t.Fatalf("an advisory on this version is Confirmed: %+v", got)
	}
	if got := find(s, "Playwright chromium-1", "CVE-2026-76024"); got == nil || got.Label != snapshot.Inferred {
		t.Fatalf("the chromium-1248 class: %+v", got)
	}
	if got := find(s, "brotli", "CVE-2026-3"); got == nil || got.Label != snapshot.Doubtful || !got.Absent || got.Severity != "Unrated" {
		t.Fatalf("another project's module is Doubtful: %+v", got)
	}
	if got := find(s, "poppler", "CVE-2026-4"); got == nil || got.Label != snapshot.Confirmed {
		t.Fatalf("a C++ symbol in the summary must not read as foreign: %+v", got)
	}
	exposures := map[string]int{}
	for _, it := range s.Items {
		exposures[it.App] = it.Exposure
	}
	if exposures["poppler"] != 3 || exposures["brotli"] != 1 || exposures["Chat.app"] != 2 {
		t.Fatalf("%v", exposures)
	}
	if len(s.Degraded()) != 0 {
		t.Fatalf("%v", s.Degraded())
	}
}

func TestAFailedSourceDegradesVisibly(t *testing.T) {
	for _, c := range []struct{ failing, want string }{
		{"Desktop%20Update", "Chrome Releases"},
		{"known_exploited", "CISA"},
		{"api.osv.dev", "OSV"},
		{"api.first.org", "EPSS"},
		{"chromium/src/+log", "branch history"},
	} {
		s, err := Run(context.Background(), options(t, world{routes: routes, failing: c.failing}))
		if err != nil {
			t.Fatalf("%s: a failed source must not fail the scan: %v", c.failing, err)
		}
		if !strings.Contains(strings.Join(s.Degraded(), "\n"), c.want) {
			t.Errorf("%s: want a degraded %q, got %v", c.failing, c.want, s.Degraded())
		}
	}
}

func TestAnUnreadableExposureFileStopsTheScan(t *testing.T) {
	o := options(t, world{routes: routes})
	o.Brew = func(context.Context) (collect.BrewReport, error) { return collect.BrewReport{}, errors.New("no brew") }
	s, err := Run(context.Background(), o)
	if err != nil || !strings.Contains(strings.Join(s.Degraded(), ""), "Homebrew") {
		t.Fatalf("brew missing should degrade: %v %v", err, s.Degraded())
	}
}

func TestForeignAdvisory(t *testing.T) {
	for _, c := range []struct {
		f, s string
		want bool
	}{
		{"brotli", "XS::libbrotli (a Perl module) issue", true},
		{"poppler", "Poppler through 26.10.0 Stack Buffer Overflow via Decrypt::revision6Hash()", false},
		{"librsvg", "UNKNOWN READ in _blit_xrgb32_lerp_spans", false},
	} {
		if foreignAdvisory(c.f, c.s) != c.want {
			t.Errorf("%s", c.f)
		}
	}
}

func TestIconsAreKeptByContentAndPruned(t *testing.T) {
	dir := t.TempDir()
	r := &run{Options: Options{Dir: dir}}
	id := r.saveIcon([]byte("an icon"))
	other := r.saveIcon([]byte("an icon since removed"))
	if len(id) != 64 || r.saveIcon([]byte("an icon")) != id || r.saveIcon(nil) != "" {
		t.Fatal(id)
	}
	if _, err := snapshot.Write(dir, snapshot.Snapshot{ScannedAt: time.Unix(1, 0), Items: []snapshot.Item{{App: "A", Icon: id}, {App: "B"}}}); err != nil {
		t.Fatal(err)
	}
	if err := PruneIcons(dir); err != nil {
		t.Fatal(err)
	}
	names, err := filepath.Glob(filepath.Join(IconDir(dir), "*"))
	if err != nil || len(names) != 1 || filepath.Base(names[0]) != id+".png" {
		t.Fatalf("%v %v; want only the used one, not %s", names, err, other)
	}
}

func TestPruneIconsWithNoScanYet(t *testing.T) {
	if err := PruneIcons(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestEveryAppAndAgentToolIsListedHonestly(t *testing.T) {
	w := world{routes: routes}
	s, err := Run(context.Background(), options(t, w))
	if err != nil {
		t.Fatal(err)
	}
	items := map[string]snapshot.Item{}
	for _, it := range s.Items {
		items[it.App] = it
	}
	if b := items["Browser.app"]; b.Kind != KindApp || b.AppVersion != "8.0.0" || !b.Running || b.CVESource != "" {
		t.Fatalf("an app with no CVE source must say so: %+v", b)
	}
	if a := items["Agent"]; a.Kind != KindAgentTool || a.CVESource != "OSV" {
		t.Fatalf("%+v", a)
	}
	if r := items["MCP: remote"]; !strings.Contains(r.ExposureWhy, "mcp.example") || r.CVESource != "" {
		t.Fatalf("%+v", r)
	}
	if m := items["MCP: moving"]; !strings.Contains(m.Note, "Unpinned") || m.CVESource != "" {
		t.Fatalf("an unpinned package with no known version can't have been checked: %+v", m)
	}
	var agentFindings int
	for _, f := range s.Findings {
		if f.App == "Agent" {
			agentFindings++
		}
	}
	if agentFindings == 0 {
		t.Fatal("OSV's answer for the agent should be findings")
	}
}

func TestPendingUpdatesReachTheCardsTheyBelongTo(t *testing.T) {
	s, err := Run(context.Background(), options(t, world{routes: routes}))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Pending) != 4 {
		t.Fatalf("%+v", s.Pending)
	}
	for _, it := range s.Items {
		switch it.App {
		case "poppler", "Browser.app":
			if it.Update != "available" {
				t.Errorf("%s should show its update: %+v", it.App, it)
			}
		}
	}
	for _, p := range s.Pending {
		if p.Name == "Browser" && (p.Via != snapshot.ViaSystem || p.Installed != "8.0.0") {
			t.Errorf("a system component takes its installed version from its bundle: %+v", p)
		}
		if p.Name == "macOS 99" && !p.Restart {
			t.Errorf("%+v", p)
		}
	}
}

// A source failing makes the page say so; it doesn't lose the scan.
func TestAFailedUpdateSourceIsSaid(t *testing.T) {
	o := options(t, world{routes: routes})
	o.Outdated = func(context.Context) ([]collect.Pending, error) { return nil, errors.New("no brew") }
	s, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(s.Degraded(), func(d string) bool { return strings.Contains(d, "no brew") }) {
		t.Fatalf("%v", s.Degraded())
	}
}
