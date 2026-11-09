package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thwomp-io/debuff/internal/resolve"
	"github.com/thwomp-io/debuff/internal/snapshot"
)

const ownOrigin = "http://127.0.0.1:8737"

func press(t *testing.T, h http.Handler, origin, cookie, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/rescan", strings.NewReader(form))
	req.Host = "127.0.0.1:8737"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie}) // #nosec G124 -- a request in a test
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func getPage(t *testing.T, h http.Handler) string {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:8737"
	req.AddCookie(&http.Cookie{Name: cookieName, Value: testToken}) // #nosec G124 -- a request in a test
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Body.String()
}

func TestPressScansAndComesBackToTheSamePage(t *testing.T) {
	var scans atomic.Int32
	h := Handler("8737", testInfo, Options{Token: testToken, Scan: func(context.Context) error {
		scans.Add(1)
		return nil
	}})
	form := url.Values{"view": {"exploited"}, "min": {"all"}, "app": {"Some App"}}.Encode()
	rec := press(t, h, ownOrigin, testToken, form)
	if rec.Code != http.StatusSeeOther || scans.Load() != 1 {
		t.Fatalf("%d after %d scans", rec.Code, scans.Load())
	}
	if got := rec.Header().Get("Location"); got != "/?app=Some+App&min=all&view=exploited" {
		t.Fatal(got)
	}
}

// From the attacker's side: nothing but this page's own button may start a scan.
func TestOnlyThisPageCanStartAScan(t *testing.T) {
	var scans atomic.Int32
	h := Handler("8737", testInfo, Options{Token: testToken, Scan: func(context.Context) error {
		scans.Add(1)
		return nil
	}})
	for _, c := range []struct {
		name, origin, cookie string
		want                 int
	}{
		{"another site", "https://evil.example", testToken, 403},
		{"a sandboxed frame", "null", testToken, 403},
		{"another local service", "http://127.0.0.1:9000", testToken, 403},
		{"no origin at all", "", testToken, 403},
		{"no session", ownOrigin, "", 401},
		{"a wrong session", ownOrigin, "wrong", 401},
	} {
		if got := press(t, h, c.origin, c.cookie, "").Code; got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/rescan", nil)
	req.Host = "127.0.0.1:8737"
	req.AddCookie(&http.Cookie{Name: cookieName, Value: testToken}) // #nosec G124 -- a request in a test
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("a GET: %d", rec.Code)
	}
	if scans.Load() != 0 {
		t.Fatalf("%d scans started", scans.Load())
	}
}

func TestTheOffsiteRedirectCantBeAskedFor(t *testing.T) {
	h := Handler("8737", testInfo, Options{Token: testToken, Scan: func(context.Context) error { return nil }})
	rec := press(t, h, ownOrigin, testToken, url.Values{"app": {"//evil.example/"}, "view": {"https://evil.example"}}.Encode())
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/?") {
		t.Fatalf("%q", loc)
	}
}

func TestThePolicyLetsTheButtonWorkAndStillTellsOtherSitesNothing(t *testing.T) {
	rec := request(t, "/", "localhost:8737", "")
	if got := rec.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("no-referrer makes a browser send Origin: null on the button's POST: %q", got)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self'") {
		t.Fatal(csp)
	}
}

func TestTwoPressesRunOneScanAndThePageSaysSo(t *testing.T) {
	var scans atomic.Int32
	running, release := make(chan struct{}), make(chan struct{})
	h := Handler("8737", testInfo, Options{Token: testToken, Scan: func(context.Context) error {
		if scans.Add(1) == 1 {
			close(running)
		}
		<-release
		return nil
	}})
	first := make(chan int)
	go func() { first <- press(t, h, ownOrigin, testToken, "").Code }()
	<-running
	body := getPage(t, h)
	for _, want := range []string{"Scanning…", " disabled", `http-equiv="refresh"`, "the earlier results"} {
		if !strings.Contains(body, want) {
			t.Fatalf("while scanning, want %q", want)
		}
	}
	second := make(chan int)
	go func() { second <- press(t, h, ownOrigin, testToken, "").Code }()
	time.Sleep(50 * time.Millisecond)
	close(release)
	if a, b := <-first, <-second; a != http.StatusSeeOther || b != http.StatusSeeOther {
		t.Fatal(a, b)
	}
	if scans.Load() != 1 {
		t.Fatalf("%d scans", scans.Load())
	}
	if body := getPage(t, h); strings.Contains(body, "Scanning…") || strings.Contains(body, "http-equiv") {
		t.Fatal("the page should stop refreshing once it's done")
	}
}

func TestALongScanAnswersThePressAndKeepsRunning(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	s := &rescanner{base: context.Background(), wait: 10 * time.Millisecond, run: func(context.Context) error {
		<-release
		return nil
	}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/rescan", nil)
	req.Header.Set("Origin", ownOrigin)
	rec := httptest.NewRecorder()
	s.handlePress(rec, req)
	if running, _, _ := s.status(); !running || rec.Code != http.StatusSeeOther {
		t.Fatalf("running %v, status %d", running, rec.Code)
	}
}

func TestAFailedScanKeepsTheOldResultsAndSaysSo(t *testing.T) {
	var fail atomic.Value
	fail.Store("boom <b>")
	v := View{Scanned: true, ScannedAt: time.Now(), Rows: []Row{{App: "Kept App", CVE: "CVE-1", Severity: "High", Label: "Inferred"}}}
	h := Handler("8737", testInfo, Options{
		Token: testToken,
		Load:  func() (View, error) { return v, nil },
		Scan: func(context.Context) error {
			if m := fail.Load().(string); m != "" {
				return errors.New(m)
			}
			return nil
		},
	})
	press(t, h, ownOrigin, testToken, "")
	body := getPage(t, h)
	if !strings.Contains(body, "The last scan failed") || !strings.Contains(body, "Kept App") {
		t.Fatal(body)
	}
	if strings.Contains(body, "boom <b>") {
		t.Fatal("an error's text must reach the page escaped")
	}
	if strings.Contains(body, " disabled") {
		t.Fatal("a failed scan can be tried again")
	}
	fail.Store("")
	press(t, h, ownOrigin, testToken, "")
	if strings.Contains(getPage(t, h), "The last scan failed") {
		t.Fatal("a later success clears the failure")
	}
}

func TestAPanickingScanIsAFailureNotACrash(t *testing.T) {
	h := Handler("8737", testInfo, Options{Token: testToken, Scan: func(context.Context) error { panic("kaboom") }})
	press(t, h, ownOrigin, testToken, "")
	if !strings.Contains(getPage(t, h), "kaboom") {
		t.Fatal("the failure should be on the page")
	}
}

func TestShuttingDownStopsARunningScan(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	s := &rescanner{base: base, run: func(ctx context.Context) error {
		<-ctx.Done()
		close(stopped)
		return ctx.Err()
	}}
	s.start()
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the scan outlived the server")
	}
}

func TestNoScanNoButton(t *testing.T) {
	body := request(t, "/", "localhost:8737", "").Body.String()
	if strings.Contains(body, `action="/rescan"`) {
		t.Fatal("a server that can't scan shouldn't offer it")
	}
	if got := press(t, Handler("8737", testInfo, Options{Token: testToken}), ownOrigin, testToken, "").Code; got != http.StatusNotFound {
		t.Fatal(got)
	}
	withScan := Handler("8737", testInfo, Options{Token: testToken, Scan: func(context.Context) error { return nil }})
	if !strings.Contains(getPage(t, withScan), `action="/rescan"`) {
		t.Fatal("an unscanned machine needs the button most")
	}
}

func changeView(prev, now []Row, prevApps, nowApps map[string]AppFacts) View {
	return View{
		Scanned: true, ScannedAt: time.Now(), Rows: now, Apps: nowApps,
		Previous: &Previous{Rows: prev, Apps: prevApps, ScannedAt: time.Date(2020, 1, 2, 15, 4, 0, 0, time.Local)},
	}
}

func TestChangeSaysWhatClosedAndWhatsNew(t *testing.T) {
	high := func(app, cve string, kev bool) Row {
		return Row{App: app, CVE: cve, Severity: "High", Label: "Inferred", KEV: kev}
	}
	prev := []Row{high("A", "CVE-1", true), high("A", "CVE-2", false), high("Gone.app", "CVE-3", true)}
	now := []Row{high("A", "CVE-2", false), high("A", "CVE-4", false)}
	body := loaded(t, changeView(prev, now,
		map[string]AppFacts{"A": {Version: "1.0"}, "Gone.app": {}},
		map[string]AppFacts{"A": {Version: "2.0"}}), "")
	for _, want := range []string{
		"Since the scan at Jan 2, 3:04 PM", "<b>2 closed</b>", "<b>1 new</b>", "exploited 2 → 0", "Gone removed",
		"v1.0 → v2.0", "1 closed, 1 new",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestFindingsAreCollapsedOnACardAndOpenOnAnAppsPage(t *testing.T) {
	rows := []Row{{App: "A", CVE: "CVE-1", Severity: "High", Label: "Inferred"}}
	v := View{Scanned: true, ScannedAt: time.Now(), Rows: rows, Apps: map[string]AppFacts{"A": {Kind: kindApp, Why: "It handles things"}}}
	body := loaded(t, v, "")
	if !strings.Contains(body, `<details class="findings">`) || strings.Contains(body, `<details class="findings" open`) {
		t.Fatal("a card's findings start closed")
	}
	if !strings.Contains(body, "1 finding<") || !strings.Contains(body, "CVE-1") {
		t.Fatal("the count shows, and the rows are there to open")
	}
	if !strings.Contains(body, "It handles things") || !strings.Contains(body, "<b>1</b><span>high</span>") {
		t.Fatal("what matters shows without opening anything")
	}
	if page := loaded(t, v, "?app=A"); strings.Contains(page, `class="findings"`) || !strings.Contains(page, "CVE-1") {
		t.Fatal("an app's own page shows them outright")
	}
}

func TestNoChangeIsSaid(t *testing.T) {
	rows := []Row{{App: "A", CVE: "CVE-1", Severity: "High", Label: "Inferred"}}
	apps := map[string]AppFacts{"A": {Version: "1.0"}}
	body := loaded(t, changeView(rows, rows, apps, apps), "")
	if !strings.Contains(body, "No change in findings since the scan at") || strings.Contains(body, `class="changed"`) {
		t.Fatal(body)
	}
}

func TestChangeFollowsTheSeveritySetting(t *testing.T) {
	low := Row{App: "A", CVE: "CVE-LOW", Severity: "Low", Label: "Inferred"}
	high := Row{App: "A", CVE: "CVE-HIGH", Severity: "High", Label: "Inferred"}
	apps := map[string]AppFacts{"A": {}}
	v := changeView([]Row{low, high}, []Row{high}, apps, apps)
	if !strings.Contains(loaded(t, v, ""), "No change in findings") {
		t.Fatal("a Low that closed isn't a change at High+")
	}
	if !strings.Contains(loaded(t, v, "?min=all"), "<b>1 closed</b>") {
		t.Fatal("it is at All")
	}
}

func TestAnAppWithNothingLeftAtThisSettingIsntRemoved(t *testing.T) {
	high := Row{App: "A", CVE: "CVE-1", Severity: "High", Label: "Inferred"}
	apps := map[string]AppFacts{"A": {}}
	body := loaded(t, changeView([]Row{high}, nil, apps, apps), "")
	if strings.Contains(body, "removed") || !strings.Contains(body, "<b>1 closed</b>") {
		t.Fatal(body)
	}
}

func TestARescanThatFindsTheSameKeepsTheNews(t *testing.T) {
	dir := t.TempDir()
	write := func(at time.Time, cves ...string) {
		t.Helper()
		s := snapshot.Snapshot{ScannedAt: at, Items: []snapshot.Item{{App: "A"}}}
		for _, c := range cves {
			s.Findings = append(s.Findings, snapshot.Finding{CVE: c, App: "A", Label: "Inferred", Severity: "High"})
		}
		if _, err := snapshot.Write(dir, s); err != nil {
			t.Fatal(err)
		}
	}
	load := LatestLoader(dir)
	base := time.Now().Add(-3 * time.Hour)
	write(base, "CVE-1", "CVE-2")
	if v, err := load(); err != nil || v.Previous != nil {
		t.Fatalf("one scan has nothing to compare: %+v %v", v.Previous, err)
	}
	write(base.Add(time.Hour), "CVE-2")
	v, err := load()
	if err != nil || v.Previous == nil || len(v.Previous.Rows) != 2 || len(v.Rows) != 1 {
		t.Fatalf("%+v %v", v.Previous, err)
	}
	if body := loaded(t, v, ""); !strings.Contains(body, "Since the scan at") || !strings.Contains(body, "<b>1 closed</b>") {
		t.Fatal(body)
	}
	write(base.Add(2*time.Hour), "CVE-2")
	v, err = load()
	if err != nil {
		t.Fatal(err)
	}
	body := loaded(t, v, "")
	if !strings.Contains(body, "<b>1 closed</b>") {
		t.Fatal("an identical rescan erased what changed")
	}
	if !strings.Contains(body, "No change since the scan at") {
		t.Fatal("it should say this press found nothing new")
	}
}

func TestRepeatedScansOfAnUnchangedMachineSaySo(t *testing.T) {
	rows := []Row{{App: "A", CVE: "CVE-1", Severity: "High", Label: "Inferred"}}
	body := loaded(t, View{Scanned: true, ScannedAt: time.Now(), Rows: rows, UnchangedSince: time.Now().Add(-time.Hour)}, "")
	if !strings.Contains(body, "No change in findings since the scan at") {
		t.Fatal(body)
	}
}

func TestAScheduledFailureReachesThePage(t *testing.T) {
	v := View{Scanned: true, ScannedAt: time.Now(), Rows: []Row{{App: "Kept App", CVE: "CVE-1", Severity: "High", Label: "Inferred"}}}
	failure := "the network was <down>"
	h := Handler("8737", testInfo, Options{Token: testToken, Load: func() (View, error) { return v, nil }, LastFailure: func() string { return failure }})
	body := getPage(t, h)
	if !strings.Contains(body, "The last scan failed") || !strings.Contains(body, "Kept App") || strings.Contains(body, "<down>") {
		t.Fatal(body)
	}
	failure = ""
	if strings.Contains(getPage(t, h), "The last scan failed") {
		t.Fatal("a success clears it")
	}
}

func TestAnOldScanSaysSo(t *testing.T) {
	rows := []Row{{App: "A", CVE: "CVE-1", Severity: "High", Label: "Inferred"}}
	if body := loaded(t, View{Scanned: true, ScannedAt: time.Now().Add(-staleAfter - time.Hour), Rows: rows}, ""); !strings.Contains(body, "may be out of date") {
		t.Fatal(body)
	}
	if body := loaded(t, View{Scanned: true, ScannedAt: time.Now().Add(-time.Hour), Rows: rows}, ""); strings.Contains(body, "may be out of date") {
		t.Fatal(body)
	}
}

func TestACardOnlyLinksToMoreWhenThereIsMore(t *testing.T) {
	body := loaded(t, View{Scanned: true, ScannedAt: time.Now(), Rows: []Row{{App: "A", CVE: "CVE-1", Severity: "High", Label: "Inferred"}}}, "")
	if strings.Contains(body, `class="all"`) {
		t.Fatal("every finding is already on the card")
	}
}

func TestIconsNeedASessionAndTakeOnlyAHash(t *testing.T) {
	dir := t.TempDir()
	id := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(dir, id+".png"), []byte("png bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := Handler("8737", testInfo, Options{Token: testToken, Icons: dir})
	get := func(path, cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		req.Host = "127.0.0.1:8737"
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie}) // #nosec G124 -- a request in a test
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	ok := get("/icon/"+id, testToken)
	if ok.Code != 200 || ok.Body.String() != "png bytes" || ok.Header().Get("Content-Type") != "image/png" || ok.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d %q %v", ok.Code, ok.Body.String(), ok.Header())
	}
	if !strings.Contains(ok.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("named by its content, it can be cached")
	}
	if got := get("/icon/"+id, "").Code; got != 401 {
		t.Fatalf("no session: %d", got)
	}
	for _, bad := range []string{"/icon/" + strings.Repeat("b", 64), "/icon/token", "/icon/..%2f..%2ftoken", "/icon/" + strings.Repeat("A", 64), "/icon/" + id + ".png"} {
		if got := get(bad, testToken).Code; got == 200 {
			t.Errorf("%s answered", bad)
		}
	}
	none := Handler("8737", testInfo, Options{Token: testToken})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/icon/"+id, nil)
	req.Host = "127.0.0.1:8737"
	req.AddCookie(&http.Cookie{Name: cookieName, Value: testToken}) // #nosec G124 -- a request in a test
	rec := httptest.NewRecorder()
	none.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("no icons configured: %d", rec.Code)
	}
}

func TestACardShowsItsIconOrALetter(t *testing.T) {
	id := strings.Repeat("a", 64)
	rows := []Row{{App: "Mail.app", CVE: "CVE-1", Severity: "High", Label: "Inferred"}, {App: "tool", CVE: "CVE-2", Severity: "High", Label: "Inferred"}}
	body := loaded(t, View{Scanned: true, ScannedAt: time.Now(), Rows: rows, Apps: map[string]AppFacts{"Mail.app": {Icon: id}, "tool": {}}}, "")
	if !strings.Contains(body, `src="/icon/`+id+`"`) {
		t.Fatal("the app with an icon should show it")
	}
	if !strings.Contains(body, `class="icon letter" aria-hidden="true">T<`) {
		t.Fatal("the one without should show a letter")
	}
}

func TestEverythingElseIsListedAndNeverReadsAsClean(t *testing.T) {
	rows := []Row{{App: "Carded.app", CVE: "CVE-1", Severity: "High", Label: "Inferred"}}
	v := View{Scanned: true, ScannedAt: time.Now(), Rows: rows, Apps: map[string]AppFacts{
		"Carded.app":  {Kind: kindElectron},
		"Zed.app":     {Kind: kindApp, Version: "1.0", Latest: "2.0", Update: resolve.UpdateAvailable},
		"Alpha.app":   {Kind: kindApp, Version: "1.0"},
		"Scanned.app": {Kind: kindElectron, Version: "1.0"},
		"Agent":       {Kind: kindAgentTool, CVESource: "OSV", Version: "1.0"},
		"MCP: moving": {Kind: kindAgentTool, Note: "Unpinned: runs whatever is newest each time it starts"},
	}}
	body := loaded(t, v, "")
	section := body[strings.Index(body, "Also on this machine"):]
	if strings.Contains(section, "Carded") {
		t.Fatal("an app with a card isn't listed again")
	}
	split := strings.Index(section, "<h4>No CVE source</h4>")
	if split < 0 {
		t.Fatal("what couldn't be checked must be named")
	}
	checked, unchecked := section[:split], section[split:]
	if !strings.Contains(unchecked, "doesn't make them clean") {
		t.Fatal("the group must say what it means")
	}
	for _, name := range []string{"Scanned", "Agent"} {
		if !strings.Contains(checked, ">"+name) {
			t.Errorf("%s was checked", name)
		}
	}
	for _, name := range []string{"Alpha", "Zed", "MCP: moving"} {
		if !strings.Contains(unchecked, ">"+name) || strings.Contains(checked, ">"+name) {
			t.Errorf("%s has no CVE source", name)
		}
	}
	if strings.Index(unchecked, ">Zed") > strings.Index(unchecked, ">Alpha") {
		t.Fatal("something to update comes first")
	}
	if !strings.Contains(unchecked, "v2.0 available") || !strings.Contains(unchecked, "Unpinned") {
		t.Fatal("the update and the note should show")
	}
	if strings.Contains(section, ">latest<") {
		t.Fatal("nothing here is known to be latest, and unknown must not read as current")
	}
	if strings.Contains(loaded(t, v, "?view=exploited"), "Also on this machine") {
		t.Fatal("only the inbox lists everything else")
	}
	if strings.Contains(loaded(t, v, "?app=Carded.app"), "Also on this machine") {
		t.Fatal("an app's own page doesn't")
	}
}
