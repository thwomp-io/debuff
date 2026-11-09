package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thwomp-io/debuff/internal/resolve"
	"github.com/thwomp-io/debuff/internal/snapshot"
	"github.com/thwomp-io/debuff/internal/update"
)

func updatesFixture() View {
	return View{
		Scanned: true, ScannedAt: time.Now(),
		Apps: map[string]AppFacts{
			"Behind.app":   {Kind: kindElectron, Version: "1.0", Latest: "2.0", Update: resolve.UpdateAvailable, Path: "/Applications/Behind.app"},
			"Quiet.app":    {Kind: kindApp, Version: "1.0", Latest: "1.1", Update: resolve.UpdateAvailable, Path: "/Applications/Quiet.app"},
			"Stuck.app":    {Kind: kindElectron, Version: "3.0", Latest: "3.0", Update: resolve.UpdateCurrent, Path: "/Applications/Stuck.app"},
			"Store.app":    {Kind: kindApp, Version: "1.0", AppStore: true, Path: "/Applications/Store.app"},
			"Mystery.app":  {Kind: kindApp, Version: "1.0", Path: "/Applications/Mystery.app"},
			"Browser.app":  {Kind: kindApp, Version: "8.0", Latest: "9.0", Update: resolve.UpdateAvailable, Path: "/Applications/Browser.app"},
			"Bought.app":   {Kind: kindApp, Version: "1.0", Latest: "2.0", Update: resolve.UpdateAvailable, AppStore: true, Path: "/Applications/Bought.app"},
			"Agent thing":  {Kind: kindAgentTool},
			"Pathless.app": {Kind: kindApp, Version: "1.0", Latest: "2.0", Update: resolve.UpdateAvailable},
		},
		Rows: []Row{
			{App: "Behind.app", CVE: "CVE-1", Severity: "High", KEV: true},
			{App: "Behind.app", CVE: "CVE-2", Severity: "Critical"},
			{App: "Behind.app", CVE: "CVE-3", Severity: "Critical", Absent: true},
			{App: "Stuck.app", CVE: "CVE-4", Severity: "High", KEV: true},
			{App: "tool", CVE: "CVE-5", Severity: "High"},
		},
		Pending: []snapshot.Pending{
			{Name: "tool", Installed: "1", Latest: "2", Via: snapshot.ViaHomebrew},
			{Name: "Browser", Latest: "9.0", Via: snapshot.ViaSystem},
			{Name: "macOS 99", Installed: "98", Latest: "99", Via: snapshot.ViaSystem, Restart: true},
		},
	}
}

func rowNamed(t *testing.T, rows []UpdateRow, name string) UpdateRow {
	t.Helper()
	i := slices.IndexFunc(rows, func(u UpdateRow) bool { return u.Name() == name })
	if i < 0 {
		t.Fatalf("no %s in %+v", name, rows)
	}
	return rows[i]
}

// The reason this page exists: an exploited finding in an app with no update is nothing anyone can act on.
func TestOnlyWhatHasAnUpdateIsListed(t *testing.T) {
	rows := updateRows(updatesFixture())
	if slices.ContainsFunc(rows, func(u UpdateRow) bool { return u.Name() == "Stuck" }) {
		t.Fatal("an app with findings and no update isn't an update")
	}
	if rows[0].Name() != "Behind" {
		t.Fatalf("known exploited comes first: %+v", rows[0])
	}
	if c := rows[0]; c.Exploited != 1 || c.Critical != 1 || c.High != 1 {
		t.Fatalf("a finding probably absent here isn't counted: %+v", c)
	}
	if n := len(rows); n != 7 {
		t.Fatalf("%d rows: %+v", n, rows)
	}
}

func TestEachKindGetsTheActionItCanHonestlyDo(t *testing.T) {
	rows := updateRows(updatesFixture())
	if u := rowNamed(t, rows, "tool"); u.Formula != "tool" || u.Open != "" || !u.Primary() {
		t.Errorf("a formula upgrades here: %+v", u)
	}
	if u := rowNamed(t, rows, "Behind"); u.Open != "/Applications/Behind.app" || u.Formula != "" || u.Primary() {
		t.Errorf("an app opens: %+v", u)
	}
	if u := rowNamed(t, rows, "Bought"); u.Open != update.AppStore {
		t.Errorf("an App Store app goes there: %+v", u)
	}
	if u := rowNamed(t, rows, "macOS 99"); u.Open != update.SoftwareUpdate || !u.Restart {
		t.Errorf("%+v", u)
	}
	// A system component with a bundle appears once, with its findings and icon, going where it's installed from.
	if u := rowNamed(t, rows, "Browser"); u.Open != update.SoftwareUpdate || u.Installed != "" {
		t.Errorf("%+v", u)
	}
	if u := rowNamed(t, rows, "Pathless"); u.Button != "" || u.Open != "" {
		t.Errorf("nothing to press: %+v", u)
	}
}

func TestWhatCantBeSeenIsSaid(t *testing.T) {
	store, unknown := notListed(updatesFixture())
	if !slices.Equal(store, []string{"Store"}) || !slices.Equal(unknown, []string{"Mystery"}) {
		t.Fatalf("%v %v", store, unknown)
	}
}

func TestUpdatesViewAndNav(t *testing.T) {
	d := buildPage("1", updatesView, "", "", false, updatesFixture())
	if !d.OnUpdates || d.Title != "Updates" || len(d.Updates) != 7 || d.Cards != nil || len(d.Filters) != 0 {
		t.Fatalf("%+v", d)
	}
	if d.Views[1].Name != "Updates" || d.Views[1].Count != 7 || !d.Views[1].Current || d.Views[0].Current {
		t.Fatalf("%+v", d.Views)
	}
	inbox := buildPage("1", "", "", "", false, updatesFixture())
	if inbox.OnUpdates || inbox.Updates != nil || inbox.Views[1].Current || !inbox.Views[0].Current {
		t.Fatalf("%+v", inbox.Views)
	}
}

func TestUpdatesPageRendersEscaped(t *testing.T) {
	v := updatesFixture()
	v.Pending = append(v.Pending, snapshot.Pending{Name: "<script>x</script>", Latest: "<b>2", Via: snapshot.ViaSystem})
	h := Handler("8737", testInfo, Options{Token: testToken, Load: func() (View, error) { return v, nil }, Upgrade: func(context.Context, []string) error { return nil }})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/?view=updates", nil)
	req.Host = "127.0.0.1:8737"
	req.AddCookie(&http.Cookie{Name: cookieName, Value: testToken}) // #nosec G124 -- a request in a test
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != 200 || strings.Contains(body, "<script>x") || !strings.Contains(body, "Mystery") || !strings.Contains(body, `name="row" value="tool"`) {
		t.Fatalf("%d\n%s", rec.Code, body)
	}
}

// A press whose only input is the row: what runs comes from the scan.
type presses struct {
	mu       sync.Mutex
	upgraded []string
	opened   []string
	scans    int
	upErr    error
	hold     chan struct{}
}

func pressRow(t *testing.T, h http.Handler, origin, cookie, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/update", strings.NewReader(form))
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

func harness(p *presses) http.Handler {
	return Handler("8737", testInfo, Options{
		Token: testToken,
		Load:  func() (View, error) { return updatesFixture(), nil },
		Upgrade: func(_ context.Context, f []string) error {
			if p.hold != nil {
				<-p.hold
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			p.upgraded = append(p.upgraded, strings.Join(f, " "))
			return p.upErr
		},
		Open: func(_ context.Context, target string) error {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.opened = append(p.opened, target)
			return nil
		},
		Scan: func(context.Context) error {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.scans++
			return nil
		},
	})
}

func (p *presses) waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		ok := cond()
		p.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func TestPressingAFormulaUpgradesItThenRescans(t *testing.T) {
	p := &presses{}
	h := harness(p)
	rec := pressRow(t, h, ownOrigin, testToken, url.Values{"row": {"tool"}, "min": {"all"}}.Encode())
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/?min=all&view=updates" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	p.waitFor(t, func() bool { return len(p.upgraded) == 1 && p.scans == 1 })
	if p.upgraded[0] != "tool" || len(p.opened) != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestPressingAnAppOpensWhatTheScanFound(t *testing.T) {
	p := &presses{}
	rec := pressRow(t, harness(p), ownOrigin, testToken, url.Values{"row": {"Behind.app"}}.Encode())
	if rec.Code != http.StatusSeeOther || !slices.Equal(p.opened, []string{"/Applications/Behind.app"}) || len(p.upgraded) != 0 {
		t.Fatalf("%d %+v", rec.Code, p)
	}
}

// From the attacker's side: a request can name a row and nothing else.
func TestARequestCantChooseWhatRuns(t *testing.T) {
	p := &presses{}
	h := harness(p)
	for _, form := range []url.Values{
		{"row": {"/tmp/evil.app"}},
		{"row": {"--force"}},
		{"row": {"Stuck.app"}},
		{"row": {"Store.app"}},
		{"row": {""}},
		{"formula": {"evil"}, "open": {"/tmp/evil.app"}},
	} {
		pressRow(t, h, ownOrigin, testToken, form.Encode())
	}
	if len(p.upgraded)+len(p.opened) != 0 {
		t.Fatalf("%+v", p)
	}
	if !strings.Contains(getPage(t, h), "no longer listed") {
		t.Fatal("the page should say nothing was run")
	}
}

func TestOnlyThisPageCanPressARow(t *testing.T) {
	p := &presses{}
	h := harness(p)
	form := url.Values{"row": {"tool"}}.Encode()
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
		if got := pressRow(t, h, c.origin, c.cookie, form).Code; got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
	if len(p.upgraded) != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestOneUpgradeAtATime(t *testing.T) {
	p := &presses{hold: make(chan struct{})}
	h := harness(p)
	form := url.Values{"row": {"tool"}}.Encode()
	pressRow(t, h, ownOrigin, testToken, form)
	pressRow(t, h, ownOrigin, testToken, form)
	page := getUpdates(t, h)
	if !strings.Contains(page, "Updating tool") || !strings.Contains(page, "Updating…") || !strings.Contains(page, `http-equiv="refresh"`) {
		t.Fatalf("the page should say so and keep checking:\n%s", page)
	}
	close(p.hold)
	p.waitFor(t, func() bool { return len(p.upgraded) >= 1 && p.scans == 1 })
	if len(p.upgraded) != 1 {
		t.Fatalf("%+v", p.upgraded)
	}
}

func TestAFailedUpgradeIsSaidAndStillRescans(t *testing.T) {
	p := &presses{upErr: errors.New("exit status 1: <b>locked</b>")}
	h := harness(p)
	pressRow(t, h, ownOrigin, testToken, url.Values{"row": {"tool"}}.Encode())
	p.waitFor(t, func() bool { return len(p.upgraded) == 1 })
	deadline := time.Now().Add(5 * time.Second)
	var page string
	for time.Now().Before(deadline) {
		if page = getUpdates(t, h); strings.Contains(page, "failed") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(page, "brew upgrade tool failed") || strings.Contains(page, "<b>locked") {
		t.Fatalf("%s", page)
	}
	// A failed upgrade can still have changed things (a dependency, the formulae before the failure).
	p.waitFor(t, func() bool { return p.scans == 1 })
}

func TestTheAppStoreButton(t *testing.T) {
	p := &presses{}
	pressRow(t, harness(p), ownOrigin, testToken, url.Values{"store": {"1"}}.Encode())
	if !slices.Equal(p.opened, []string{update.AppStore}) {
		t.Fatalf("%+v", p.opened)
	}
}

func getUpdates(t *testing.T, h http.Handler) string {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/?view=updates", nil)
	req.Host = "127.0.0.1:8737"
	req.AddCookie(&http.Cookie{Name: cookieName, Value: testToken}) // #nosec G124 -- a request in a test
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Body.String()
}

// An outcome is news once. Left up, a refused press or an old "updated" would read as current for days.
func TestAnOutcomeShowsOnce(t *testing.T) {
	p := &presses{}
	h := harness(p)
	pressRow(t, h, ownOrigin, testToken, url.Values{"row": {"gone"}}.Encode())
	if !strings.Contains(getUpdates(t, h), "no longer listed") {
		t.Fatal("should say so once")
	}
	if strings.Contains(getUpdates(t, h), "no longer listed") {
		t.Fatal("should not say so twice")
	}

	pressRow(t, h, ownOrigin, testToken, url.Values{"row": {"tool"}}.Encode())
	deadline := time.Now().Add(5 * time.Second)
	seen := false
	for time.Now().Before(deadline) && !seen {
		seen = strings.Contains(getUpdates(t, h), "tool updated.")
		time.Sleep(time.Millisecond)
	}
	if !seen {
		t.Fatal("the outcome should show after the rescan settles, or during it")
	}
	p.waitFor(t, func() bool { return p.scans == 1 })
	for time.Now().Before(deadline) {
		if !strings.Contains(getUpdates(t, h), "Scanning…") {
			break
		}
		time.Sleep(time.Millisecond)
	}
	_ = getUpdates(t, h)
	if strings.Contains(getUpdates(t, h), "tool updated.") {
		t.Fatal("should be gone once shown with nothing running")
	}
}

func TestUpdateAllIsOneUpgradeOfEveryHomebrewRow(t *testing.T) {
	v := updatesFixture()
	v.Pending = append(v.Pending, snapshot.Pending{Name: "other", Installed: "1", Latest: "2", Via: snapshot.ViaHomebrew})
	p := &presses{}
	h := Handler("8737", testInfo, Options{
		Token: testToken, Load: func() (View, error) { return v, nil },
		Upgrade: func(_ context.Context, f []string) error {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.upgraded = append(p.upgraded, strings.Join(f, " "))
			return nil
		},
		Scan: func(context.Context) error {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.scans++
			return nil
		},
	})
	if !strings.Contains(getUpdates(t, h), "Update all (2)") {
		t.Fatal("the button should count the Homebrew rows")
	}
	rec := pressRow(t, h, ownOrigin, testToken, url.Values{"all": {"1"}}.Encode())
	if rec.Code != http.StatusSeeOther {
		t.Fatal(rec.Code)
	}
	p.waitFor(t, func() bool { return len(p.upgraded) == 1 && p.scans == 1 })
	if p.upgraded[0] != "tool other" { // page order: the row with findings first
		t.Fatalf("one brew command for both, nothing else: %q", p.upgraded)
	}
}

func TestDuringUpdateAllEachRowSaysUpdating(t *testing.T) {
	v := updatesFixture()
	v.Pending = append(v.Pending, snapshot.Pending{Name: "other", Installed: "1", Latest: "2", Via: snapshot.ViaHomebrew})
	hold := make(chan struct{})
	h := Handler("8737", testInfo, Options{
		Token: testToken, Load: func() (View, error) { return v, nil },
		Upgrade: func(context.Context, []string) error { <-hold; return nil },
	})
	pressRow(t, h, ownOrigin, testToken, url.Values{"all": {"1"}}.Encode())
	page := getUpdates(t, h)
	close(hold)
	if strings.Count(page, "Updating…") != 3 { // both rows and the header button
		t.Fatalf("want 3 Updating… labels:\n%s", page)
	}
	if !strings.Contains(page, "Updating 2 formulae (tool, other)") {
		t.Fatal("the summary should name what's running")
	}
}

func TestAPressDuringAnUpdateSaysItWasIgnored(t *testing.T) {
	p := &presses{hold: make(chan struct{})}
	h := harness(p)
	pressRow(t, h, ownOrigin, testToken, url.Values{"row": {"tool"}}.Encode())
	pressRow(t, h, ownOrigin, testToken, url.Values{"all": {"1"}}.Encode())
	if !strings.Contains(getUpdates(t, h), "Another update is running, so this press was ignored.") {
		t.Fatal("a refused press must say so, not vanish")
	}
	close(p.hold)
	p.waitFor(t, func() bool { return len(p.upgraded) == 1 })
}

func TestNoUpdateAllButtonWithNothingToPatch(t *testing.T) {
	v := updatesFixture()
	v.Pending = nil
	h := Handler("8737", testInfo, Options{
		Token: testToken, Load: func() (View, error) { return v, nil },
		Upgrade: func(context.Context, []string) error { return nil },
	})
	if strings.Contains(getUpdates(t, h), "Update all") {
		t.Fatal("no Homebrew rows, no button")
	}
}
