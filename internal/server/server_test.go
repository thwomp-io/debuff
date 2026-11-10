package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thwomp-io/debuff/internal/resolve"
	"github.com/thwomp-io/debuff/internal/version"
)

var testInfo = version.Info{Version: "9.9.9", Commit: "abc"}

const testToken = "test-token-test-token-test-token"

func request(t *testing.T, path, host, origin string) *httptest.ResponseRecorder {
	t.Helper()
	return requestWith(t, Options{Token: testToken}, path, host, origin)
}

func requestWith(t *testing.T, opt Options, path, host, origin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	req.Host = host
	if opt.Token == "" {
		opt.Token = testToken
	}
	req.AddCookie(&http.Cookie{Name: cookieName, Value: opt.Token}) // #nosec G124 -- a request in a test
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	Handler("8737", testInfo, opt).ServeHTTP(rec, req)
	return rec
}

func TestHealthReportsTheVersion(t *testing.T) {
	rec := request(t, "/healthz", "127.0.0.1:8737", "")
	var got struct {
		Status, Version string
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || got.Status != "ok" || got.Version != "9.9.9" {
		t.Fatalf("%d %+v", rec.Code, got)
	}
}

func TestPageRendersWithAStrictPolicyAndNoRemoteAssets(t *testing.T) {
	rec := request(t, "/", "localhost:8737", "")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "9.9.9") {
		t.Fatalf("%d %q", rec.Code, body)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("missing CSP")
	}
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") || strings.Contains(body, "<script") {
		t.Fatal("the page must load nothing remote and run no script")
	}
	if css := request(t, "/style.css", "localhost:8737", ""); css.Code != 200 {
		t.Fatalf("style.css %d", css.Code)
	}
}

func TestGuardRefusals(t *testing.T) {
	for _, c := range []struct {
		name, host, origin string
		want               int
	}{
		{"loopback ip", "127.0.0.1:8737", "", 200},
		{"ipv6 loopback", "[::1]:8737", "", 200},
		{"the hosts-file name", "debuff:8737", "http://debuff:8737", 200},
		{"a domain under that name", "debuff.evil.example:8737", "", 403},
		{"that name on a domain", "evil.example.debuff:8737", "", 403},
		{"own origin", "127.0.0.1:8737", "http://127.0.0.1:8737", 200},
		{"rebinding domain", "evil.example:8737", "", 403},
		{"rebinding, no port", "evil.example", "", 403},
		{"lan address", "192.168.1.5:8737", "", 403},
		{"wrong port", "127.0.0.1:9999", "", 403},
		{"cross-site origin", "127.0.0.1:8737", "https://evil.example", 403},
		{"other local port", "127.0.0.1:8737", "http://127.0.0.1:9000", 403},
		{"null origin", "127.0.0.1:8737", "null", 403},
	} {
		if got := request(t, "/healthz", c.host, c.origin).Code; got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestServeRefusesANonLoopbackAddress(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "192.168.1.5:0", "example.com:0", "nonsense"} {
		err := Serve(context.Background(), addr, testInfo, Options{Token: testToken}, func(string) { t.Error("became ready") })
		if err == nil || !strings.Contains(err.Error(), "loopback only") {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestServeAnswersThenStopsCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bound := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, "127.0.0.1:0", testInfo, Options{Token: testToken}, func(a string) { bound <- a })
	}()
	addr := <-bound
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, HealthURL(addr), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("didn't stop")
	}
}

func TestARealServerNeverShowsSampleData(t *testing.T) {
	body := request(t, "/", "localhost:8737", "").Body.String()
	for _, sample := range []string{"Sample data", "CVE-0000", "Example Mail"} {
		if strings.Contains(body, sample) {
			t.Fatalf("the real page shows %q", sample)
		}
	}
	if !strings.Contains(body, "Nothing scanned yet") || !strings.Contains(body, "mean this machine is safe") {
		t.Fatal("an empty inbox must say no scan has run")
	}
}

func demoPage(t *testing.T, query string) string {
	t.Helper()
	return requestWith(t, Options{Rows: DemoRows(), Demo: true}, "/"+query, "localhost:8737", "").Body.String()
}

func loaded(t *testing.T, v View, query string) string {
	t.Helper()
	opt := Options{Load: func() (View, error) { return v, nil }}
	return requestWith(t, opt, "/"+query, "localhost:8737", "").Body.String()
}

func TestAScanWithNoFindingsDoesntReadAsSafe(t *testing.T) {
	body := loaded(t, View{Scanned: true, ScannedAt: time.Now()}, "")
	if !strings.Contains(body, "Nothing found in what was scanned") || !strings.Contains(body, "the same as safe") {
		t.Fatal(body)
	}
}

func TestADegradedScanSaysSo(t *testing.T) {
	body := loaded(t, View{Scanned: true, ScannedAt: time.Now(), Degraded: []string{"Chrome Releases (failed): HTTP 500"}}, "")
	if !strings.Contains(body, "may be incomplete") || !strings.Contains(body, "Chrome Releases (failed)") {
		t.Fatal(body)
	}
}

func TestALongCardScrollsItsMostUrgentAndLinksToTheRest(t *testing.T) {
	var rows []Row
	for i := range rowsPerCard + 40 {
		rows = append(rows, Row{App: "Big App", CVE: "CVE-" + strconv.Itoa(i), Severity: "High", Label: "Inferred"})
	}
	v := View{Scanned: true, ScannedAt: time.Now(), Rows: rows}
	body := loaded(t, v, "")
	want := rowsPerCard + 40
	if count(body, "row") != rowsPerCard || !strings.Contains(body, "All "+strconv.Itoa(want)+" findings") || !strings.Contains(body, `href="/?app=Big&#43;App"`) {
		t.Fatalf("%d rows", count(body, "row"))
	}
	if !strings.Contains(body, `<div class="list">`) {
		t.Fatal("a card's rows belong in its scrolling list")
	}
	all := loaded(t, v, "?app=Big+App")
	if count(all, "row") != want || !strings.Contains(all, "<h2>Big App</h2>") {
		t.Fatalf("the app's page must hold every row: %d", count(all, "row"))
	}
}

func TestCardSaysHowSureItsExploitedCountIs(t *testing.T) {
	body := loaded(t, View{Scanned: true, ScannedAt: time.Now(), Rows: []Row{
		{App: "A", CVE: "CVE-1", KEV: true, Severity: "High", Label: "Inferred"},
		{App: "A", CVE: "CVE-2", KEV: true, Severity: "High", Label: "Inferred"},
		{App: "A", CVE: "CVE-3", KEV: true, Severity: "High", Label: "Confirmed"},
	}}, "")
	if !strings.Contains(body, "<b>3</b><span>exploited</span>") || !strings.Contains(body, ">1 confirmed<") {
		t.Fatal(body)
	}
}

func TestTopEPSSIgnoresFindingsWithNoScore(t *testing.T) {
	got := cards([]Row{{App: "A", EPSS: "<1%"}, {App: "A"}}, nil)
	if got[0].TopEPSS != "<1%" {
		t.Fatalf("%q", got[0].TopEPSS)
	}
}

func TestBehindSinceDescribesTheAppWhateverTheFilter(t *testing.T) {
	v := View{Scanned: true, ScannedAt: time.Now(), Rows: []Row{
		{App: "A", CVE: "CVE-1", Severity: "Critical", Label: "Inferred", Sort: "2026-03-01"},
		{App: "A", CVE: "CVE-2", Severity: "Low", Label: "Inferred", Sort: "2024-07-01"},
		{App: "A", CVE: "CVE-3", Severity: "High", Label: "Inferred", Sort: "2020-01-01", Absent: true},
	}, Apps: map[string]AppFacts{"A": {Kind: kindBrowser}}}
	for _, q := range []string{"", "?min=critical", "?min=all"} {
		if body := loaded(t, v, q); !strings.Contains(body, "<dt>Behind since</dt><dd>Jul 2024") {
			t.Fatalf("%s: a Low still counts, one that probably doesn't apply doesn't:\n%s", q, body)
		}
	}
}

func TestCardLinesSayWhatIsKnown(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name  string
		facts AppFacts
		has   []string
		lacks []string
	}{
		{
			"never recorded",
			AppFacts{Kind: kindElectron, Stack: "37.1.0", Runtime: "138.0.0.1", Updated: "2020-01-15"},
			[]string{"Not running", "last opened unknown", "Jan 2020", "Electron 37.1.0", "Chromium 138"},
			nil,
		},
		{"opened today", AppFacts{Kind: kindElectron, LastOpened: now.Format(time.DateOnly)}, []string{"last opened today"}, nil},
		{"opened long ago", AppFacts{Kind: kindElectron, LastOpened: "2020-06-19"}, []string{"last opened Jun 2020"}, nil},
		{"running", AppFacts{Kind: kindElectron, Running: true, Updated: "2020-01-15"}, []string{"Running", "Jan 2020"}, []string{"last opened", "Not running"}},
		{"agent browser", AppFacts{Kind: kindBrowser, Runtime: "156.0.0.1"}, []string{"Not running", "Chromium 156"}, []string{"last opened", "Electron"}},
		{"a formula that isn't listening", AppFacts{Kind: kindHomebrew, Version: "2.5.4"}, []string{"v2.5.4", "Homebrew formula"}, []string{"running", "last opened"}},
		{"a formula that is", AppFacts{Kind: kindHomebrew, Running: true}, []string{"Running"}, nil},
		{"out of support", AppFacts{Kind: kindElectron, Unsupported: true, Note: "no more fixes"}, []string{"out of support", `title="no more fixes"`}, nil},
		{"supported", AppFacts{Kind: kindElectron}, nil, []string{"out of support"}},
		{"an update", AppFacts{Kind: kindElectron, Version: "1.0", Latest: "2.0", Update: resolve.UpdateAvailable}, []string{"v2.0 available"}, []string{"ewest version unknown", ">latest<"}},
		{"up to date", AppFacts{Kind: kindElectron, Version: "2.0", Latest: "2.0", Update: resolve.UpdateCurrent}, []string{">latest<"}, []string{"available", "ewest version unknown"}},
		{"unknown never reads as current", AppFacts{Kind: kindElectron, Version: "2.0"}, []string{"ewest version unknown"}, []string{">latest<", " available"}},
	} {
		body := loaded(t, View{Scanned: true, ScannedAt: now, Rows: []Row{{App: "A.app", CVE: "CVE-1", Severity: "High", Label: "Inferred"}}, Apps: map[string]AppFacts{"A.app": c.facts}}, "")
		for _, s := range c.has {
			if !strings.Contains(body, s) {
				t.Errorf("%s: missing %q", c.name, s)
			}
		}
		for _, s := range c.lacks {
			if strings.Contains(body, s) {
				t.Errorf("%s: shouldn't say %q", c.name, s)
			}
		}
	}
}

func TestAProbablyAbsentFindingIsHiddenUnlessAskedFor(t *testing.T) {
	v := View{Scanned: true, ScannedAt: time.Now(), Rows: []Row{{App: "A", CVE: "CVE-1", Severity: "Critical", Label: "Inferred", Absent: true}}}
	if body := loaded(t, v, ""); count(body, "row") != 0 || !strings.Contains(body, "1 lower-severity hidden") {
		t.Fatal(body)
	}
	if count(loaded(t, v, "?min=all"), "row") != 1 {
		t.Fatal("All must show it")
	}
}

func count(body, class string) int { return strings.Count(body, `<details class="`+class+`">`) }

func TestEveryPageButHealthNeedsTheToken(t *testing.T) {
	h := Handler("8737", testInfo, Options{Token: testToken})
	send := func(path string, cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		req.Host = "127.0.0.1:8737"
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie}) // #nosec G124 -- a request in a test
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if got := send("/healthz", "").Code; got != 200 {
		t.Fatalf("healthz: %d", got)
	}
	for _, p := range []string{"/", "/?view=exploited", "/style.css", "/?token=wrong"} {
		if got := send(p, "").Code; got != 401 {
			t.Errorf("%s without a token: %d", p, got)
		}
	}
	if got := send("/", "wrong").Code; got != 401 {
		t.Errorf("a wrong cookie: %d", got)
	}
	in := send("/?token="+testToken+"&view=exploited", "")
	if in.Code != 303 || in.Header().Get("Location") != "/?view=exploited" {
		t.Fatalf("a valid token should redirect it out of the URL: %d %s", in.Code, in.Header().Get("Location"))
	}
	for _, path := range []string{"//evil.example/", `/\evil.example/`, "///evil.example"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.URL.Path, req.URL.RawQuery, req.Host = path, "token="+testToken, "127.0.0.1:8737"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if loc := rec.Header().Get("Location"); strings.HasPrefix(loc, "//") || strings.HasPrefix(loc, `/\`) {
			t.Fatalf("%q redirected off-site to %q", path, loc)
		}
	}
	c := in.Result().Cookies()
	if len(c) != 1 || !c[0].HttpOnly || c[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("%+v", c)
	}
	if got := send("/", c[0].Value).Code; got != 200 {
		t.Fatalf("with the cookie: %d", got)
	}
}

func TestServeRefusesToRunWithoutAToken(t *testing.T) {
	err := Serve(context.Background(), "127.0.0.1:0", testInfo, Options{}, func(string) { t.Error("became ready") })
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatal(err)
	}
}

func TestDemoGroupsByAppBehindABanner(t *testing.T) {
	all := demoPage(t, "?min=all")
	if !strings.Contains(all, "Sample data") || strings.Count(all, `<section class="card">`) != 4 || count(all, "row") != 8 {
		t.Fatalf("want the banner, 4 cards, 8 rows: %d %d", strings.Count(all, `<section class="card">`), count(all, "row"))
	}
	mail, chat := strings.Index(all, "Example Mail"), strings.Index(all, "Example Chat")
	tool := strings.Index(all, "exampletool")
	if mail < 0 || mail > chat || chat > tool {
		t.Fatal("cards should sort exploited first, then by exposure")
	}
	if !strings.Contains(all, "<b>1</b><span>exploited</span>") {
		t.Fatal("the card should carry its exploited count")
	}
}

func TestOnlyTheSampleServerHasTheLargeSample(t *testing.T) {
	if !strings.Contains(demoPage(t, "?sample=many"), "All 150 findings") {
		t.Fatal("the sample server should show it")
	}
	if strings.Contains(request(t, "/?sample=many", "localhost:8737", "").Body.String(), "CVE-0000") {
		t.Fatal("a real server must never show sample data, whatever it's asked")
	}
}

func TestSeverityFilter(t *testing.T) {
	def := demoPage(t, "")
	if count(def, "row") != 5 || !strings.Contains(def, "3 lower-severity hidden") {
		t.Fatalf("default: want 5 rows and 3 hidden, got %d", count(def, "row"))
	}
	if !strings.Contains(def, "CVE-0000-0001") {
		t.Fatal("a known-exploited Medium must survive the default filter")
	}
	if strings.Count(def, `<section class="card">`) != 3 || strings.Index(def, "exampletool") < strings.Index(def, "Also on this machine") {
		t.Fatal("a card with nothing left should move to the list of everything else")
	}
	crit := demoPage(t, "?min=critical")
	if count(crit, "row") != 3 || !strings.Contains(crit, "CVE-0000-0001") {
		t.Fatalf("critical: want the 2 criticals + the exploited Medium, got %d", count(crit, "row"))
	}
	all := demoPage(t, "?min=all")
	if strings.Contains(all, "lower-severity hidden") {
		t.Fatal("nothing is hidden at All")
	}
	if got := demoPage(t, "?min=nonsense"); count(got, "row") != count(def, "row") {
		t.Fatal("an unknown filter should fall back to the default")
	}
}

func TestViewsAndFilterCombine(t *testing.T) {
	kev := demoPage(t, "?view=exploited")
	if count(kev, "row") != 1 || !strings.Contains(kev, "CVE-0000-0001") {
		t.Fatal("exploited view should show only the KEV row")
	}
	if strings.Contains(kev, "lower-severity hidden") {
		t.Fatal("the exploited view hides nothing")
	}
	conf := demoPage(t, "?view=confirmed&min=all")
	if count(conf, "row") != 3 {
		t.Fatalf("confirmed: want 3 rows, got %d", count(conf, "row"))
	}
	if !strings.Contains(conf, `href="/?min=all&amp;view=exploited"`) {
		t.Fatal("switching views should keep the severity setting")
	}
	if !strings.Contains(demoPage(t, "?view=nope"), "<h2>Inbox</h2>") {
		t.Fatal("an unknown view should fall back to the inbox")
	}
}

func TestSeverityRankTreatsUnknownAsMedium(t *testing.T) {
	for s, want := range map[string]int{"CRITICAL": 4, "High": 3, "Moderate": 2, "medium": 2, "UNKNOWN": 2, "": 2, "Low": 1} {
		if got := severityRank(s); got != want {
			t.Errorf("%q: got %d, want %d", s, got, want)
		}
	}
}

// Advisory and changelog text is untrusted: it must arrive on the page as text.
func TestHostileAdvisoryTextIsEscaped(t *testing.T) {
	const attack = `<script>alert(1)</script><img src=x onerror=alert(2)>`
	row := Row{Severity: attack, App: attack, CVE: attack, Title: attack, Label: attack, EPSS: attack, FixedIn: attack, Date: attack, Description: attack, Evidence: attack}
	apps := map[string]AppFacts{attack: {Kind: kindElectron, Stack: attack, Runtime: attack, Version: attack, LastOpened: attack, Updated: attack, Why: attack, Note: attack, Unsupported: true, Latest: attack, Update: resolve.UpdateAvailable}}
	opt := Options{Rows: []Row{row}, Apps: apps}
	for _, query := range []string{"?min=all", "?min=all&app=" + url.QueryEscape(attack)} {
		body := requestWith(t, opt, "/"+query, "localhost:8737", "").Body.String()
		if strings.Contains(body, "<script") || strings.Contains(body, "<img") {
			t.Fatalf("untrusted text reached the page as markup:\n%s", body)
		}
		if !strings.Contains(body, `class="sev-other"`) {
			t.Fatal("an unknown severity must map to the closed class set")
		}
	}
}

func FuzzHostAllowed(f *testing.F) {
	for _, s := range []string{"127.0.0.1:8737", "localhost:8737", "[::1]:8737", "evil.example:8737", "127.0.0.1.evil.example:8737", "", ":", "[", "0x7f.1:8737"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		if hostAllowed(host, "8737") {
			h, _, ok := strings.Cut(host, ":8737")
			if !ok {
				t.Fatalf("allowed %q without the port", host)
			}
			if h != "localhost" && h != "debuff" && !strings.HasPrefix(h, "127.") && !strings.HasPrefix(h, "[") && !strings.Contains(h, ":") {
				t.Fatalf("allowed a non-loopback host %q", host)
			}
		}
	})
}

func TestIconIsServedAsSVG(t *testing.T) {
	rec := request(t, "/icon.svg", "127.0.0.1:8737", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/svg+xml" || !strings.HasPrefix(rec.Body.String(), "<svg") {
		t.Fatalf("icon: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	// An SVG can carry script; the policy on every response is what keeps one inert.
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("the icon went out without the content policy")
	}
}
