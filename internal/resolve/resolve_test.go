package resolve

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/thwomp-io/debuff/internal/fetch"
)

func TestParsePost(t *testing.T) {
	c := `The Stable channel has been updated to 156.0.8078.79/.80 for Mac. &lt;span&gt;[$1,000][ 542403045 ]&lt;/span&gt; High CVE-2026-85046: Type confusion in V8. Reported by x. [N/A][502304489] Critical CVE-2026-1: Use after free in Skia. Reported`
	v, cves := ParsePost(c)
	if v != "156.0.8078.79" || len(cves) != 2 || cves[0].Bug != "542403045" || cves[1].Severity != "Critical" || cves[1].Component != "Use after free in Skia" {
		t.Fatalf("%s %+v", v, cves)
	}
}

func TestFixedIn(t *testing.T) {
	c := ChromeCVE{Fixes: []string{"156.0.8078.73"}}
	for v, want := range map[string]bool{"156.0.8078.4": false, "156.0.8078.73": true, "157.0.1.1": true, "152.0.7977.167": false} {
		if got := c.FixedIn(v); got != want {
			t.Errorf("%s: got %v", v, got)
		}
	}
	// a fix on the runtime's own older branch decides it, however the newer branch looks
	e := ChromeCVE{Fixes: []string{"156.0.8078.73", "154.0.8037.97"}}
	if !e.FixedIn("154.0.8037.100") || e.FixedIn("154.0.8037.1") {
		t.Error("branch fix")
	}
	if e.FirstFix() != "154.0.8037.97" {
		t.Error(e.FirstFix())
	}
}

const page = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><id>post-1</id><title>Stable Channel Update for Desktop</title><published>2026-10-29T14:26:00</published>
<content>updated to 156.0.8078.79 for Mac [1234567] Critical CVE-2026-76024: Memory corruption in MediaStream. Reported</content>
<link rel="alternate" href="https://example.test/post-1"/></entry>
<entry><id>post-2</id><title>Chrome Beta for Desktop Update</title><published>2026-10-28T00:00:00</published>
<content>updated to 157.0.8103.1 [7654321] High CVE-2026-99999: Beta only. Reported</content></entry>
<entry><id>post-3</id><title>Extended Stable Update for Desktop</title><published>2026-10-27T00:00:00</published>
<content>updated to 154.0.8037.120 [1234567] Critical CVE-2026-76024: Memory corruption in MediaStream. Reported</content></entry>
</feed>`

func TestMergeKeepsStableFixesAndSkipsBeta(t *testing.T) {
	db := newChromeDB()
	oldest, known, n, err := db.Merge([]byte(page))
	if err != nil || oldest != "2026-10-27" || known || n != 3 {
		t.Fatal(oldest, known, n, err)
	}
	c := db.CVEs["CVE-2026-76024"]
	if c == nil || len(c.Fixes) != 2 || c.First != "2026-10-27" || db.CVEs["CVE-2026-99999"] != nil {
		t.Fatalf("%+v", db.CVEs)
	}
	if db.ByBug()["1234567"] != "CVE-2026-76024" {
		t.Fatal("bug map")
	}
	if _, known, _, _ := db.Merge([]byte(page)); !known {
		t.Fatal("a repeat page should report known posts")
	}
	if len(db.CVEs["CVE-2026-76024"].Fixes) != 2 {
		t.Fatal("merging twice must not duplicate fixes")
	}
}

func TestBackports(t *testing.T) {
	cves, bugs := Backports([]byte(`* Security: backported fix for CVE-2024-0518.
  * Security: backported fix for 1506535.
* Security: backported fix for chromium:1517354. &amp; other`))
	if len(cves) != 1 || cves[0] != "CVE-2024-0518" || len(bugs) != 2 || bugs[1] != "1517354" {
		t.Fatalf("%v %v", cves, bugs)
	}
}

func TestElectronLineAndSupport(t *testing.T) {
	e := Electron{Releases: []ElectronRelease{
		{Version: "45.2.1", Date: "2026-10-30"},
		{Version: "44.10.1", Date: "2026-10-30"},
		{Version: "44.9.1", Date: "2026-10-20"},
		{Version: "44.0.0", Date: "2026-06-01"},
		{Version: "44.0.0-beta.1", Date: "2026-05-01"},
		{Version: "43.0.0", Date: "2026-04-01"},
		{Version: "42.0.0", Date: "2026-02-01"},
		{Version: "47.0.0-nightly.1", Date: "2026-11-02"},
	}}
	if got := e.Line("44.9.1"); len(got) != 2 {
		t.Fatalf("%v", got)
	}
	if e.LineStart("44.9.1") != "2026-06-01" {
		t.Fatal(e.LineStart("44.9.1"))
	}
	if !e.Supported("43.0.0") || e.Supported("42.0.0") {
		t.Fatal("the newest three stable majors, ignoring nightlies")
	}
}

func TestBugIDs(t *testing.T) {
	got := BugIDs("[M152] Fix it\n\nBug: 543557673, chromium:1234567\nFixed: 7654321\nChange-Id: I12345678\nReviewed-on: https://x/1234567890\n")
	if len(got) != 3 || got[0] != "543557673" {
		t.Fatalf("%v", got)
	}
}

func TestEngineRepos(t *testing.T) {
	r := EngineRepos("152.0.7977.167", "15.2.124.43")
	if r["v8"] != "https://chromium.googlesource.com/v8/v8/+log/refs/branch-heads/15.2" || !strings.HasSuffix(r["angle"], "chromium/7977") || !strings.HasSuffix(r["skia"], "chrome/m152") {
		t.Fatalf("%v", r)
	}
	if _, err := logTime("Thu Sep 03 18:14:49 2026 +0000"); err != nil {
		t.Fatal(err)
	}
}

func TestBrowserOnly(t *testing.T) {
	for comp, want := range map[string]bool{
		"Use after free in Extensions": true, "Inappropriate implementation in Omnibox": true,
		"Type confusion in V8": false, "Use after free in Skia": false, "Out of bounds read in ANGLE": false,
	} {
		if BrowserOnly(comp) != want {
			t.Errorf("%s", comp)
		}
	}
}

// A fake git server: chromium/src's branch log, and one engine's log holding the fix.
func gitFake(routes map[string]string) func(*http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		for needle, body := range routes {
			if strings.Contains(r.URL.String(), needle) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(")]}'\n" + body))}, nil
			}
		}
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
}

// The spike's lesson, pinned: a fix on the engine's own branch, invisible to chromium/src, counts.
func TestMergedSeesAFixOnAnEngineBranch(t *testing.T) {
	commit := func(msg, when string) string {
		return fmt.Sprintf(`{"message":%q,"committer":{"time":%q}}`, msg, when)
	}
	do := gitFake(map[string]string{ //nolint:bodyclose // the fake's bodies need no closing
		"chromium/src/+log": `{"log":[` + commit("Roll v8\n\nBug: 1111111", "Tue Sep 01 00:00:00 2026") + `,` + commit("cut", "Mon Aug 03 00:00:00 2026") + `]}`,
		"v8/v8/+log": `{"log":[` + commit("too late\n\nBug: 3333333", "Fri Oct 30 00:00:00 2026") + `,` +
			commit("[M152] the fix\n\nBug: 2222222", "Thu Sep 03 18:14:49 2026") + `,` +
			commit("before the cut\n\nBug: 4444444", "Sat Aug 01 00:00:00 2026") + `]}`,
	})
	c := &fetch.Client{Dir: t.TempDir(), UserAgent: "t", Do: do}
	got, err := Merged(context.Background(), c, "152.0.7977.167", "15.2.124.43", "2026-10-20")
	if err != nil {
		t.Fatal(err)
	}
	if !got["1111111"] || !got["2222222"] {
		t.Fatalf("missing: %v", got)
	}
	if got["3333333"] || got["4444444"] {
		t.Fatalf("outside the window: %v", got)
	}
	// complete, so it's cached: a second call needs no network
	c.Do = func(*http.Request) (*http.Response, error) { t.Fatal("should be cached"); return nil, nil }
	if again, err := Merged(context.Background(), c, "152.0.7977.167", "15.2.124.43", "2026-10-20"); err != nil || !again["2222222"] {
		t.Fatal(again, err)
	}
}

func TestAPartialBranchAnswerIsReportedAndNotCached(t *testing.T) {
	calls := 0
	c := &fetch.Client{Dir: t.TempDir(), UserAgent: "t", Do: func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 502, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	if _, err := Merged(context.Background(), c, "152.0.7977.167", "", ""); err == nil {
		t.Fatal("want an error")
	}
	if _, _, err := c.Read("branches/152.0.7977.167___.json"); err == nil {
		t.Fatal("a partial answer must not be cached")
	}
}

func TestABranchLogResumesAfterAFailedPage(t *testing.T) {
	var asked []string
	fail := true
	page2 := `{"log":[{"message":"Bug: 2222222","committer":{"time":"Mon Aug 03 00:00:00 2026"}}]}`
	do := func(r *http.Request) (*http.Response, error) {
		u := r.URL.String()
		asked = append(asked, u)
		body, code := `{"log":[{"message":"Bug: 1111111","committer":{"time":"Tue Sep 01 00:00:00 2026"}}],"next":"abc"}`, 200
		if strings.Contains(u, "&s=abc") {
			body = page2
			if fail {
				body, code = "", 502
			}
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(")]}'\n" + body))}, nil
	}
	c := &fetch.Client{Dir: t.TempDir(), UserAgent: "t", Do: do}
	if _, err := Merged(context.Background(), c, "152.0.7977.1", "", ""); err == nil {
		t.Fatal("want the failure reported")
	}
	first := len(asked)
	fail = false
	got, err := Merged(context.Background(), c, "152.0.7977.1", "", "")
	if err != nil || !got["1111111"] || !got["2222222"] {
		t.Fatal(got, err)
	}
	if len(asked) != first+1 {
		t.Fatalf("the retry should fetch only the page that failed: %d then %d", first, len(asked))
	}
}

func FuzzParsePost(f *testing.F) {
	f.Add("updated to 156.0.8078.79 [1234567] Critical CVE-2026-1: x in y. Reported")
	f.Add("&lt;&amp;lt;[ ] High CVE-")
	f.Fuzz(func(t *testing.T, s string) {
		_, cves := ParsePost(s)
		for _, c := range cves {
			if !strings.HasPrefix(c.ID, "CVE-") {
				t.Fatalf("%+v", c)
			}
		}
	})
}

func FuzzMerge(f *testing.F) {
	f.Add([]byte(page))
	f.Add([]byte("<feed><entry>"))
	f.Fuzz(func(_ *testing.T, b []byte) { _, _, _, _ = newChromeDB().Merge(b) })
}

func FuzzCompareVersions(f *testing.F) {
	f.Add("1.2.3", "1.2.4")
	f.Fuzz(func(t *testing.T, a, b string) {
		if CompareVersions(a, b) != -CompareVersions(b, a) {
			t.Fatalf("%q %q", a, b)
		}
	})
}

func TestCatalogNamesTheLatestAndOnlyWhenItCan(t *testing.T) {
	cat, err := ParseCatalog([]byte(`[
		{"token":"mail","version":"1.15.1","artifacts":[{"app":["Mail.app"]},{"zap":{"trash":"x"}}]},
		{"token":"build","version":"2.2.5,21124","artifacts":[{"app":["Build.app"]}]},
		{"token":"moving","version":"latest","artifacts":[{"app":["Moving.app"]}]},
		{"token":"beta","version":"8.12.44-25.BETA","artifacts":[{"app":["Beta.app"]}]},
		{"token":"pair","version":"1.0","artifacts":[{"app":["Pair.app"]}]},
		{"token":"pair2","version":"2.0","artifacts":[{"app":["Pair.app"]}]},
		{"token":"solo","version":"3.0","artifacts":[{"app":["Solo.app"]}]},
		{"token":"solo@beta","version":"4.0","artifacts":[{"app":["Solo.app"]}]},
		{"token":"renamed","version":"5.0","artifacts":[{"app":["Source.app",{"target":"Target.app"}]}]},
		{"token":"nothing","version":"1.0","artifacts":[{"pkg":["x.pkg"]}]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		app, installed, latest, state string
	}{
		{"Mail.app", "1.12.1", "1.15.1", UpdateAvailable},
		{"Mail.app", "1.15.1", "1.15.1", UpdateCurrent},
		{"Mail.app", "1.16.0", "1.15.1", UpdateCurrent},  // the catalog can lag a vendor
		{"Mail.app", "1.9.0", "1.15.1", UpdateAvailable}, // numbers, not text
		{"Build.app", "2.2.3", "2.2.5", UpdateAvailable},
		{"Moving.app", "1.0", "", ""},
		{"Beta.app", "1.0", "", ""},
		{"Pair.app", "1.0", "", ""},               // two stable casks: ambiguous
		{"Solo.app", "3.0", "3.0", UpdateCurrent}, // a beta variant doesn't count
		{"Target.app", "4.0", "5.0", UpdateAvailable},
		{"Source.app", "4.0", "", ""},
		{"Unlisted.app", "1.0", "", ""},
		{"Mail.app", "", "", ""},
		{"Mail.app", "1.2b", "", ""},
	} {
		latest, state := cat.Update(c.app, c.installed)
		if latest != c.latest || state != c.state {
			t.Errorf("%s %q: got %q %q, want %q %q", c.app, c.installed, latest, state, c.latest, c.state)
		}
	}
}

func TestAnEmptyCatalogKnowsNothing(t *testing.T) {
	if latest, state := (Catalog{}).Update("Mail.app", "1.0"); latest != "" || state != "" {
		t.Fatal(latest, state)
	}
}

func FuzzParseCatalog(f *testing.F) {
	f.Add([]byte(`[{"token":"a","version":"1.0","artifacts":[{"app":["A.app",{"target":"B.app"}]}]}]`))
	f.Add([]byte(`[{"artifacts":[{"app":[{"target":"B.app"}]},"x",7]}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		cat, err := ParseCatalog(b)
		if err != nil {
			return
		}
		for app, v := range cat.latest {
			if !plainVersion.MatchString(v) {
				t.Fatalf("%q kept a version that can't be compared: %q", app, v)
			}
		}
	})
}

const nvdSample = `{"totalResults":3,"resultsPerPage":2000,"vulnerabilities":[
 {"cve":{"id":"CVE-2026-1","published":"2026-10-06T12:00:00.000","vulnStatus":"Analyzed",
  "descriptions":[{"lang":"es","value":"no"},{"lang":"en","value":"Memory corruption in a parser. More detail follows."}],
  "metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"CRITICAL"}}]},
  "configurations":[{"nodes":[{"cpeMatch":[
    {"vulnerable":true,"criteria":"cpe:2.3:a:mozilla:firefox:*:*","versionEndExcluding":"160.0"},
    {"vulnerable":true,"criteria":"cpe:2.3:a:mozilla:firefox:*:*","versionEndExcluding":"159.5"},
    {"vulnerable":true,"criteria":"cpe:2.3:a:mozilla:firefox:*:*","versionEndExcluding":"100.0"},
    {"vulnerable":true,"criteria":"cpe:2.3:a:other:firefox:*:*","versionEndExcluding":"159.1"},
    {"vulnerable":false,"criteria":"cpe:2.3:a:mozilla:firefox:*:*","versionEndExcluding":"159.2"}]}]}]}},
 {"cve":{"id":"CVE-2026-2","vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"Rejected reason"}]}},
 {"cve":{"id":"CVE-2026-3","metrics":{"cvssMetricV2":[{"baseSeverity":"HIGH"}]},"descriptions":[]}}
]}`

func TestParseNVD(t *testing.T) {
	got, total, err := ParseNVD([]byte(nvdSample), "mozilla:firefox", "159.0")
	if err != nil || total != 3 || len(got) != 2 {
		t.Fatalf("%d of %d, %v", len(got), total, err)
	}
	a := got[0]
	if a.CVE != "CVE-2026-1" || a.Severity != "CRITICAL" || a.Published != "2026-10-06" || a.Title != "Memory corruption in a parser" || a.FixedIn != "159.5" {
		t.Fatalf("%+v", a)
	}
	if got[1].Severity != "HIGH" {
		t.Fatalf("%+v", got[1])
	}
	if !a.Ranged || got[1].Ranged {
		t.Fatalf("a range counts, and no configuration doesn't: %v %v", a.Ranged, got[1].Ranged)
	}
	for criteria, want := range map[string]bool{
		"cpe:2.3:a:a:b:1.2.3:*:*": true, "cpe:2.3:a:a:b:*:*:*": false, "cpe:2.3:a:a:b:-:*:*": false, "short": false,
	} {
		if exactVersion(criteria) != want {
			t.Errorf("%s", criteria)
		}
	}
}

func TestNVDWontAskAboutAVersionItCantTrust(t *testing.T) {
	c := &fetch.Client{Dir: t.TempDir(), UserAgent: "t", Do: func(*http.Request) (*http.Response, error) {
		t.Fatal("no request should be made")
		return nil, nil
	}}
	for _, v := range []string{"", "1.2b", "1:*:evil", "../x"} {
		if _, _, err := NVDAffected(context.Background(), c, "a:b", v); err == nil {
			t.Errorf("%q should be refused", v)
		}
	}
	if _, _, err := NVDAffected(context.Background(), c, "a:b:c", "1.0"); err == nil {
		t.Error("a malformed CPE should be refused")
	}
}

func FuzzParseNVD(f *testing.F) {
	f.Add([]byte(nvdSample))
	f.Add([]byte(`{"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV31":[]},"configurations":[{"nodes":[{}]}]}}]}`))
	f.Fuzz(func(_ *testing.T, b []byte) { _, _, _ = ParseNVD(b, "a:b", "1.0") })
}

func TestFromCaskCoversPackageInstallsAndBuildNumbers(t *testing.T) {
	cat, err := ParseCatalog([]byte(`[
		{"token":"office","version":"16.114.26102720","artifacts":[{"pkg":["x.pkg"]}]},
		{"token":"plain","version":"1.104.5","artifacts":[{"pkg":["y.pkg"]}]},
		{"token":"odd","version":"1.9.3b","artifacts":[]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		cask, installed string
		parts           int
		latest, state   string
	}{
		{"office", "16.109.2", 2, "16.114", UpdateAvailable},
		{"office", "16.114.1", 2, "16.114", UpdateCurrent}, // a build number mustn't read as an update
		{"plain", "1.104.4", 0, "1.104.5", UpdateAvailable},
		{"odd", "1.9.1", 0, "", ""},
		{"missing", "1.0", 0, "", ""},
	} {
		latest, state := cat.UpdateFromCask(c.cask, c.installed, c.parts)
		if latest != c.latest || state != c.state {
			t.Errorf("%+v: got %q %q", c, latest, state)
		}
	}
}
