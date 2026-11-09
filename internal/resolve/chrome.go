// Package resolve turns a bundled Chromium version into honest findings. Version arithmetic alone is
// wrong: fixes reach a release branch without moving past the fix version that Chrome's posts name. So
// the order is version → Electron's notes → the branch's git history → the engines' own repos, and what
// survives is labeled Inferred: an upper bound, because nothing here knows if the bug existed that far back.
package resolve

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/thwomp-io/debuff/internal/fetch"
)

// CompareVersions orders dotted numeric versions.
func CompareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func major(v string) int {
	m, _ := strconv.Atoi(strings.SplitN(v, ".", 2)[0])
	return m
}

// ChromeCVE is one CVE as Chrome Releases states it. The text is untrusted.
type ChromeCVE struct {
	ID        string   `json:"id"`
	Severity  string   `json:"severity"`
	Component string   `json:"component"`
	Bug       string   `json:"bug,omitempty"`
	First     string   `json:"first"`
	URL       string   `json:"url,omitempty"`
	Fixes     []string `json:"fixes"`
}

// FixedIn says whether runtime version v is at or past this CVE's fix. A fix on v's own branch decides
// it. With none, v counts as fixed only on a newer major than every fix.
func (c ChromeCVE) FixedIn(v string) bool {
	vm, onBranch, lowest := major(v), false, 1<<30
	for _, f := range c.Fixes {
		if major(f) == vm {
			onBranch = true
			if CompareVersions(v, f) >= 0 {
				return true
			}
		}
		lowest = min(lowest, major(f))
	}
	if onBranch {
		return false
	}
	return vm > lowest
}

// FirstFix is the earliest version the fix shipped in.
func (c ChromeCVE) FirstFix() string {
	if len(c.Fixes) == 0 {
		return ""
	}
	best := c.Fixes[0]
	for _, f := range c.Fixes[1:] {
		if CompareVersions(f, best) < 0 {
			best = f
		}
	}
	return best
}

var (
	tagRe   = regexp.MustCompile(`<[^>]+>`)
	spaceRe = regexp.MustCompile(`\s+`)
	verRe   = regexp.MustCompile(`\b\d{2,3}\.0\.\d{4}\.\d+\b`)
	cveRe   = regexp.MustCompile(`(?:\[\s*(\d{6,})\s*\]\s*)?(Critical|High|Medium|Low)\s+(CVE-\d{4}-\d+)\s*:\s*([^.]{0,90})`)
	titleRe = regexp.MustCompile(`^(Stable Channel Update for Desktop|Extended Stable (Channel )?Update for Desktop|Early Stable Update for Desktop)`)
)

// ParsePost reads a release post: its fix version and CVEs. The text only ever becomes data.
func ParsePost(content string) (string, []ChromeCVE) {
	text := html.UnescapeString(html.UnescapeString(content))
	text = spaceRe.ReplaceAllString(tagRe.ReplaceAllString(text, " "), " ")
	ver := verRe.FindString(text)
	var out []ChromeCVE
	for _, m := range cveRe.FindAllStringSubmatch(text, -1) {
		out = append(out, ChromeCVE{ID: m[3], Severity: m[2], Bug: m[1], Component: strings.TrimSpace(m[4])})
	}
	return ver, out
}

type feed struct {
	Entries []struct {
		ID        string `xml:"id"`
		Title     string `xml:"title"`
		Published string `xml:"published"`
		Content   string `xml:"content"`
		Links     []struct {
			Rel  string `xml:"rel,attr"`
			Href string `xml:"href,attr"`
		} `xml:"link"`
	} `xml:"entry"`
}

// ChromeDB is every Chrome CVE seen, kept between scans. New posts are merged in.
type ChromeDB struct {
	Format int                   `json:"format"`
	Posts  map[string]bool       `json:"posts"`
	Oldest string                `json:"oldest"`
	CVEs   map[string]*ChromeCVE `json:"cves"`
}

const chromeDBFormat = 1

func newChromeDB() *ChromeDB {
	return &ChromeDB{Format: chromeDBFormat, Posts: map[string]bool{}, CVEs: map[string]*ChromeCVE{}}
}

// Merge adds a feed page, and reports the oldest date it held and whether any post was already known.
func (db *ChromeDB) Merge(page []byte) (oldest string, known bool, n int, err error) {
	var fd feed
	if err := xml.Unmarshal(page, &fd); err != nil {
		return "", false, 0, err
	}
	for _, e := range fd.Entries {
		n++
		date := e.Published
		if len(date) >= 10 {
			date = date[:10]
		}
		if oldest == "" || date < oldest {
			oldest = date
		}
		if db.Posts[e.ID] {
			known = true
			continue
		}
		db.Posts[e.ID] = true
		if db.Oldest == "" || date < db.Oldest {
			db.Oldest = date
		}
		if !titleRe.MatchString(strings.TrimSpace(e.Title)) {
			continue
		}
		ver, cves := ParsePost(e.Content)
		if ver == "" {
			continue
		}
		link := ""
		for _, l := range e.Links {
			if l.Rel == "alternate" {
				link = l.Href
			}
		}
		for _, c := range cves {
			cur := db.CVEs[c.ID]
			if cur == nil {
				cc := c
				cc.First, cc.URL = date, link
				db.CVEs[c.ID] = &cc
				cur = &cc
			}
			if date < cur.First {
				cur.First, cur.URL = date, link
			}
			if cur.Bug == "" {
				cur.Bug = c.Bug
			}
			if !slices.Contains(cur.Fixes, ver) {
				cur.Fixes = append(cur.Fixes, ver)
			}
		}
	}
	return oldest, known, n, nil
}

const chromeDBFile = "chrome/db.json"

// ByBug maps Chromium bug ids to CVEs.
func (db *ChromeDB) ByBug() map[string]string {
	out := map[string]string{}
	for id, c := range db.CVEs {
		if c.Bug != "" {
			out[c.Bug] = id
		}
	}
	return out
}

// SyncChrome brings the database up to date, back to the cutoff date, newest pages first. On a failure
// it keeps what it has, and returns the error for the caller to report.
func SyncChrome(ctx context.Context, c *fetch.Client, cutoff string, progress func(string)) (*ChromeDB, error) {
	db := newChromeDB()
	if b, _, err := c.Read(chromeDBFile); err == nil {
		var stored ChromeDB
		if err := json.Unmarshal(b, &stored); err == nil && stored.Format == chromeDBFormat && stored.Posts != nil {
			db = &stored
		}
	}
	const size = 50
	var firstErr error
	for start := 1; start < 20000; start += size {
		u := fmt.Sprintf("https://chromereleases.googleblog.com/feeds/posts/default/-/Desktop%%20Update?redirect=false&max-results=%d&start-index=%d", size, start)
		page, err := c.Get(ctx, u)
		if err != nil {
			firstErr = err
			break
		}
		oldest, known, n, err := db.Merge(page)
		if err != nil {
			firstErr = err
			break
		}
		if progress != nil {
			progress("Chrome releases back to " + oldest)
		}
		reached := oldest < cutoff || n == 0
		if reached || (known && db.Oldest != "" && db.Oldest <= cutoff) {
			break
		}
	}
	if b, err := json.Marshal(db); err == nil {
		if err := c.Write(chromeDBFile, b); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return db, firstErr
}

// DaysBefore formats a cutoff date.
func DaysBefore(date string, days int) string {
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return date
	}
	return t.AddDate(0, 0, -days).Format("2006-01-02")
}
