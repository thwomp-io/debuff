package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"

	"github.com/thwomp-io/debuff/internal/fetch"
)

// ElectronRelease is one line of Electron's release list.
type ElectronRelease struct {
	Version string `json:"version"`
	Chrome  string `json:"chrome"`
	V8      string `json:"v8"`
	Date    string `json:"date"`
}

// Electron is the release list.
type Electron struct{ Releases []ElectronRelease }

var stableVer = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// LoadElectron fetches the release list, cached a day.
func LoadElectron(ctx context.Context, c *fetch.Client) (Electron, fetch.Result, error) {
	r, err := c.Cached(ctx, "electron/releases.json", 24*time.Hour, "https://releases.electronjs.org/releases.json")
	if err != nil {
		return Electron{}, r, err
	}
	var e Electron
	return e, r, json.Unmarshal(r.Body, &e.Releases)
}

// Find returns one release.
func (e Electron) Find(v string) (ElectronRelease, bool) {
	for _, r := range e.Releases {
		if r.Version == v {
			return r, true
		}
	}
	return ElectronRelease{}, false
}

func (e Electron) stable(major string) []ElectronRelease {
	var out []ElectronRelease
	for _, r := range e.Releases {
		if stableVer.MatchString(r.Version) && strings.SplitN(r.Version, ".", 2)[0] == major {
			out = append(out, r)
		}
	}
	return out
}

// Line is the stable releases on v's major, at or below v: where a backport could have landed.
func (e Electron) Line(v string) []string {
	var out []string
	for _, r := range e.stable(strings.SplitN(v, ".", 2)[0]) {
		if CompareVersions(r.Version, v) <= 0 {
			out = append(out, r.Version)
		}
	}
	return out
}

// LineStart is the date v's major line began: the oldest Chrome CVE that could matter to it.
func (e Electron) LineStart(v string) string {
	first := ""
	for _, r := range e.stable(strings.SplitN(v, ".", 2)[0]) {
		if first == "" || r.Date < first {
			first = r.Date
		}
	}
	return first
}

// Supported: Electron backs the newest three stable majors.
func (e Electron) Supported(v string) bool {
	newest := 0
	for _, r := range e.Releases {
		if stableVer.MatchString(r.Version) {
			newest = max(newest, major(r.Version))
		}
	}
	return major(v) > newest-3
}

var (
	backportCVE = regexp.MustCompile(`(?i)backported fix for\s+(CVE-\d{4}-\d+)`)
	backportBug = regexp.MustCompile(`(?i)backported fix for\s+(?:chromium:)?(\d{6,})`)
)

// Backports reads Electron's notes for the CVEs and bug ids a release says it backported.
func Backports(notes []byte) (cves, bugs []string) {
	text := html.UnescapeString(string(notes))
	for _, m := range backportCVE.FindAllStringSubmatch(text, -1) {
		cves = append(cves, strings.ToUpper(m[1]))
	}
	for _, m := range backportBug.FindAllStringSubmatch(text, -1) {
		bugs = append(bugs, m[1])
	}
	return cves, bugs
}

// LineBackports gathers everything an Electron line backported up to v. A release's notes never change,
// so they're cached for good. It keeps what it found if a page fails, and returns the error.
func LineBackports(ctx context.Context, c *fetch.Client, e Electron, v string, byBug map[string]string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, rel := range e.Line(v) {
		r, err := c.Cached(ctx, "electron/notes/v"+fetch.SafeName(rel)+".html", 10*365*24*time.Hour,
			"https://releases.electronjs.org/release/v"+rel)
		if err != nil {
			return out, fmt.Errorf("Electron %s notes: %w", rel, err)
		}
		cves, bugs := Backports(r.Body)
		for _, id := range cves {
			out[id] = true
		}
		for _, b := range bugs {
			if id, ok := byBug[b]; ok {
				out[id] = true
			}
		}
	}
	return out, nil
}
