package resolve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/thwomp-io/debuff/internal/fetch"
)

var (
	bugLine = regexp.MustCompile(`(?m)^\s*(?:Bug|Fixed|BUG):\s*(.+)$`)
	bugNum  = regexp.MustCompile(`\b(\d{6,})\b`)
)

// BugIDs reads the bug ids a commit message names.
func BugIDs(message string) []string {
	var out []string
	for _, line := range bugLine.FindAllStringSubmatch(message, -1) {
		out = append(out, bugNum.FindAllString(line[1], -1)...)
	}
	return out
}

type gitLog struct {
	Log []struct {
		Message   string `json:"message"`
		Committer struct {
			Time string `json:"time"`
		} `json:"committer"`
	} `json:"log"`
	Next string `json:"next"`
}

func parseLog(b []byte) (gitLog, error) {
	var r gitLog
	return r, json.Unmarshal(bytes.TrimPrefix(b, []byte(")]}'\n")), &r)
}

func logTime(s string) (time.Time, error) {
	f := strings.Fields(s)
	if len(f) < 5 {
		return time.Time{}, fmt.Errorf("bad time %q", s)
	}
	return time.Parse("Mon Jan 2 15:04:05 2006", strings.Join(f[:5], " "))
}

// branchLog reads chromium/src from the branch cut to the runtime's exact version: fixes the build
// really has, whatever its version number says. It returns the bug ids and the cut's date.
func branchLog(ctx context.Context, c *fetch.Client, version string) (map[string]bool, time.Time, error) {
	bugs := map[string]bool{}
	var cut time.Time
	p := strings.Split(version, ".")
	if len(p) != 4 {
		return bugs, cut, fmt.Errorf("bad Chromium version %q", version)
	}
	base := strings.Join(p[:3], ".") + ".0"
	next := ""
	for page := range 60 {
		u := fmt.Sprintf("https://chromium.googlesource.com/chromium/src/+log/%s..%s?format=JSON&n=200", base, version)
		if next != "" {
			u += "&s=" + url.QueryEscape(next)
		}
		// A released version's history never changes, and these servers fail on deep pages now and then.
		// Keeping each page lets the next try resume, and lets apps on the same Chromium share it.
		name := fmt.Sprintf("branches/src/%s/%02d-%s.json", fetch.SafeName(version), page, fetch.SafeName(next))
		res, err := c.Cached(ctx, name, 10*365*24*time.Hour, u)
		if err != nil {
			return bugs, cut, err
		}
		r, err := parseLog(res.Body)
		if err != nil {
			return bugs, cut, err
		}
		for _, l := range r.Log {
			for _, id := range BugIDs(l.Message) {
				bugs[id] = true
			}
			if t, err := logTime(l.Committer.Time); err == nil && (cut.IsZero() || t.Before(cut)) {
				cut = t
			}
		}
		if r.Next == "" {
			return bugs, cut, nil
		}
		next = r.Next
	}
	return bugs, cut, fmt.Errorf("chromium/src log for %s ran past the page cap", version)
}

// EngineRepos: the engines Chromium pulls from their own repos, on this build's release branch. A fix
// lands there and arrives as a roll, so chromium/src never names its bug.
func EngineRepos(chromium, v8 string) map[string]string {
	p := strings.Split(chromium, ".")
	if len(p) != 4 {
		return nil
	}
	build, m := p[2], p[0]
	out := map[string]string{
		"angle":  "https://chromium.googlesource.com/angle/angle/+log/refs/heads/chromium/" + build,
		"dawn":   "https://dawn.googlesource.com/dawn/+log/refs/heads/chromium/" + build,
		"pdfium": "https://pdfium.googlesource.com/pdfium/+log/refs/heads/chromium/" + build,
		"skia":   "https://skia.googlesource.com/skia/+log/refs/heads/chrome/m" + m,
		"webrtc": "https://webrtc.googlesource.com/src/+log/refs/branch-heads/" + build,
	}
	if q := strings.Split(v8, "."); len(q) >= 2 {
		out["v8"] = "https://chromium.googlesource.com/v8/v8/+log/refs/branch-heads/" + q[0] + "." + q[1]
	}
	return out
}

// engineLog reads one engine's branch, from the cut to the runtime's release. Newest first, so it stops
// at the cut. A branch that doesn't exist (an engine younger than the build) is simply empty.
func engineLog(ctx context.Context, c *fetch.Client, base string, cut, until time.Time) (map[string]bool, error) {
	bugs := map[string]bool{}
	next := ""
	for range 12 {
		u := base + "?format=JSON&n=200"
		if next != "" {
			u += "&s=" + url.QueryEscape(next)
		}
		b, err := c.Get(ctx, u)
		if err != nil {
			if s, ok := err.(fetch.Status); ok && s.Code == 404 { //nolint:errorlint // Get returns it unwrapped
				return bugs, nil
			}
			return bugs, err
		}
		r, err := parseLog(b)
		if err != nil {
			return bugs, err
		}
		for _, l := range r.Log {
			t, err := logTime(l.Committer.Time)
			if err != nil {
				continue
			}
			if t.Before(cut) {
				return bugs, nil
			}
			if t.After(until) {
				continue
			}
			for _, id := range BugIDs(l.Message) {
				bugs[id] = true
			}
		}
		if r.Next == "" {
			return bugs, nil
		}
		next = r.Next
	}
	return bugs, fmt.Errorf("%s ran past the page cap before the branch cut", path.Base(base))
}

type mergedFile struct {
	Format int      `json:"format"`
	Bugs   []string `json:"bugs"`
}

// Merged is every bug id a build carries: its branch log and, given a release date and a V8 version, its
// engines' logs. A released build never changes, so a complete answer is cached for good. A partial one
// is used but not kept, and comes back with the error, so the page can say the evidence was incomplete.
func Merged(ctx context.Context, c *fetch.Client, chromium, v8, released string) (map[string]bool, error) {
	name := "branches/" + fetch.SafeName(chromium+"_"+v8+"_"+released) + ".json"
	if b, _, err := c.Read(name); err == nil {
		var f mergedFile
		if json.Unmarshal(b, &f) == nil && f.Format == 1 {
			out := map[string]bool{}
			for _, id := range f.Bugs {
				out[id] = true
			}
			return out, nil
		}
	}
	bugs, cut, err := branchLog(ctx, c, chromium)
	if err != nil {
		return bugs, err
	}
	if released != "" && !cut.IsZero() {
		until, perr := time.Parse("2006-01-02", released)
		if perr != nil {
			return bugs, perr
		}
		repos := EngineRepos(chromium, v8)
		names := make([]string, 0, len(repos))
		for n := range repos {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			got, err := engineLog(ctx, c, repos[n], cut, until.Add(24*time.Hour))
			for id := range got {
				bugs[id] = true
			}
			if err != nil {
				return bugs, fmt.Errorf("%s log: %w", n, err)
			}
		}
	}
	ids := make([]string, 0, len(bugs))
	for id := range bugs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if b, err := json.Marshal(mergedFile{1, ids}); err == nil {
		if err := c.Write(name, b); err != nil {
			return bugs, err
		}
	}
	return bugs, nil
}
