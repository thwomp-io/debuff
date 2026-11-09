package server

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/thwomp-io/debuff/internal/snapshot"
)

// View is what the inbox shows from one scan.
type View struct {
	Rows      []Row
	Apps      map[string]AppFacts
	Scanned   bool
	ScannedAt time.Time
	Degraded  []string
	Previous  *Previous
	// UnchangedSince is the earliest scan that already said the same as this one. Zero if this is the first.
	UnchangedSince time.Time
	Pending        []snapshot.Pending
}

// FromSnapshot turns a scan into rows, and the things it inspected into app facts.
func FromSnapshot(s snapshot.Snapshot) View {
	v := View{Scanned: true, ScannedAt: s.ScannedAt, Degraded: s.Degraded(), Apps: map[string]AppFacts{}, Pending: s.Pending}
	for _, it := range s.Items {
		v.Apps[it.App] = AppFacts{
			Kind: it.Kind, Stack: it.Version, Runtime: it.Runtime, Version: it.AppVersion,
			LastOpened: it.LastOpened, Updated: it.Updated, Why: it.ExposureWhy, Note: it.Note,
			Exposure: it.Exposure, Running: it.Running, Unsupported: it.Unsupported,
			Latest: it.Latest, Update: it.Update, Icon: it.Icon, CVESource: it.CVESource,
			Path: it.Path, AppStore: it.AppStore,
		}
	}
	for _, f := range s.Findings {
		r := Row{
			KEV: f.KEV, Severity: f.Severity, App: f.App, CVE: f.CVE, Title: f.Title, Label: f.Label,
			FixedIn: f.FixedIn, Evidence: f.Evidence, URL: f.URL, Absent: f.Absent, EPSSScore: f.EPSS,
			Date: displayDate(f.Date), Sort: f.Date,
		}
		if f.HasEPSS {
			r.EPSS = displayEPSS(f.EPSS)
		}
		if f.Absent && f.Label != snapshot.Doubtful {
			r.Evidence += " It's also in a Chrome feature this app probably doesn't ship."
		}
		v.Rows = append(v.Rows, r)
	}
	return v
}

func displayDate(d string) string {
	t, err := time.Parse("2006-01-02", d)
	if err != nil {
		return d
	}
	if t.Year() == time.Now().Year() {
		return t.Format("Jan 2")
	}
	return t.Format("Jan 2006")
}

func displayEPSS(p float64) string {
	if p < 0.01 {
		return "<1%"
	}
	return fmt.Sprintf("%.0f%%", p*100)
}

// LatestLoader serves the newest snapshot in dir and what to compare it with, re-reading only when a newer one
// appears, so a scan shows up without a restart.
func LatestLoader(dir string) func() (View, error) {
	var mu sync.Mutex
	var path string
	var modTime time.Time
	var cached View
	return func() (View, error) {
		mu.Lock()
		defer mu.Unlock()
		p, err := snapshot.Latest(dir)
		if errors.Is(err, snapshot.ErrNone) {
			return View{}, nil
		}
		if err != nil {
			return View{}, err
		}
		fi, err := os.Stat(p)
		if err != nil {
			return View{}, err
		}
		if p == path && fi.ModTime().Equal(modTime) {
			return cached, nil
		}
		h, err := snapshot.LoadHistory(dir)
		if err != nil {
			return View{}, err
		}
		v := FromSnapshot(h.Latest)
		v.UnchangedSince = h.Since
		if h.Previous != nil {
			o := FromSnapshot(*h.Previous)
			v.Previous = &Previous{Rows: o.Rows, Apps: o.Apps, ScannedAt: o.ScannedAt}
		}
		path, modTime, cached = p, fi.ModTime(), v
		return cached, nil
	}
}
