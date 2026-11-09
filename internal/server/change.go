package server

import (
	"slices"
	"strings"
	"time"
)

// Previous is the last scan that found something different from the one on the page. Comparing with that, and
// not simply the scan before, means rescanning an unchanged machine can't erase the news.
type Previous struct {
	Rows      []Row
	Apps      map[string]AppFacts
	ScannedAt time.Time
}

// Change is what differs from the last scan that found something else, under the same view and severity setting as the page. A finding
// can close because the app changed or because an advisory did: this says that it changed, not why.
type Change struct {
	Since                         string
	Unchanged                     string // the scan this state began at, when later scans have found the same
	Closed, New                   int
	ExploitedBefore, ExploitedNow int
	Removed                       []string
}

// None: nothing differs, which is worth saying after a rescan.
func (c Change) None() bool {
	return c.Closed == 0 && c.New == 0 && len(c.Removed) == 0
}

// CardChange is one app's part of it.
type CardChange struct {
	From, To    string
	Closed, New int
}

// Any: this app has something to show.
func (c CardChange) Any() bool { return c.From != c.To || c.Closed > 0 || c.New > 0 }

func rowKey(r Row) string { return r.App + "\x00" + r.CVE }

// compare diffs the rows on the page against the same selection of the previous scan.
func compare(prev *Previous, now []Row, apps map[string]AppFacts, keep func(Row) bool) (Change, map[string]CardChange) {
	c := Change{Since: prev.ScannedAt.Local().Format("Jan 2, 3:04 PM")}
	cards := map[string]CardChange{}
	was := map[string]bool{}
	before := map[string]bool{}
	for _, r := range prev.Rows {
		if keep(r) {
			was[rowKey(r)] = true
			before[r.App] = true
			if r.KEV {
				c.ExploitedBefore++
			}
		}
	}
	is := map[string]bool{}
	for _, r := range now {
		k := rowKey(r)
		is[k] = true
		if r.KEV {
			c.ExploitedNow++
		}
		if !was[k] {
			c.New++
			cc := cards[r.App]
			cc.New++
			cards[r.App] = cc
		}
	}
	for _, r := range prev.Rows {
		if keep(r) && !is[rowKey(r)] {
			c.Closed++
			cc := cards[r.App]
			cc.Closed++
			cards[r.App] = cc
		}
	}
	for app := range before {
		if _, ok := apps[app]; !ok {
			c.Removed = append(c.Removed, strings.TrimSuffix(app, ".app"))
		}
	}
	slices.Sort(c.Removed)
	for app, was := range prev.Apps {
		if to, ok := apps[app]; ok && was.Version != "" && to.Version != "" && was.Version != to.Version {
			cc := cards[app]
			cc.From, cc.To = was.Version, to.Version
			cards[app] = cc
		}
	}
	return c, cards
}
