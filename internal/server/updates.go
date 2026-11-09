package server

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/thwomp-io/debuff/internal/resolve"
	"github.com/thwomp-io/debuff/internal/snapshot"
	"github.com/thwomp-io/debuff/internal/update"
)

const (
	updatesView = "updates"
	// The most an upgrade gets. A formula that builds from source can take a while.
	upgradeLimit = 30 * time.Minute
)

// UpdateRow is one thing with an update, and what its button does. The server works that out from the scan: a
// press only names the row, so a request can't choose a command or a path.
type UpdateRow struct {
	Card
	Installed, Latest, How, Button string
	Formula, Open                  string // what a press does; one of them, or neither when nothing can be done from here
	Restart                        bool
}

// formulaCount is how many rows "Update all" covers.
func formulaCount(rows []UpdateRow) int {
	n := 0
	for _, u := range rows {
		if u.Formula != "" {
			n++
		}
	}
	return n
}

// Primary: this button does the update itself, as opposed to opening where it's done.
func (u UpdateRow) Primary() bool { return u.Formula != "" }

// Unchecked: nothing could look for CVEs in this, so an empty count must not read as none.
func (u UpdateRow) Unchecked() bool { return !u.Checked() }

// updateRows lists everything with an update, the most urgent first: known exploited, then critical, then high.
func updateRows(v View) []UpdateRow {
	var out []UpdateRow
	done := map[string]bool{}
	for _, p := range v.Pending {
		u := UpdateRow{Installed: p.Installed, Latest: p.Latest, Restart: p.Restart}
		u.App = p.Name
		switch p.Via {
		case snapshot.ViaHomebrew:
			u.Facts = AppFacts{Kind: kindHomebrew}
			if f, ok := v.Apps[p.Name]; ok {
				u.Facts = f
			}
			u.Formula, u.Button, u.How = p.Name, "Update", "Homebrew formula. Runs brew upgrade, then rescans."
			done[p.Name] = true
		case snapshot.ViaSystem:
			if f, ok := v.Apps[p.Name+".app"]; ok {
				u.App, u.Facts = p.Name+".app", f
			}
			u.Open, u.Button, u.How = update.SoftwareUpdate, "Software Update", "Installed through System Settings."
			done[u.App] = true
		default:
			continue
		}
		out = append(out, u)
	}
	for name, f := range v.Apps {
		if done[name] || f.Update != resolve.UpdateAvailable {
			continue
		}
		u := UpdateRow{Installed: f.Version, Latest: f.Latest}
		u.App, u.Facts = name, f
		switch {
		case f.AppStore:
			u.Open, u.Button, u.How = update.AppStore, "App Store", "Installed from the App Store."
		case f.Path != "":
			u.Open, u.Button, u.How = f.Path, "Open app", "Opens the app. Look for its Check for Updates."
		default:
			u.How = "Debuff can't update this or open it from here."
		}
		out = append(out, u)
	}
	index := map[string]int{}
	for i := range out {
		index[out[i].App] = i
	}
	for _, r := range v.Rows {
		i, ok := index[r.App]
		if !ok {
			continue
		}
		c := &out[i]
		c.Count++
		if r.KEV {
			c.Exploited++
		}
		if r.Absent {
			continue
		}
		switch severityRank(r.Severity) {
		case 4:
			c.Critical++
		case 3:
			c.High++
		}
	}
	slices.SortFunc(out, func(a, b UpdateRow) int {
		switch {
		case a.Exploited != b.Exploited:
			return b.Exploited - a.Exploited
		case a.Critical != b.Critical:
			return b.Critical - a.Critical
		case a.High != b.High:
			return b.High - a.High
		}
		return strings.Compare(strings.ToLower(a.Name()), strings.ToLower(b.Name()))
	})
	return out
}

// notListed names the apps this page can't speak for, so an empty or short list doesn't read as everything being
// current. App Store apps come separately: they have somewhere to go.
func notListed(v View) (store, unknown []string) {
	for name, f := range v.Apps {
		switch {
		case f.Kind != kindApp && f.Kind != kindElectron:
		case f.AppStore && f.Update == "":
			store = append(store, strings.TrimSuffix(name, ".app"))
		case f.Update == "":
			unknown = append(unknown, strings.TrimSuffix(name, ".app"))
		}
	}
	slices.SortFunc(store, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	slices.SortFunc(unknown, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	return store, unknown
}

// upgrader runs one upgrade at a time, in the background, since it can far outlast a request. "Update all" is one
// upgrade of several formulae: Homebrew locks each install, so parallel upgrades would only queue or collide.
type upgrader struct {
	base    context.Context
	run     func(context.Context, []string) error
	after   func() // starts a rescan, so the page catches up by itself
	mu      sync.Mutex
	names   []string
	done    string
	failure string
	wg      sync.WaitGroup // lets a test wait for it
}

// label names what's being upgraded: one formula by name, several by count and names.
func label(names []string) string {
	if len(names) == 1 {
		return names[0]
	}
	return fmt.Sprintf("%d formulae (%s)", len(names), strings.Join(names, ", "))
}

// start reports false when another upgrade is running.
func (u *upgrader) start(formulae []string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.names) > 0 || len(formulae) == 0 {
		return false
	}
	u.names, u.done, u.failure = formulae, "", ""
	u.wg.Go(func() {
		// Not cancelled by the server stopping: killing a package manager partway is worse than letting it finish.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(u.base), upgradeLimit)
		defer cancel()
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("%v", r)
				}
			}()
			return u.run(ctx, formulae)
		}()
		u.mu.Lock()
		u.names = nil
		if err != nil {
			u.failure = "brew upgrade " + strings.Join(formulae, " ") + " failed: " + err.Error()
			if len(formulae) > 1 {
				u.failure += ". Some may have updated before it stopped; the rescan shows which."
			}
		} else {
			u.done = label(formulae) + " updated."
		}
		u.mu.Unlock()
		// Rescan after any attempt: a failed upgrade can still have changed things (a dependency, or the
		// formulae before the one that failed), and the page should show what's true now.
		if u.after != nil {
			u.after()
		}
	})
	return true
}

// status says what's happening. With seen, the outcome is being shown for good, so it won't be shown again: left
// in place, "updated" would still be on the page tomorrow.
func (u *upgrader) status(seen bool) (running string, names []string, done, failure string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.names) > 0 {
		running, names = label(u.names), slices.Clone(u.names)
	}
	done, failure = u.done, u.failure
	if seen {
		u.done, u.failure = "", ""
	}
	return running, names, done, failure
}

// pressHandler answers a row's button. Like the rescan button, an absent Origin is refused here: a browser always
// sends one on a POST, so nothing but this page can press it.
func pressHandler(load func() (View, error), up *upgrader, open func(context.Context, string) error, note func(string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		back := link(updatesView, r.PostFormValue("min"), "")
		defer http.Redirect(w, r, back, http.StatusSeeOther) // #nosec G710 -- link builds a path on this site from escaped values
		note("")
		if r.PostFormValue("store") != "" {
			if open != nil {
				if err := open(r.Context(), update.AppStore); err != nil {
					note("Couldn't open the App Store: " + err.Error())
				}
			}
			return
		}
		view, err := load()
		if err != nil {
			note("Couldn't read the latest scan: " + err.Error())
			return
		}
		refused := "Another update is running, so this press was ignored."
		if r.PostFormValue("all") != "" {
			var formulae []string
			for _, u := range updateRows(view) {
				if u.Formula != "" {
					formulae = append(formulae, u.Formula)
				}
			}
			switch {
			case up == nil:
			case len(formulae) == 0:
				note("Nothing on the page can be updated from here.")
			case !up.start(formulae): //nolint:contextcheck // the upgrade outlives this press
				note(refused)
			}
			return
		}
		name := r.PostFormValue("row")
		i := slices.IndexFunc(updateRows(view), func(u UpdateRow) bool { return u.App == name })
		if i < 0 {
			note("That's no longer listed, so nothing was run.")
			return
		}
		row := updateRows(view)[i]
		switch {
		case row.Formula != "" && up != nil:
			if !up.start([]string{row.Formula}) { //nolint:contextcheck // the upgrade outlives this press
				note(refused)
			}
		case row.Open != "" && open != nil:
			if err := open(r.Context(), row.Open); err != nil {
				note("Couldn't open " + row.Name() + ": " + err.Error())
			}
		}
	}
}
