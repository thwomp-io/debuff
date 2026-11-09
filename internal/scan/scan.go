// Package scan runs one scan: find what's installed, resolve it against the advisories, write a snapshot.
// A source that fails makes the scan weaker, not wrong: it's recorded, and the page says so.
package scan

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/thwomp-io/debuff/internal/collect"
	"github.com/thwomp-io/debuff/internal/fetch"
	"github.com/thwomp-io/debuff/internal/registry"
	"github.com/thwomp-io/debuff/internal/resolve"
	"github.com/thwomp-io/debuff/internal/snapshot"
)

// Kinds of item beyond the runtimes.
const (
	KindApp       = "app"
	KindAgentTool = "agent tool"
)

// Options configures a scan.
type Options struct {
	Dir      string // the data directory
	Home     string
	Version  string
	Cache    *fetch.Client
	Now      func() time.Time
	Progress func(string)
	// Replaceable for tests; the zero value uses the real collectors.
	Runtimes   func(ctx context.Context, chromiumOf func(string) string) ([]collect.Runtime, error)
	Brew       func(context.Context) (collect.BrewReport, error)
	Listening  func(context.Context) map[string]bool
	Apps       func(ctx context.Context, skip map[string]bool) ([]collect.App, error)
	AgentTools func() ([]collect.AgentTool, []string)
	Outdated   func(context.Context) ([]collect.Pending, error)
	System     func(context.Context) ([]collect.Pending, error)
}

type run struct {
	Options
	sources []snapshot.Source
	catalog resolve.Catalog
}

func (r *run) source(name string, err error, okDetail string) {
	if err != nil {
		r.sources = append(r.sources, snapshot.Source{Name: name, Status: "failed", Detail: err.Error()})
		return
	}
	r.sources = append(r.sources, snapshot.Source{Name: name, Status: "ok", Detail: okDetail})
}

func (r *run) cachedSource(name string, res fetch.Result, err error, okDetail string) {
	if err == nil && res.Stale != nil {
		r.sources = append(r.sources, snapshot.Source{
			Name: name, Status: "stale",
			Detail: fmt.Sprintf("using a copy %.0f hours old: %v", res.Age.Hours(), res.Stale),
		})
		return
	}
	r.source(name, err, okDetail)
}

func (r *run) say(format string, a ...any) {
	if r.Progress != nil {
		r.Progress(fmt.Sprintf(format, a...))
	}
}

// Run scans, and returns the snapshot without writing it.
func Run(ctx context.Context, o Options) (snapshot.Snapshot, error) {
	r := &run{Options: o}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Runtimes == nil {
		r.Runtimes = func(ctx context.Context, f func(string) string) ([]collect.Runtime, error) {
			return collect.Runtimes(ctx, r.Home, f)
		}
	}
	if r.Brew == nil {
		r.Brew = collect.Brew
	}
	if r.Listening == nil {
		r.Listening = collect.Listening
	}
	if r.Apps == nil {
		r.Apps = func(ctx context.Context, skip map[string]bool) ([]collect.App, error) {
			return collect.Apps(ctx, r.Home, skip)
		}
	}
	if r.AgentTools == nil {
		r.AgentTools = func() ([]collect.AgentTool, []string) { return collect.AgentTools(r.Home) }
	}
	if r.Outdated == nil {
		r.Outdated = collect.Outdated
	}
	if r.System == nil {
		r.System = collect.SystemUpdates
	}
	now := r.Now()
	host, _ := os.Hostname()
	s := snapshot.Snapshot{Format: snapshot.Format, Host: host, ScannedAt: now.UTC(), Version: r.Version}

	exposure, err := collect.LoadExposure(r.Dir)
	if err != nil {
		return s, err
	}

	r.say("Electron release list")
	electron, res, err := resolve.LoadElectron(ctx, r.Cache)
	r.cachedSource("Electron releases", res, err, fmt.Sprintf("%d releases", len(electron.Releases)))

	r.say("looking for bundled runtimes")
	runtimes, err := r.Runtimes(ctx, func(v string) string {
		if rel, ok := electron.Find(v); ok {
			return rel.Chrome
		}
		return ""
	})
	r.source("Bundled runtimes on this machine", err, fmt.Sprintf("%d found", len(runtimes)))

	kev := r.loadKEV(ctx)
	r.catalog = r.loadCatalog(ctx)
	if len(runtimes) > 0 {
		db := r.syncChrome(ctx, electron, runtimes, now)
		for _, rt := range runtimes {
			item, found := r.resolveRuntime(ctx, rt, electron, db, kev, exposure)
			s.Items = append(s.Items, item)
			s.Findings = append(s.Findings, found...)
		}
	}
	items, found := r.brew(ctx, kev)
	s.Items = append(s.Items, items...)
	s.Findings = append(s.Findings, found...)
	skip := map[string]bool{}
	for _, rt := range runtimes {
		skip[rt.App] = true
	}
	items, found = r.apps(ctx, skip, exposure, kev)
	s.Items = append(s.Items, items...)
	s.Findings = append(s.Findings, found...)
	items, found = r.agentStack(ctx, kev)
	s.Items = append(s.Items, items...)
	s.Findings = append(s.Findings, found...)
	s.Pending = r.pending(ctx, s.Items)
	r.scoreEPSS(ctx, s.Findings)
	s.Sources = r.sources
	return s, nil
}

// Write stores a snapshot, returning where.
func Write(dir string, s snapshot.Snapshot) (string, error) { return snapshot.Write(dir, s) }

// apps lists the apps with no bundled runtime to resolve. The registry says where to ask about each, and only a
// verified entry is asked. The rest are listed with no CVE source, which the page says isn't the same as clean.
func (r *run) apps(ctx context.Context, skip map[string]bool, exposure map[string]collect.Exposure, kev map[string]bool) ([]snapshot.Item, []snapshot.Finding) {
	r.say("the other apps")
	apps, err := r.Apps(ctx, skip)
	r.source("Other apps on this machine", err, fmt.Sprintf("%d found", len(apps)))
	reg, err := registry.Load(r.Dir)
	if err != nil {
		r.source("App registry", err, "")
	}
	items := make([]snapshot.Item, 0, len(apps))
	var found []snapshot.Finding
	for _, a := range apps {
		it := snapshot.Item{
			App: a.Name, Kind: KindApp, Version: a.Bundle.Version, AppVersion: a.Bundle.Version, Running: a.Running,
			LastOpened: a.Bundle.LastOpened, Updated: a.Bundle.Updated, Icon: r.saveIcon(a.Bundle.Icon),
			Exposure: 2, ExposureWhy: "Not assessed yet", Path: a.Path, AppStore: a.Bundle.AppStore,
		}
		e, known := reg.Lookup(a.Bundle.ID)
		if known && e.Cask != "" {
			it.Latest, it.Update = r.catalog.UpdateFromCask(e.Cask, a.Bundle.Version, e.Parts)
		} else {
			it.Latest, it.Update = r.catalog.Update(a.Name, a.Bundle.Version)
		}
		if known && e.Why != "" {
			it.Exposure, it.ExposureWhy = e.Exposure, e.Why
		}
		if x, ok := exposure[a.Name]; ok {
			it.Exposure, it.ExposureWhy = x.Rank, x.Why
		}
		if known && e.CPE != "" && e.Verified != "" {
			if fs, ok := r.nvd(ctx, a.Name, e, a.Bundle.Version, kev); ok {
				it.CVESource = "NVD"
				found = append(found, fs...)
			}
		}
		items = append(items, it)
	}
	return items, found
}

// pending is what the package tools say can be updated. Anything already inspected gets the news on its card too,
// matched by name: a formula as itself, a system component such as a browser by its bundle.
func (r *run) pending(ctx context.Context, items []snapshot.Item) []snapshot.Pending {
	r.say("available updates")
	byName := map[string]*snapshot.Item{}
	for i := range items {
		byName[items[i].App] = &items[i]
	}
	var out []snapshot.Pending
	add := func(list []collect.Pending, via, suffix string) {
		for _, p := range list {
			if it := byName[p.Name+suffix]; it != nil {
				it.Latest, it.Update = p.Latest, resolve.UpdateAvailable
				if p.Installed == "" {
					p.Installed = it.AppVersion
				}
			}
			out = append(out, snapshot.Pending{Name: p.Name, Installed: p.Installed, Latest: p.Latest, Via: via, Restart: p.Restart})
		}
	}
	formulae, err := r.Outdated(ctx)
	r.source("Homebrew updates", err, fmt.Sprintf("%d formulae outdated", len(formulae)))
	add(formulae, snapshot.ViaHomebrew, "")
	system, err := r.System(ctx)
	r.source("Software Update", err, fmt.Sprintf("%d available", len(system)))
	add(system, snapshot.ViaSystem, ".app")
	return out
}

// nvd asks NVD about one app. It reports false when it couldn't, so the app reads as unchecked, never as clean.
func (r *run) nvd(ctx context.Context, app string, e registry.Entry, version string, kev map[string]bool) ([]snapshot.Finding, bool) {
	listed, res, err := resolve.NVDAffected(ctx, r.Cache, e.CPE, version)
	r.cachedSource("NVD: "+e.Name, res, err, fmt.Sprintf("%d CVEs at %s", len(listed), version))
	if err != nil {
		return nil, false
	}
	found := make([]snapshot.Finding, 0, len(listed))
	for _, f := range listed {
		label, evidence := snapshot.Confirmed, "NVD lists "+e.Name+" "+version+" as affected."
		if !f.Ranged {
			label, evidence = snapshot.Inferred, "NVD matches this with no version range, so it may not apply to "+version+"."
		}
		found = append(found, snapshot.Finding{
			CVE: f.CVE, App: app, Label: label, Severity: normalSeverity(f.Severity), Title: f.Title,
			KEV: kev[f.CVE], FixedIn: f.FixedIn, Date: f.Published, URL: "https://nvd.nist.gov/vuln/detail/" + f.CVE,
			Evidence: evidence,
		})
	}
	return found, true
}

// agentStack lists what agents here can run, and asks OSV about anything with a package and a version.
func (r *run) agentStack(ctx context.Context, kev map[string]bool) ([]snapshot.Item, []snapshot.Finding) {
	r.say("the agent stack")
	tools, notes := r.AgentTools()
	detail := fmt.Sprintf("%d found", len(tools))
	if len(notes) > 0 {
		r.sources = append(r.sources, snapshot.Source{Name: "Agent configs", Status: "failed", Detail: strings.Join(notes, "; ")})
	} else {
		r.sources = append(r.sources, snapshot.Source{Name: "Agent stack", Status: "ok", Detail: detail})
	}
	var items []snapshot.Item
	var found []snapshot.Finding
	for _, t := range tools {
		it := snapshot.Item{App: t.Name, Kind: KindAgentTool, Version: t.Version, AppVersion: t.Version, Exposure: 3}
		switch t.Kind {
		case collect.AgentCLI:
			it.ExposureWhy = "Agent CLI: runs commands and reads files on your behalf"
		case collect.AgentPlugin:
			it.ExposureWhy = "Agent plugin: runs inside the agent"
			it.Exposure = 2
		default:
			it.ExposureWhy = "MCP server: an agent calls it, and acts on what it returns"
		}
		if t.Host != "" {
			it.ExposureWhy = "Remote MCP server at " + t.Host + ": nothing installed here to check"
		}
		if t.Unpinned {
			it.Note = "Unpinned: runs whatever is newest each time it starts"
		}
		if t.Pkg != "" && t.Version != "" {
			it.CVESource = "OSV"
			found = append(found, r.osvPackage(ctx, t, kev)...)
		}
		items = append(items, it)
	}
	return items, found
}

func (r *run) osvPackage(ctx context.Context, t collect.AgentTool, kev map[string]bool) []snapshot.Finding {
	name := "osv/" + fetch.SafeName(t.Ecosystem+"-"+t.Pkg+"-"+t.Version) + ".json"
	body := fmt.Sprintf(`{"package":{"name":%q,"ecosystem":%q},"version":%q}`, t.Pkg, t.Ecosystem, t.Version)
	res, err := r.Cache.CachedPost(ctx, name, 24*time.Hour, "https://api.osv.dev/v1/query", []byte(body))
	var parsed struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err == nil {
		err = json.Unmarshal(res.Body, &parsed)
	}
	r.cachedSource("OSV: "+t.Name, res, err, fmt.Sprintf("%d advisories", len(parsed.Vulns)))
	var found []snapshot.Finding
	for _, v := range parsed.Vulns {
		id := v.ID
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				id = a
			}
		}
		date := v.Published
		if len(date) > 10 {
			date = date[:10]
		}
		found = append(found, snapshot.Finding{
			CVE: id, App: t.Name, Label: snapshot.Confirmed, Severity: normalSeverity(v.DB.Severity), Title: v.Summary,
			KEV: kev[id], FixedIn: v.nextFix(t.Version), Date: date, URL: "https://osv.dev/vulnerability/" + v.ID,
			Evidence: "An advisory lists " + t.Pkg + " " + t.Version + " as affected.",
		})
	}
	return found
}

// IconDir is where icons live under the data directory. Which icons are here says which apps are installed,
// so like findings they stay out of git and backups.
func IconDir(dir string) string { return filepath.Join(dir, "icons") }

// saveIcon stores an icon under its content hash and returns that. Without an icon a card shows a letter, so
// a failure here costs only that and is said in the progress output.
func (r *run) saveIcon(icon []byte) string {
	if len(icon) == 0 {
		return ""
	}
	sum := sha256.Sum256(icon)
	id := hex.EncodeToString(sum[:])
	dir := IconDir(r.Dir)
	p := filepath.Join(dir, id+".png")
	if _, err := os.Stat(p); err == nil {
		return id
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		r.say("couldn't keep an icon: %v", err)
		return ""
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		r.say("couldn't keep an icon: %v", err)
		return ""
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.Write(icon)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), p)
	}
	if err != nil {
		r.say("couldn't keep an icon: %v", err)
		return ""
	}
	return id
}

// PruneIcons removes icons the newest scan doesn't use. Only the newest scan's cards show one.
func PruneIcons(dir string) error {
	p, err := snapshot.Latest(dir)
	if err != nil {
		if errors.Is(err, snapshot.ErrNone) {
			return nil
		}
		return err
	}
	s, err := snapshot.Read(p)
	if err != nil {
		return err
	}
	used := map[string]bool{}
	for _, it := range s.Items {
		used[it.Icon+".png"] = true
	}
	names, err := filepath.Glob(filepath.Join(IconDir(dir), "*.png"))
	if err != nil {
		return err
	}
	for _, name := range names {
		if !used[filepath.Base(name)] {
			if err := os.Remove(name); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadCatalog: a failure costs only the update line on each card, and the page says so.
func (r *run) loadCatalog(ctx context.Context) resolve.Catalog {
	r.say("Homebrew catalog")
	cat, res, err := resolve.LoadCatalog(ctx, r.Cache)
	r.cachedSource("Homebrew catalog", res, err, "latest versions")
	return cat
}

func (r *run) loadKEV(ctx context.Context) map[string]bool {
	res, err := r.Cache.Cached(ctx, "kev.json", 24*time.Hour, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	out := map[string]bool{}
	if err == nil {
		var f struct {
			Vulnerabilities []struct {
				ID string `json:"cveID"`
			} `json:"vulnerabilities"`
		}
		if err = json.Unmarshal(res.Body, &f); err == nil {
			for _, v := range f.Vulnerabilities {
				out[v.ID] = true
			}
		}
	}
	r.cachedSource("CISA known exploited list", res, err, fmt.Sprintf("%d entries", len(out)))
	return out
}

// syncChrome reads far enough back for the oldest runtime here.
func (r *run) syncChrome(ctx context.Context, e resolve.Electron, runtimes []collect.Runtime, now time.Time) *resolve.ChromeDB {
	cutoff := now.AddDate(0, -6, 0).Format("2006-01-02")
	for _, rt := range runtimes {
		if rt.Kind != collect.KindElectron {
			continue
		}
		if start := e.LineStart(rt.Electron); start != "" {
			if back := resolve.DaysBefore(start, 45); back < cutoff {
				cutoff = back
			}
		}
	}
	db, err := resolve.SyncChrome(ctx, r.Cache, cutoff, r.Progress)
	r.source("Chrome Releases", err, fmt.Sprintf("%d CVEs back to %s", len(db.CVEs), db.Oldest))
	return db
}

func (r *run) resolveRuntime(ctx context.Context, rt collect.Runtime, e resolve.Electron, db *resolve.ChromeDB, kev map[string]bool, exposure map[string]collect.Exposure) (snapshot.Item, []snapshot.Finding) {
	r.say("resolving %s (Chromium %s)", rt.App, rt.Chromium)
	item := snapshot.Item{
		App: rt.App, Kind: rt.Kind, Version: rt.Electron, Runtime: rt.Chromium, Running: rt.Running,
		AppVersion: rt.Bundle.Version, LastOpened: rt.Bundle.LastOpened, Updated: rt.Bundle.Updated,
		Icon: r.saveIcon(rt.Bundle.Icon), AppStore: rt.Bundle.AppStore,
	}
	if rt.Kind == collect.KindElectron {
		item.Path = rt.Path // a browser's Path is a cache directory, not something to open
	}
	item.Latest, item.Update = r.catalog.Update(rt.App, rt.Bundle.Version)
	item.Exposure, item.ExposureWhy = 2, "Not assessed yet"
	if rt.Kind == collect.KindBrowser {
		item.Exposure, item.ExposureWhy = 3, "Agent browser: loads whatever it's pointed at while launched"
	}
	if x, ok := exposure[rt.App]; ok {
		item.Exposure, item.ExposureWhy = x.Rank, x.Why
	}
	if rt.Chromium == "" {
		item.Note = "Couldn't read its Chromium version, so its bundled browser engine wasn't checked"
		r.sources = append(r.sources, snapshot.Source{Name: rt.App, Status: "failed", Detail: "no Chromium version found"})
		return item, nil
	}
	byBug := db.ByBug()
	var backports map[string]bool
	var v8, released string
	var found []snapshot.Finding
	confirmed := map[string]bool{}
	if rt.Kind == collect.KindElectron {
		var err error
		backports, err = resolve.LineBackports(ctx, r.Cache, e, rt.Electron, byBug)
		if err != nil {
			r.sources = append(r.sources, snapshot.Source{Name: rt.App + " backport notes", Status: "failed", Detail: err.Error()})
		}
		if rel, ok := e.Find(rt.Electron); ok {
			v8, released = rel.V8, rel.Date
		}
		if len(e.Releases) > 0 && !e.Supported(rt.Electron) {
			item.Unsupported = true
			item.Note = "Electron " + strings.SplitN(rt.Electron, ".", 2)[0] + " is out of support: no more fixes on this line"
		}
		found, confirmed = r.osvElectron(ctx, rt, kev)
	}
	merged, err := resolve.Merged(ctx, r.Cache, rt.Chromium, v8, released)
	if err != nil {
		r.sources = append(r.sources, snapshot.Source{
			Name: rt.App + " branch history", Status: "failed",
			Detail: "some fixes on its branch may be counted as missing: " + err.Error(),
		})
	}
	for id, c := range db.CVEs {
		if c.FixedIn(rt.Chromium) || backports[id] || (c.Bug != "" && merged[c.Bug]) || confirmed[id] {
			continue
		}
		found = append(found, snapshot.Finding{
			CVE: id, App: rt.App, Label: snapshot.Inferred, Severity: c.Severity, Title: c.Component,
			KEV: kev[id], FixedIn: c.FirstFix(), Date: c.First, URL: c.URL,
			Absent: rt.Kind == collect.KindElectron && resolve.BrowserOnly(c.Component),
			Evidence: fmt.Sprintf("Its Chromium %s is older than the fix (%s), with no sign of the fix in Electron's notes or the branch history. An upper bound: the bug may not exist in code this old.",
				rt.Chromium, c.FirstFix()),
		})
	}
	return item, found
}

type osvVuln struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Published string   `json:"published"`
	DB        struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// nextFix is the lowest fixed version above v, preferring v's own major.
func (o osvVuln) nextFix(v string) string {
	var fixes []string
	for _, a := range o.Affected {
		for _, rg := range a.Ranges {
			for _, ev := range rg.Events {
				if ev.Fixed != "" && !strings.Contains(ev.Fixed, "-") && resolve.CompareVersions(ev.Fixed, v) > 0 {
					fixes = append(fixes, ev.Fixed)
				}
			}
		}
	}
	slices.SortFunc(fixes, resolve.CompareVersions)
	m := strings.SplitN(v, ".", 2)[0]
	for _, f := range fixes {
		if strings.SplitN(f, ".", 2)[0] == m {
			return f
		}
	}
	if len(fixes) > 0 {
		return fixes[0]
	}
	return ""
}

func (r *run) osvElectron(ctx context.Context, rt collect.Runtime, kev map[string]bool) ([]snapshot.Finding, map[string]bool) {
	name := "osv/electron-" + fetch.SafeName(rt.Electron) + ".json"
	body := fmt.Sprintf(`{"package":{"name":"electron","ecosystem":"npm"},"version":%q}`, rt.Electron)
	res, err := r.Cache.CachedPost(ctx, name, 24*time.Hour, "https://api.osv.dev/v1/query", []byte(body))
	var parsed struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err == nil {
		err = json.Unmarshal(res.Body, &parsed)
	}
	r.cachedSource("OSV: Electron "+rt.Electron, res, err, fmt.Sprintf("%d advisories", len(parsed.Vulns)))
	var found []snapshot.Finding
	confirmed := map[string]bool{}
	for _, v := range parsed.Vulns {
		id := v.ID
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				id = a
			}
			confirmed[a] = true
		}
		confirmed[v.ID] = true
		date := v.Published
		if len(date) > 10 {
			date = date[:10]
		}
		found = append(found, snapshot.Finding{
			CVE: id, App: rt.App, Label: snapshot.Confirmed, Severity: normalSeverity(v.DB.Severity), Title: v.Summary,
			KEV: kev[id], FixedIn: v.nextFix(rt.Electron), Date: date, URL: "https://osv.dev/vulnerability/" + v.ID,
			Evidence: "An advisory lists Electron " + rt.Electron + " as affected.",
		})
	}
	return found, confirmed
}

func normalSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "Critical"
	case "HIGH":
		return "High"
	case "MODERATE", "MEDIUM":
		return "Medium"
	case "LOW":
		return "Low"
	}
	return "Unrated"
}

var moduleToken = regexp.MustCompile(`\w+::\w+`)

// foreignAdvisory: the advisory names another ecosystem's module and never the formula itself, like a
// Perl XS::libbrotli CVE matched to the brotli formula. A text heuristic until matchers compare the
// advisory's package; it marks the finding Doubtful, and hides it unless asked for.
func foreignAdvisory(formula, summary string) bool {
	whole, err := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(formula) + `\b`)
	if err != nil {
		return false
	}
	return moduleToken.MatchString(summary) && !whole.MatchString(summary)
}

func (r *run) brew(ctx context.Context, kev map[string]bool) ([]snapshot.Item, []snapshot.Finding) {
	r.say("brew vulns")
	report, err := r.Brew(ctx)
	detail := fmt.Sprintf("%d formulae checked, %d skipped; formulae only, not casks", report.Checked, len(report.Skipped))
	r.source("Homebrew", err, detail)
	if err != nil {
		return nil, nil
	}
	listening := r.Listening(ctx)
	var items []snapshot.Item
	var found []snapshot.Finding
	for _, f := range report.Findings {
		item := snapshot.Item{App: f.Formula, Kind: "homebrew", Version: f.Version, AppVersion: f.Version, Exposure: 1, ExposureWhy: "A command-line tool or library; not listening on a port"}
		if listening[f.Formula] {
			item.Exposure, item.ExposureWhy, item.Running = 3, "Listening on a TCP port", true
		}
		items = append(items, item)
		for _, v := range f.Vulnerabilities {
			id := v.ID
			for _, a := range v.Aliases {
				if strings.HasPrefix(a, "CVE-") {
					id = a
				}
			}
			fi := snapshot.Finding{
				CVE: id, App: f.Formula, Label: snapshot.Confirmed, Severity: normalSeverity(v.Severity), Title: v.Summary,
				KEV: kev[id], URL: "https://osv.dev/vulnerability/" + v.ID,
				Evidence: "brew vulns matched an advisory to " + f.Formula + " " + f.Version + ".",
			}
			if foreignAdvisory(f.Formula, v.Summary) {
				fi.Label, fi.Absent = snapshot.Doubtful, true
				fi.Evidence = "brew vulns matched this to " + f.Formula + ", but the advisory seems to describe another project's module."
			}
			found = append(found, fi)
		}
	}
	return items, found
}

// scoreEPSS scores where it can change the order: known exploited, Critical, and anything confirmed.
func (r *run) scoreEPSS(ctx context.Context, found []snapshot.Finding) {
	want := map[string]bool{}
	for _, f := range found {
		if strings.HasPrefix(f.CVE, "CVE-") && (f.KEV || f.Severity == "Critical" || f.Label == snapshot.Confirmed) {
			want[f.CVE] = true
		}
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, cmp.Compare[string])
	scores := map[string]float64{}
	var firstErr error
	for i := 0; i < len(ids); i += 100 {
		batch := ids[i:min(i+100, len(ids))]
		sum := sha256.Sum256([]byte(strings.Join(batch, ",")))
		res, err := r.Cache.Cached(ctx, "epss/"+hex.EncodeToString(sum[:8])+".json", 24*time.Hour,
			"https://api.first.org/data/v1/epss?limit=100&cve="+strings.Join(batch, ","))
		if err != nil {
			firstErr = err
			break
		}
		var page struct {
			Data []struct {
				CVE  string  `json:"cve"`
				EPSS float64 `json:"epss,string"`
			} `json:"data"`
		}
		if err := json.Unmarshal(res.Body, &page); err != nil {
			firstErr = err
			break
		}
		for _, d := range page.Data {
			scores[d.CVE] = d.EPSS
		}
	}
	for i := range found {
		if s, ok := scores[found[i].CVE]; ok {
			found[i].EPSS, found[i].HasEPSS = s, true
		}
	}
	r.source("EPSS scores", firstErr, fmt.Sprintf("%d of %d scored", len(scores), len(ids)))
}
