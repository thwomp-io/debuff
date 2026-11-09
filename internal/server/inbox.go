package server

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/thwomp-io/debuff/internal/resolve"
	"github.com/thwomp-io/debuff/internal/snapshot"
)

// Row is one finding: the critical facts at a glance, the long text on click. Everything here may come
// from advisories or changelogs, so it only ever reaches the page through html/template's escaping.
type Row struct {
	KEV                       bool
	Severity, App, CVE, Title string
	Label, EPSS, FixedIn      string
	Date, Description         string
	Evidence, URL             string
	EPSSScore                 float64 // the number behind EPSS, for ordering
	Absent                    bool    // probably doesn't apply here; hidden unless asked for
	Sort                      string  // the date as YYYY-MM-DD; display dates don't order
}

// AppFacts is what the scan learned about an app, apart from its findings.
type AppFacts struct {
	CVESource            string // what findings were checked against; empty when nothing could
	Icon                 string // the content hash of its icon; empty shows a letter
	Latest, Update       string // the latest version Homebrew lists, and how this one compares; empty when unknown
	Kind, Stack, Runtime string // Stack is the version scanned: Electron's, or the formula's
	Version              string // the app's own
	LastOpened, Updated  string // YYYY-MM-DD; empty when unknown
	Why, Note            string
	Exposure             int // how much untrusted content it handles; higher is worse
	Running, Unsupported bool
	Path                 string // its bundle; empty when there's nothing to open
	AppStore             bool   // the App Store is the only thing that updates it
}

// The kinds with a line of their own on a card.
const (
	kindElectron  = "electron"
	kindBrowser   = "agent browser"
	kindHomebrew  = "homebrew"
	kindApp       = "app"
	kindAgentTool = "agent tool"
)

// severityRank orders severities. An unrated finding counts as Medium: unknown isn't harmless, and it
// shouldn't outrank findings someone actually assessed either. Sources spell Medium as Moderate too.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "low":
		return 1
	}
	return 2
}

// SeverityClass picks a CSS class from a closed set, whatever the source's text says.
func (r Row) SeverityClass() string {
	switch severityRank(r.Severity) {
	case 4:
		return "critical"
	case 3:
		return "high"
	}
	return "other"
}

// Card is one app: what it is, how much is open, and its findings. The action is usually per app,
// update or remove, so the app is the unit of the page and a CVE is a detail inside it.
type Card struct {
	App                              string
	Facts                            AppFacts
	Labels, TopEPSS, Behind, AllHref string
	Count, Exploited, ExploitedSure  int
	Critical, High                   int
	Change                           CardChange
	Rows                             []Row
	score                            float64
}

// Name is the app without its bundle suffix.
func (c Card) Name() string { return strings.TrimSuffix(c.App, ".app") }

// Letter stands in for an icon on anything that doesn't ship one, like a Homebrew formula.
func (c Card) Letter() string {
	for _, r := range c.Name() {
		return strings.ToUpper(string(r))
	}
	return "?"
}

// StateKnown: a formula that isn't listening isn't "not running" in any way worth saying.
func (c Card) StateKnown() bool {
	switch c.Facts.Kind {
	case kindElectron, kindBrowser, kindApp:
		return true
	}
	return c.Facts.Running
}

// Status says whether it's running, and when it last was if not. A running app was opened, so that would say
// nothing. An unknown last-opened is said out loud on an app, since Spotlight having no record isn't "never".
func (c Card) Status() string {
	if !c.StateKnown() {
		return ""
	}
	if c.Facts.Running {
		return "Running"
	}
	if c.Facts.Kind != kindElectron && c.Facts.Kind != kindApp {
		return "Not running"
	}
	if c.Facts.LastOpened == "" {
		return "Not running, last opened unknown"
	}
	return "Not running, last opened " + dayOrMonth(c.Facts.LastOpened, time.Now())
}

// Updated is when the bundle last changed.
func (c Card) Updated() string {
	if c.Facts.Updated == "" {
		return ""
	}
	return monthYear(c.Facts.Updated)
}

// Checked says whether anything could look for CVEs in this. A listing with no source must not read as clean.
func (c Card) Checked() bool {
	switch c.Facts.Kind {
	case kindElectron, kindBrowser, kindHomebrew:
		return true
	}
	return c.Facts.CVESource != ""
}

// Caveat is a note worth showing that the out-of-support tag doesn't already say.
func (c Card) Caveat() string {
	if c.Facts.Unsupported {
		return ""
	}
	return c.Facts.Note
}

// UpdateAvailable: Homebrew lists a newer version than this one.
func (c Card) UpdateAvailable() bool { return c.Facts.Update == resolve.UpdateAvailable }

// Current: this is what Homebrew lists as newest, which can lag the vendor.
func (c Card) Current() bool { return c.Facts.Update == resolve.UpdateCurrent }

// UpdateUnknown: nothing could say, which must not read as up to date.
func (c Card) UpdateUnknown() bool { return c.Facts.Update == "" && c.Facts.Kind != "" }

// BuiltOn names the runtime it carries.
func (c Card) BuiltOn() string {
	major, _, _ := strings.Cut(c.Facts.Runtime, ".")
	switch c.Facts.Kind {
	case kindElectron:
		if major != "" {
			return "Electron " + c.Facts.Stack + ", Chromium " + major
		}
		return "Electron " + c.Facts.Stack
	case kindBrowser:
		if major != "" {
			return "Chromium " + major
		}
	case kindHomebrew:
		return "Homebrew formula"
	}
	return ""
}

func dayOrMonth(date string, now time.Time) string {
	t, err := time.ParseInLocation(time.DateOnly, date, now.Location())
	switch {
	case err != nil:
		return date
	case t.Format(time.DateOnly) == now.Format(time.DateOnly):
		return "today"
	case t.Year() == now.Year():
		return t.Format("Jan 2")
	}
	return t.Format("Jan 2006")
}

func monthYear(date string) string {
	t, err := time.Parse(time.DateOnly, date)
	if err != nil {
		return date
	}
	return t.Format("Jan 2006")
}

// others is everything scanned that has no card at this setting: most of a machine. Anything with an update
// comes first, since that's the one thing to do about it.
func others(apps map[string]AppFacts, cards []Card) []Card {
	carded := map[string]bool{}
	for _, c := range cards {
		carded[c.App] = true
	}
	var out []Card
	for name, facts := range apps {
		if !carded[name] {
			out = append(out, Card{App: name, Facts: facts})
		}
	}
	slices.SortFunc(out, func(a, b Card) int {
		if a.UpdateAvailable() != b.UpdateAvailable() {
			if a.UpdateAvailable() {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(a.Name()), strings.ToLower(b.Name()))
	})
	return out
}

// oldestOpen is each app's oldest open fix: how long it has trailed. It describes the app, so it reads
// every finding whatever the severity setting, except those that probably don't apply here.
func oldestOpen(rows []Row) map[string]string {
	out := map[string]string{}
	for _, r := range rows {
		if r.Sort == "" || (r.Absent && !r.KEV) {
			continue
		}
		if cur, ok := out[r.App]; !ok || r.Sort < cur {
			out[r.App] = r.Sort
		}
	}
	return out
}

// cards groups rows by app. Most urgent first: known exploited, then exposure, EPSS, severity.
func cards(rows []Row, apps map[string]AppFacts) []Card {
	var out []Card
	index := map[string]int{}
	for _, r := range rows {
		i, ok := index[r.App]
		if !ok {
			i = len(out)
			index[r.App] = i
			out = append(out, Card{App: r.App, Facts: apps[r.App]})
		}
		c := &out[i]
		c.Rows = append(c.Rows, r)
		c.Count++
		switch severityRank(r.Severity) {
		case 4:
			c.Critical++
		case 3:
			c.High++
		}
		if r.KEV {
			c.Exploited++
			if r.Label == "Confirmed" {
				c.ExploitedSure++
			}
		}
		if r.EPSS != "" && r.EPSSScore >= c.score {
			c.score, c.TopEPSS = r.EPSSScore, r.EPSS
		}
	}
	for i := range out {
		c := &out[i]
		slices.SortStableFunc(c.Rows, compareRows)
		c.Labels = labelSummary(c.Rows)
	}
	slices.SortStableFunc(out, func(a, b Card) int {
		switch {
		case (a.Exploited > 0) != (b.Exploited > 0):
			if a.Exploited > 0 {
				return -1
			}
			return 1
		case a.Facts.Exposure != b.Facts.Exposure:
			return b.Facts.Exposure - a.Facts.Exposure
		case a.score != b.score:
			if a.score > b.score {
				return -1
			}
			return 1
		}
		return b.Critical - a.Critical
	})
	return out
}

func compareRows(a, b Row) int {
	switch {
	case a.KEV != b.KEV:
		if a.KEV {
			return -1
		}
		return 1
	case severityRank(a.Severity) != severityRank(b.Severity):
		return severityRank(b.Severity) - severityRank(a.Severity)
	case a.EPSSScore > b.EPSSScore:
		return -1
	case a.EPSSScore < b.EPSSScore:
		return 1
	}
	return 0
}

func labelSummary(rows []Row) string {
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Label]++
	}
	if len(counts) == 1 {
		return rows[0].Label
	}
	var parts []string
	for _, l := range []string{"Confirmed", "Inferred", "Doubtful"} {
		if counts[l] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[l], strings.ToLower(l)))
		}
	}
	return strings.Join(parts, " · ")
}

// viewDef is one entry in the left panel.
type viewDef struct {
	key, name string
	match     func(Row) bool
}

var views = []viewDef{
	{"inbox", "Inbox", func(Row) bool { return true }},
	{"exploited", "Known exploited", func(r Row) bool { return r.KEV }},
	{"confirmed", "Confirmed", func(r Row) bool { return r.Label == "Confirmed" }},
}

// severityFilter is one setting of the severity toggle.
type severityFilter struct {
	key, name, note string
	floor           int
}

// The default hides Medium and Low: on a real machine they're most of the volume. Whatever the
// setting, a known-exploited finding always shows; some are rated only Medium.
var severityFilters = []severityFilter{
	{"critical", "Critical", "Critical only", 4},
	{"high", "High+", "High and above", 3},
	{"medium", "Medium+", "Medium and above", 2},
	{"all", "All", "", 1},
}

const defaultFilter = "high"

func (f severityFilter) keeps(r Row) bool {
	if r.KEV || f.key == "all" {
		return true
	}
	return !r.Absent && severityRank(r.Severity) >= f.floor
}

func link(view, filter, app string) string {
	q := url.Values{}
	if view != views[0].key {
		q.Set("view", view)
	}
	if filter != defaultFilter {
		q.Set("min", filter)
	}
	if app != "" {
		q.Set("app", app)
	}
	if len(q) == 0 {
		return "/"
	}
	return "/?" + q.Encode()
}

// Past this the page says it may be out of date: a daily scan has missed more than one run.
const staleAfter = 36 * time.Hour

// A card scrolls through its most urgent rows and links to the rest: a page holding every row of every
// app would be megabytes on a real machine.
const rowsPerCard = 100

// navItem is a link as the template renders it, in the left panel or the severity toggle.
type navItem struct {
	Name, Href string
	Count      int
	Current    bool
}

type pageData struct {
	Title, Version                         string
	Demo, Scanned                          bool
	ScannedAt                              string
	Degraded                               []string
	BackHref                               string
	Views, Filters                         []navItem
	Cards                                  []Card
	Hidden                                 int
	FilterNote, ShowAll                    string
	EmptyTitle, EmptyBody                  string
	CurrentView, CurrentFilter, CurrentApp string
	StaleSince                             string
	Checked, Unchecked                     []Card
	CanScan, Scanning                      bool
	ScanStarted, ScanFailure               string
	Change                                 *Change
	OnUpdates, CanAct                      bool
	Updates                                []UpdateRow
	StoreApps, UnknownApps                 []string
	Upgrading, UpgradeDone, PressFailure   string
	FormulaCount                           int
	UpgradingNames                         []string
}

// buildPage applies the requested view and severity floor. Unknown values fall back to the defaults,
// never an error page. Counts reflect the filter, and Hidden says what it took out.
func buildPage(version, requested, floor, app string, demo bool, v View) pageData {
	rows := v.Rows
	current := views[0]
	for _, v := range views {
		if v.key == requested {
			current = v
		}
	}
	filter := severityFilters[1]
	for _, f := range severityFilters {
		if f.key == floor {
			filter = f
		}
	}
	d := pageData{
		CurrentView: current.key, CurrentFilter: filter.key, CurrentApp: app,
		Title: current.name, Version: version, Demo: demo, FilterNote: filter.note,
		ShowAll: link(current.key, "all", app), Scanned: v.Scanned, Degraded: v.Degraded,
	}
	if v.Scanned {
		d.ScannedAt = v.ScannedAt.Local().Format("Jan 2, 3:04 PM")
	}
	if app != "" {
		d.Title, d.BackHref = strings.TrimSuffix(app, ".app"), link(current.key, filter.key, "")
	}
	for _, vd := range views {
		n := 0
		for _, r := range rows {
			if vd.match(r) && filter.keeps(r) {
				n++
			}
		}
		d.Views = append(d.Views, navItem{Name: vd.name, Href: link(vd.key, filter.key, ""), Count: n, Current: vd.key == current.key && app == ""})
	}
	updates := updateRows(v)
	onUpdates := requested == updatesView && app == ""
	d.Views = slices.Insert(d.Views, 1, navItem{Name: "Updates", Href: link(updatesView, filter.key, ""), Count: len(updates), Current: onUpdates})
	if onUpdates {
		d.Views[0].Current = false
		d.OnUpdates, d.Updates, d.Title, d.CurrentView = true, updates, "Updates", updatesView
		d.FormulaCount = formulaCount(updates)
		d.StoreApps, d.UnknownApps = notListed(v)
		if v.Scanned && !demo && time.Since(v.ScannedAt) > staleAfter {
			d.StaleSince = v.ScannedAt.Local().Format("Jan 2, 3:04 PM")
		}
		d.EmptyTitle = "Nothing has an update"
		d.EmptyBody = "Among what could be checked. That isn't the same as safe: an app can have open findings and no update yet."
		if !v.Scanned && !demo {
			d.EmptyTitle = "Nothing scanned yet"
			d.EmptyBody = "No updates here means no scan has run."
		}
		return d
	}
	for _, f := range severityFilters {
		d.Filters = append(d.Filters, navItem{Name: f.name, Href: link(current.key, f.key, app), Current: f.key == filter.key})
	}
	var shown []Row
	for _, r := range rows {
		if !current.match(r) || (app != "" && r.App != app) {
			continue
		}
		if filter.keeps(r) {
			shown = append(shown, r)
		} else {
			d.Hidden++
		}
	}
	d.Cards = cards(shown, v.Apps)
	var changes map[string]CardChange
	if v.Previous != nil {
		keep := func(r Row) bool {
			return current.match(r) && (app == "" || r.App == app) && filter.keeps(r)
		}
		var c Change
		c, changes = compare(v.Previous, shown, v.Apps, keep)
		if !v.UnchangedSince.IsZero() {
			c.Unchanged = v.UnchangedSince.Local().Format("Jan 2, 3:04 PM")
		}
		d.Change = &c
	} else if !v.UnchangedSince.IsZero() {
		d.Change = &Change{Since: v.UnchangedSince.Local().Format("Jan 2, 3:04 PM")}
	}
	if v.Scanned && !demo && time.Since(v.ScannedAt) > staleAfter {
		d.StaleSince = v.ScannedAt.Local().Format("Jan 2, 3:04 PM")
	}
	oldest := oldestOpen(rows)
	for i := range d.Cards {
		c := &d.Cards[i]
		if o := oldest[c.App]; o != "" {
			c.Behind = monthYear(o)
		}
		c.AllHref = link(current.key, filter.key, c.App)
		c.Change = changes[c.App]
		if app == "" && len(c.Rows) > rowsPerCard {
			c.Rows = c.Rows[:rowsPerCard]
		}
	}
	if requested == views[0].key || requested == "" {
		if app == "" {
			for _, o := range others(v.Apps, d.Cards) {
				if o.Checked() {
					d.Checked = append(d.Checked, o)
				} else {
					d.Unchecked = append(d.Unchecked, o)
				}
			}
		}
	}
	switch {
	case !v.Scanned && !demo:
		// Honest coverage: an empty inbox must never read as a clean bill of health.
		d.EmptyTitle = "Nothing scanned yet"
		d.EmptyBody = "No findings here means no scan has run. It doesn't mean this machine is safe."
	case len(rows) == 0:
		d.EmptyTitle = "Nothing found in what was scanned"
		d.EmptyBody = "That isn't the same as safe: only what this scan covers was checked."
	default:
		d.EmptyTitle = "Nothing in this view"
		d.EmptyBody = "Other views or a wider severity setting may still have findings."
	}
	return d
}

// DemoApps is made-up facts to go with DemoRows.
func DemoApps() map[string]AppFacts {
	return map[string]AppFacts{
		"Example Mail": {
			Kind: kindElectron, Stack: "30.1.0", Runtime: "120.0.0.1", Version: "2.4.0", Updated: "2024-03-10", Latest: "2.6.1", Update: resolve.UpdateAvailable, Path: "/Applications/Example Mail.app",
			Why: "Renders inbound email", Exposure: 3, Unsupported: true, Note: "Electron 30 is out of support: no more fixes on this line",
		},
		"Example Chat": {
			Kind: kindElectron, Stack: "33.0.0", Runtime: "118.0.0.1", Version: "7.1.2", LastOpened: "2024-05-02", Updated: "2024-05-01", Latest: "7.1.2", Update: resolve.UpdateCurrent,
			Why: "Renders inbound messages", Exposure: 3,
		},
		"Example Notes": {
			Kind: kindElectron, Stack: "39.0.0", Runtime: "139.0.0.1", Version: "1.0.3", Updated: "2024-04-20",
			Why: "Mostly local content", Exposure: 2, Running: true,
		},
		"Example Editor": {
			Kind: kindApp, Stack: "4.2.0", Version: "4.2.0", LastOpened: "2024-05-02", Latest: "4.3.0", Update: resolve.UpdateAvailable, Exposure: 2, Path: "/Applications/Example Editor.app",
		},
		"Example Slides": {Kind: kindApp, Stack: "15.1", Version: "15.1", AppStore: true, Exposure: 1},
		"Example Clock":  {Kind: kindApp, Stack: "2.0", Version: "2.0", Exposure: 1},
		"Example Agent":  {Kind: kindAgentTool, Stack: "1.5.0", Version: "1.5.0", Why: "Agent CLI: runs commands and reads files on your behalf", CVESource: "OSV", Exposure: 3},
		"MCP: example":   {Kind: kindAgentTool, Why: "MCP server: an agent calls it, and acts on what it returns", Note: "Unpinned: runs whatever is newest each time it starts", Exposure: 3},
		"exampletool": {
			Kind: kindHomebrew, Stack: "2.5.4", Version: "2.5.4",
			Why: "Local files only; not running", Exposure: 1,
		},
	}
}

// DemoPending is made-up updates from the package tools.
func DemoPending() []snapshot.Pending {
	return []snapshot.Pending{
		{Name: "exampletool", Installed: "2.5.4", Latest: "2.5.5", Via: snapshot.ViaHomebrew},
		{Name: "examplelib", Installed: "1.0.0", Latest: "1.0.1", Via: snapshot.ViaHomebrew},
		{Name: "Example OS 12.1", Installed: "12.0", Latest: "12.1", Via: snapshot.ViaSystem, Restart: true},
	}
}

// DemoPrevious is a made-up scan before DemoRows, so the page can show what changed.
func DemoPrevious() *Previous {
	rows := append(DemoRows(), Row{
		Severity: "Critical", App: "Example Chat", CVE: "CVE-0000-0009", Title: "A sample finding the latest scan closed",
		Label: "Inferred",
	}, Row{
		Severity: "High", App: "Example Recorder", CVE: "CVE-0000-0010", Title: "A sample finding in an app since removed",
		Label: "Inferred",
	})
	apps := DemoApps()
	chat := apps["Example Chat"]
	chat.Version = "7.1.0"
	apps["Example Chat"] = chat
	apps["Example Recorder"] = AppFacts{Kind: kindElectron}
	return &Previous{Rows: rows, Apps: apps, ScannedAt: time.Date(2024, 10, 1, 8, 30, 0, 0, time.Local)}
}

// DemoMany is sample data at a real machine's size: long lists are where a layout breaks. Only `serve --demo`
// reaches it, through ?sample=many.
func DemoMany() ([]Row, map[string]AppFacts) {
	apps := map[string]AppFacts{}
	var rows []Row
	for i, name := range []string{"Example Mail", "Example Chat", "Example Notes", "Example Vault", "Example Recorder", "Example Browser"} {
		apps[name] = AppFacts{
			Kind: kindElectron, Stack: "30.1.0", Runtime: "120.0.0.1", Version: "2.4.0", Updated: "2024-03-10",
			Why: "Renders inbound email", Exposure: 3 - i%3, Unsupported: i%2 == 0, Note: "Out of support", Latest: "2.6.1", Update: resolve.UpdateAvailable,
		}
		for n := range 150 {
			rows = append(rows, Row{
				KEV: n < 3 && i < 4, Severity: []string{"Critical", "High", "High"}[n%3], App: name,
				CVE: fmt.Sprintf("CVE-0000-%d%03d", i, n), Title: "A sample finding in an example component", Label: "Inferred",
				EPSS: "<1%", EPSSScore: 0.001, FixedIn: "120.0.1", Date: "Oct 29", Sort: "2024-10-29", Evidence: "A sample reason.",
			})
		}
	}
	return rows, apps
}

// DemoRows is made-up data for looking at the layout. It reaches the page only under `serve --demo`,
// which shows a banner saying so. Names and identifiers are fictional on purpose.
func DemoRows() []Row {
	const (
		bundled = "The bundled runtime is older than the first release containing the fix, and no backport appears in its release notes or branch history."
		listed  = "An advisory lists the installed version as affected."
	)
	return []Row{
		{
			KEV: true, Severity: "Medium", App: "Example Mail", CVE: "CVE-0000-0001", Title: "Out of bounds write in an example engine",
			Label: "Inferred", EPSS: "55%", EPSSScore: 0.55, FixedIn: "120.0.1", Date: "Oct 29", Sort: "2024-10-29", Evidence: bundled,
			Description: "A sample long description. It sits behind the click, along with a changelog excerpt, so the row stays one line however long the advisory runs. This one is only rated Medium but is known to be exploited, so the severity filter never hides it.",
		},
		{
			Severity: "Critical", App: "Example Mail", CVE: "CVE-0000-0005", Title: "Use after free in an example renderer",
			Label: "Inferred", EPSS: "3%", EPSSScore: 0.03, FixedIn: "120.0.1", Date: "Oct 27", Sort: "2024-10-27", Evidence: bundled,
			Description: "A sample description for a critical finding nobody is known to be exploiting.",
		},
		{
			Severity: "High", App: "Example Mail", CVE: "CVE-0000-0006", Title: "Memory corruption in an example decoder",
			Label: "Confirmed", EPSS: "1%", EPSSScore: 0.01, FixedIn: "119.4.0", Date: "Oct 13", Sort: "2024-10-13", Evidence: listed,
			Description: "A sample description for a finding where an advisory names this exact version.",
		},
		{
			Severity: "Low", App: "Example Mail", CVE: "CVE-0000-0007", Title: "Incorrect security UI in an example dialog",
			Label: "Inferred", EPSS: "<1%", EPSSScore: 0.001, FixedIn: "118.0.2", Date: "Sep 30", Sort: "2024-09-30", Evidence: bundled,
			Description: "A sample low-severity finding, hidden until the filter is widened.",
		},
		{
			Severity: "Critical", App: "Example Chat", CVE: "CVE-0000-0002", Title: "Memory corruption in an example parser",
			Label: "Inferred", EPSS: "1%", EPSSScore: 0.01, FixedIn: "118.2.0", Date: "Oct 27", Sort: "2024-10-27", Evidence: bundled,
			Description: "A sample description for a critical finding in an app that handles untrusted messages.",
		},
		{
			Severity: "Medium", App: "Example Chat", CVE: "CVE-0000-0008", Title: "Policy bypass in an example loader",
			Label: "Inferred", EPSS: "<1%", EPSSScore: 0.002, FixedIn: "118.1.0", Date: "Oct 6", Sort: "2024-10-06", Evidence: bundled,
			Description: "A sample medium-severity finding, hidden until the filter is widened.",
		},
		{
			Severity: "High", App: "Example Notes", CVE: "CVE-0000-0003", Title: "Cookie restrictions not applied to opened windows",
			Label: "Confirmed", EPSS: "2%", EPSSScore: 0.02, FixedIn: "39.9.0", Date: "Oct 21", Sort: "2024-10-21", Evidence: listed,
			Description: "A sample description for a finding where an advisory names this exact version.",
		},
		{
			Severity: "Medium", App: "exampletool", CVE: "CVE-0000-0004", Title: "Out of bounds read when decoding a crafted file",
			Label: "Confirmed", EPSS: "<1%", EPSSScore: 0.003, FixedIn: "2.5.5", Date: "Oct 9", Sort: "2024-10-09", Evidence: listed,
			Description: "A sample description for a command-line tool that isn't running and doesn't listen on a port. Its whole card disappears at the default setting.",
		},
	}
}
