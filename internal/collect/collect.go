// Package collect finds what's installed that could carry a vulnerability. It only reads.
package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Runtime is one app or browser carrying its own Chromium.
type Runtime struct {
	App, Kind, Electron, Chromium, Path string
	Running                             bool
	Bundle                              BundleFacts
}

// BundleFacts is what an app's bundle says about itself. Each is empty when unknown.
type BundleFacts struct {
	ID                           string // CFBundleIdentifier
	Version, LastOpened, Updated string
	Icon                         []byte // a validated PNG, or nil
	AppStore                     bool   // installed from the Mac App Store, which is the only thing that updates it
}

// ReadBundle reads an app bundle's own version, when Spotlight last saw it opened, and when it last
// changed. The last is close to "last updated", but anything that touches the bundle moves it.
func ReadBundle(ctx context.Context, app string) BundleFacts {
	f := BundleFacts{
		Version: plistValue(ctx, filepath.Join(app, "Contents/Info.plist"), "CFBundleShortVersionString"),
		Icon:    ReadIcon(ctx, app),
		ID:      plistValue(ctx, filepath.Join(app, "Contents/Info.plist"), "CFBundleIdentifier"),
	}
	if fi, err := os.Stat(app); err == nil {
		f.Updated = fi.ModTime().Format(time.DateOnly)
	}
	if _, err := os.Stat(filepath.Join(app, "Contents/_MASReceipt/receipt")); err == nil {
		f.AppStore = true
	}
	f.LastOpened = parseLastUsed(spotlight(ctx, app, "kMDItemLastUsedDate"), spotlight(ctx, app, "kMDItemUseCount"))
	return f
}

func spotlight(ctx context.Context, app, attribute string) string {
	// #nosec G204 -- a fixed tool, given a path it found under the apps folders
	out, err := exec.CommandContext(ctx, "/usr/bin/mdls", "-raw", "-name", attribute, app).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// parseLastUsed turns Spotlight's answer into a local date. With no use count there's no usage record,
// and the date is just the bundle's modified time (verified 2026-11-02), so a never-opened app would
// read as opened. No record doesn't mean never opened either, so that stays unknown.
func parseLastUsed(lastUsed, useCount string) string {
	if n, err := strconv.Atoi(useCount); err != nil || n < 1 {
		return ""
	}
	t, err := time.Parse("2006-01-02 15:04:05 -0700", lastUsed)
	if err != nil {
		return ""
	}
	return t.Local().Format(time.DateOnly)
}

// Kinds of runtime.
const (
	KindElectron = "electron"
	KindBrowser  = "agent browser"
)

var chromeStr = regexp.MustCompile(`Chrome/(\d+\.\d+\.\d+\.\d+)`)

func plistValue(ctx context.Context, path, key string) string {
	// #nosec G204 -- a fixed tool, given a path it found under the apps folders
	out, err := exec.CommandContext(ctx, "/usr/libexec/PlistBuddy", "-c", "Print :"+key, path).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Runtimes walks the apps folders for Electron frameworks and the Playwright browser cache. chromiumOf
// gives Electron's stated Chromium for a version; when it can't, the framework binary is read instead.
func Runtimes(ctx context.Context, home string, chromiumOf func(string) string) ([]Runtime, error) {
	ps, err := exec.CommandContext(ctx, "/bin/ps", "-axo", "command").Output()
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}
	var out []Runtime
	for _, root := range []string{"/Applications", filepath.Join(home, "Applications")} {
		for _, pattern := range []string{"*.app", "*/*.app"} {
			apps, err := filepath.Glob(filepath.Join(root, pattern))
			if err != nil {
				return nil, err
			}
			for _, app := range apps {
				fw := filepath.Join(app, "Contents/Frameworks/Electron Framework.framework")
				if _, err := os.Stat(fw); err != nil {
					continue
				}
				r := Runtime{
					App: filepath.Base(app), Kind: KindElectron, Path: app,
					Electron: plistValue(ctx, filepath.Join(fw, "Resources/Info.plist"), "CFBundleVersion"),
					Running:  strings.Contains(string(ps), app),
				}
				r.Bundle = ReadBundle(ctx, app)
				if r.Chromium = chromiumOf(r.Electron); r.Chromium == "" {
					r.Chromium = chromiumInBinary(filepath.Join(fw, "Electron Framework"))
				}
				out = append(out, r)
			}
		}
	}
	caches, err := filepath.Glob(filepath.Join(home, "Library/Caches/ms-playwright/chromium-*"))
	if err != nil {
		return nil, err
	}
	for _, c := range caches {
		pl, err := filepath.Glob(filepath.Join(c, "chrome-mac-*/*.app/Contents/Info.plist"))
		if err != nil || len(pl) == 0 {
			continue
		}
		out = append(out, Runtime{
			App: "Playwright " + filepath.Base(c), Kind: KindBrowser, Path: c,
			Chromium: plistValue(ctx, pl[0], "CFBundleShortVersionString"),
			Bundle:   BundleFacts{Icon: ReadIcon(ctx, filepath.Dir(filepath.Dir(pl[0])))},
		})
	}
	return out, nil
}

// App is an installed app with no bundled runtime this scan can resolve. Most of a machine's apps are like this.
type App struct {
	Name, Path string
	Running    bool
	Bundle     BundleFacts
}

// Apps lists every app in the apps folders except those skip names, which were already handled.
func Apps(ctx context.Context, home string, skip map[string]bool) ([]App, error) {
	ps, err := exec.CommandContext(ctx, "/bin/ps", "-axo", "command").Output()
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}
	var out []App
	for _, root := range []string{"/Applications", filepath.Join(home, "Applications")} {
		for _, pattern := range []string{"*.app", "*/*.app"} {
			apps, err := filepath.Glob(filepath.Join(root, pattern))
			if err != nil {
				return nil, err
			}
			for _, app := range apps {
				name := filepath.Base(app)
				if skip[name] {
					continue
				}
				out = append(out, App{Name: name, Path: app, Running: strings.Contains(string(ps), app+"/"), Bundle: ReadBundle(ctx, app)})
			}
		}
	}
	return out, nil
}

func chromiumInBinary(path string) string {
	b, err := os.ReadFile(path) // #nosec G304 -- a framework binary under the apps folders
	if err != nil {
		return ""
	}
	if m := chromeStr.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

// BrewVuln is one open advisory on a Homebrew formula.
type BrewVuln struct {
	ID, Severity, Summary string
	Aliases               []string
}

// BrewFormula is a formula with open advisories.
type BrewFormula struct {
	Formula, Version string
	Vulnerabilities  []BrewVuln `json:"vulnerabilities"`
}

// BrewReport is `brew vulns --json`, keeping its own account of what it covered.
type BrewReport struct {
	Findings []BrewFormula `json:"findings"`
	Checked  int           `json:"checked"`
	Complete bool          `json:"complete"`
	Skipped  []string      `json:"skipped_formulae"`
}

// ParseBrew reads the report. A formula with nothing open is dropped: brew lists formulae whose
// advisories Homebrew has already patched.
func ParseBrew(b []byte) (BrewReport, error) {
	var r BrewReport
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	open := r.Findings[:0]
	for _, f := range r.Findings {
		if len(f.Vulnerabilities) > 0 {
			open = append(open, f)
		}
	}
	r.Findings = open
	return r, nil
}

// Brew runs `brew vulns`.
func Brew(ctx context.Context) (BrewReport, error) {
	// #nosec G204 -- a fixed tool at a fixed path
	out, err := exec.CommandContext(ctx, BrewPath(), "vulns", "--json").Output()
	if len(out) == 0 && err != nil {
		return BrewReport{}, fmt.Errorf("brew vulns: %w", err)
	}
	return ParseBrew(out)
}

// Listening returns the commands holding a listening TCP port.
func Listening(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	// #nosec G204 -- fixed arguments
	b, err := exec.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fc").Output()
	if err != nil && len(b) == 0 {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "c") {
			out[line[1:]] = true
		}
	}
	return out
}

// Exposure is the operator's own read of how much untrusted content an app handles. It lives in the
// private data directory: the list of apps is itself the inventory, so it stays out of git.
type Exposure struct {
	Rank int    `json:"rank"`
	Why  string `json:"why"`
}

type exposureFile struct {
	Format int                 `json:"format"`
	Apps   map[string]Exposure `json:"apps"`
}

// LoadExposure reads the overlay. Missing is fine; an unknown format is an error.
func LoadExposure(dir string) (map[string]Exposure, error) {
	b, err := os.ReadFile(filepath.Join(dir, "exposure.json")) // #nosec G304 -- the operator's own data dir
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f exposureFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("exposure.json: %w", err)
	}
	if f.Format != 1 {
		return nil, fmt.Errorf("exposure.json has format %d; this binary reads format 1", f.Format)
	}
	return f.Apps, nil
}
