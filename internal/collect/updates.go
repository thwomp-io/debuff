package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Pending is an update a package tool reports for something that isn't an app with a version to compare.
type Pending struct {
	Name, Installed, Latest string
	Restart                 bool
}

// FormulaName is what a formula may be called, tap-qualified or not. It can't start with a dash, so it can't
// read as a flag when it's later handed to brew.
var FormulaName = regexp.MustCompile(`^[a-z0-9][a-zA-Z0-9@+._/-]*$`)

// BrewPath finds Homebrew by path, which keeps it working under launchd's small PATH.
func BrewPath() string {
	const arm = "/opt/homebrew/bin/brew"
	if _, err := os.Stat(arm); err == nil {
		return arm
	}
	return "/usr/local/bin/brew"
}

// ParseOutdated reads `brew outdated --json=v2`. A pinned formula won't upgrade, so a button for it would only
// fail, and a name that doesn't look like a formula is left out rather than passed along.
func ParseOutdated(b []byte) ([]Pending, error) {
	var r struct {
		Formulae []struct {
			Name      string   `json:"name"`
			Installed []string `json:"installed_versions"`
			Current   string   `json:"current_version"`
			Pinned    bool     `json:"pinned"`
		} `json:"formulae"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	var out []Pending
	for _, f := range r.Formulae {
		if f.Pinned || f.Current == "" || !FormulaName.MatchString(f.Name) {
			continue
		}
		p := Pending{Name: f.Name, Latest: f.Current}
		if n := len(f.Installed); n > 0 {
			p.Installed = f.Installed[n-1]
		}
		out = append(out, p)
	}
	return out, nil
}

// Outdated lists formulae with a newer version. It reads Homebrew's local copy of the catalog, so it can trail
// by as long as Homebrew's last update; an upgrade refreshes that first.
func Outdated(ctx context.Context) ([]Pending, error) {
	// #nosec G204 -- a fixed tool at a fixed path, with fixed arguments
	out, err := exec.CommandContext(ctx, BrewPath(), "outdated", "--formula", "--json=v2").Output()
	if err != nil {
		return nil, fmt.Errorf("brew outdated: %w", err)
	}
	return ParseOutdated(out)
}

var softwareUpdateLine = regexp.MustCompile(`Title: (.+?), Version: ([^,]+),(.*)`)

// ParseSoftwareUpdates reads `softwareupdate --list`, which has no structured output.
func ParseSoftwareUpdates(s string) []Pending {
	var out []Pending
	for _, line := range strings.Split(s, "\n") {
		m := softwareUpdateLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, Pending{Name: m[1], Latest: strings.TrimSpace(m[2]), Restart: strings.Contains(m[3], "Action: restart")})
	}
	return out
}

// SystemUpdates lists what Software Update has found. --no-scan reads the result of the system's own background
// check, which takes about 2 seconds where a fresh one takes far longer and would slow every rescan.
func SystemUpdates(ctx context.Context) ([]Pending, error) {
	out, err := exec.CommandContext(ctx, "/usr/sbin/softwareupdate", "--list", "--no-scan").Output()
	if err != nil {
		return nil, fmt.Errorf("softwareupdate: %w", err)
	}
	list := ParseSoftwareUpdates(string(out))
	if v, err := exec.CommandContext(ctx, "/usr/bin/sw_vers", "-productVersion").Output(); err == nil {
		for i := range list {
			if strings.HasPrefix(list[i].Name, "macOS") {
				list[i].Installed = strings.TrimSpace(string(v))
			}
		}
	}
	return list, nil
}
