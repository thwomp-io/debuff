package resolve

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/thwomp-io/debuff/internal/fetch"
)

// The catalog is one shared file every Homebrew user reads, so asking it tells no vendor which apps are
// here, and it names versions for apps that weren't installed through Homebrew.
const catalogURL = "https://formulae.brew.sh/api/cask.json"

// Long enough to spare the server on repeat rescans, short enough that "latest" stays close to true.
const catalogTTL = 6 * time.Hour

var plainVersion = regexp.MustCompile(`^\d+(\.\d+)*$`)

// Catalog maps an app bundle's name to the latest version Homebrew lists for it.
type Catalog struct {
	latest map[string]string
	byCask map[string]string
}

// LoadCatalog fetches the catalog through the cache.
func LoadCatalog(ctx context.Context, c *fetch.Client) (Catalog, fetch.Result, error) {
	r, err := c.Cached(ctx, "homebrew/cask.json", catalogTTL, catalogURL)
	if err != nil {
		return Catalog{}, r, err
	}
	cat, err := ParseCatalog(r.Body)
	return cat, r, err
}

// ParseCatalog reads the catalog, which is untrusted. An app listed by more than one stable cask, or at a
// version that can't be compared, is left out: that makes it unknown, never a wrong answer. Variants such as
// foo@beta aren't what's installed from the stable channel, so they don't count.
func ParseCatalog(b []byte) (Catalog, error) {
	var casks []struct {
		Token     string            `json:"token"`
		Version   string            `json:"version"`
		Artifacts []json.RawMessage `json:"artifacts"`
	}
	if err := json.Unmarshal(b, &casks); err != nil {
		return Catalog{}, err
	}
	cat := Catalog{latest: map[string]string{}, byCask: map[string]string{}}
	seen := map[string]int{}
	for _, c := range casks {
		if strings.Contains(c.Token, "@") {
			continue
		}
		version, _, _ := strings.Cut(c.Version, ",") // version,build
		if plainVersion.MatchString(version) {
			cat.byCask[c.Token] = version
		}
		for _, name := range appNames(c.Artifacts) {
			seen[name]++
			if plainVersion.MatchString(version) {
				cat.latest[name] = version
			}
		}
	}
	for name, n := range seen {
		if n > 1 {
			delete(cat.latest, name)
		}
	}
	return cat, nil
}

// appNames reads the app artifacts. An entry is a bundle name, optionally followed by {"target": "Other.app"},
// which is the name it's actually installed under.
func appNames(artifacts []json.RawMessage) []string {
	var out []string
	for _, raw := range artifacts {
		var a struct {
			App []json.RawMessage `json:"app"`
		}
		if json.Unmarshal(raw, &a) != nil {
			continue
		}
		for _, entry := range a.App {
			var name string
			if json.Unmarshal(entry, &name) == nil {
				out = append(out, name)
				continue
			}
			var opts struct {
				Target string `json:"target"`
			}
			if json.Unmarshal(entry, &opts) == nil && opts.Target != "" && len(out) > 0 {
				out[len(out)-1] = opts.Target
			}
		}
	}
	return out
}

// Update states.
const (
	UpdateAvailable = "available"
	UpdateCurrent   = "current"
)

// UpdateFromCask is Update for an app the registry ties to a cask, which covers casks that install through a
// package and so name no app. parts limits the comparison to that many leading parts of each version, for
// vendors whose build numbers don't line up with the catalog's; zero compares them all.
func (c Catalog) UpdateFromCask(cask, installed string, parts int) (latest, state string) {
	latest, ok := c.byCask[cask]
	if !ok || !plainVersion.MatchString(installed) {
		return "", ""
	}
	if parts > 0 {
		latest, installed = firstParts(latest, parts), firstParts(installed, parts)
	}
	if CompareVersions(installed, latest) < 0 {
		return latest, UpdateAvailable
	}
	return latest, UpdateCurrent
}

func firstParts(v string, n int) string {
	p := strings.Split(v, ".")
	if len(p) > n {
		p = p[:n]
	}
	return strings.Join(p, ".")
}

// Update compares an installed version with the catalog. It returns the listed version and a state, with no
// state when either can't be compared. Being ahead of the catalog counts as current: it can lag a vendor.
func (c Catalog) Update(app, installed string) (latest, state string) {
	latest, ok := c.latest[app]
	if !ok || !plainVersion.MatchString(installed) {
		return "", ""
	}
	if CompareVersions(installed, latest) < 0 {
		return latest, UpdateAvailable
	}
	return latest, UpdateCurrent
}
