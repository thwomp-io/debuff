// Package registry maps an installed app to where its advisories and versions live. The shipped list covers common
// Mac apps, so it says nothing about any one machine. A private overlay in the data directory adds to it or
// overrides it, because a list of what's on a machine stays out of git.
package registry

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed apps.json
var shipped embed.FS

// Format is the file format this binary reads.
const Format = 1

// Entry is what's known about one app. An entry's CVE source only counts once Verified is set: an agent can draft
// a guess, and `debuff registry check` is what confirms the source really answers.
type Entry struct {
	ID       string `json:"id"`   // CFBundleIdentifier
	Name     string `json:"name"` // for people
	Cask     string `json:"cask,omitempty"`
	CPE      string `json:"cpe,omitempty"`      // vendor:product, for NVD
	Check    string `json:"check,omitempty"`    // an old version NVD should list CVEs for
	Verified string `json:"verified,omitempty"` // the date a check last passed
	Evidence string `json:"evidence,omitempty"` // the vendor's advisories, for a person to check against
	Why      string `json:"why,omitempty"`      // what it handles
	Exposure int    `json:"exposure,omitempty"`
	// Parts is how many leading parts of a version to compare, for vendors whose build numbers don't line up
	// with the catalog's. Zero means all of them.
	Parts int `json:"parts,omitempty"`
}

// Registry is the shipped list with the overlay applied.
type Registry struct {
	byID map[string]Entry
}

type file struct {
	Format int     `json:"format"`
	Apps   []Entry `json:"apps"`
}

func parse(b []byte, into map[string]Entry) error {
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if f.Format != Format {
		return fmt.Errorf("format %d; this binary reads format %d", f.Format, Format)
	}
	for _, e := range f.Apps {
		if e.ID == "" {
			return errors.New("an entry has no id")
		}
		into[e.ID] = e
	}
	return nil
}

// Load reads the shipped list and the overlay, registry.json in dir. A missing overlay is fine.
func Load(dir string) (Registry, error) {
	r := Registry{byID: map[string]Entry{}}
	b, err := shipped.ReadFile("apps.json")
	if err != nil {
		return r, err
	}
	if err := parse(b, r.byID); err != nil {
		return r, fmt.Errorf("shipped registry: %w", err)
	}
	overlay, err := os.ReadFile(filepath.Join(dir, "registry.json")) // #nosec G304 -- the operator's own data dir
	if errors.Is(err, fs.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if err := parse(overlay, r.byID); err != nil {
		return r, fmt.Errorf("registry.json: %w", err)
	}
	return r, nil
}

// Lookup finds an app by its bundle identifier.
func (r Registry) Lookup(id string) (Entry, bool) {
	e, ok := r.byID[id]
	return e, ok
}

// All lists every entry, for checking.
func (r Registry) All() []Entry {
	out := make([]Entry, 0, len(r.byID))
	for _, e := range r.byID {
		out = append(out, e)
	}
	return out
}
