// Package snapshot is what one scan found: one gzipped JSON file per scan, in the private data directory.
package snapshot

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Format is the on-disk format this binary reads and writes.
const Format = 1

// Labels say how sure a finding is.
const (
	Confirmed = "Confirmed" // an advisory names this exact version
	Inferred  = "Inferred"  // the bundled runtime is behind the fix; an upper bound
	Doubtful  = "Doubtful"  // an advisory matched, but it appears to be about something else
)

// Finding is one vulnerability in one installed thing. Its text comes from outside: untrusted.
type Finding struct {
	CVE      string  `json:"cve"`
	App      string  `json:"app"`
	Label    string  `json:"label"`
	Severity string  `json:"severity"`
	Title    string  `json:"title"`
	KEV      bool    `json:"kev,omitempty"`
	EPSS     float64 `json:"epss,omitempty"`
	HasEPSS  bool    `json:"has_epss,omitempty"`
	FixedIn  string  `json:"fixed_in,omitempty"`
	Date     string  `json:"date,omitempty"` // YYYY-MM-DD
	Evidence string  `json:"evidence"`
	URL      string  `json:"url,omitempty"`
	// Absent: probably in a part of Chrome this app doesn't ship. Hidden unless asked for, never dropped.
	Absent bool `json:"absent,omitempty"`
}

// Item is one thing that was inspected.
type Item struct {
	App, Kind, Version, Runtime string // Version is what was checked: Electron's for an app, the formula's for brew
	Exposure                    int
	ExposureWhy                 string
	Running                     bool
	Note                        string
	Unsupported                 bool   // its runtime line gets no more fixes
	AppVersion                  string // the app's own version, which is what its vendor's release notes name
	LastOpened, Updated         string // YYYY-MM-DD; empty when unknown. Updated is when the bundle last changed
	Latest, Update              string // the latest version Homebrew lists, and how this one compares; empty when unknown
	Icon                        string // the content hash of its icon under icons/; empty when it has none
	CVESource                   string // what its findings were checked against; empty when nothing could
	Path                        string // where its bundle is; empty when it has none
	AppStore                    bool   // installed from the Mac App Store
}

// How a Pending update gets applied.
const (
	ViaHomebrew = "homebrew"
	ViaSystem   = "system"
)

// Pending is an update a package tool reports, as opposed to one worked out for an app from the catalog.
type Pending struct {
	Name, Installed, Latest, Via string
	Restart                      bool
}

// Source is how one data source went: "ok", "stale" (older data used) or "failed".
type Source struct {
	Name, Status, Detail string
}

// Snapshot is one scan.
type Snapshot struct {
	Format    int       `json:"format"`
	Host      string    `json:"host"`
	ScannedAt time.Time `json:"scanned_at"`
	Version   string    `json:"version"`
	Items     []Item    `json:"items"`
	Sources   []Source  `json:"sources"`
	Findings  []Finding `json:"findings"`
	Pending   []Pending `json:"pending,omitempty"`
}

const (
	dirName = "snapshots"
	stamp   = "20060102-150405"
)

// Write stores a snapshot atomically under dir and returns its path.
func Write(dir string, s Snapshot) (string, error) {
	s.Format = Format
	sub := filepath.Join(dir, dirName)
	if err := os.MkdirAll(sub, 0o700); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gz).Encode(s); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(sub, ".tmp-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	path := filepath.Join(sub, s.ScannedAt.UTC().Format(stamp)+".json.gz")
	return path, os.Rename(tmp.Name(), path)
}

// ErrNone means no scan has run.
var ErrNone = errors.New("no scan yet")

// Latest is the newest snapshot's path.
func Latest(dir string) (string, error) {
	names, err := filepath.Glob(filepath.Join(dir, dirName, "*.json.gz"))
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", ErrNone
	}
	sort.Strings(names)
	return names[len(names)-1], nil
}

// Read loads one snapshot, refusing a format this binary doesn't know.
func Read(path string) (Snapshot, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- inside the operator's own data dir
	if err != nil {
		return Snapshot{}, err
	}
	return Decode(b)
}

// Fingerprint identifies what a scan found and what it found it in: two scans with the same one say the same
// thing, whatever time they ran. EPSS moves daily and whether an app was open at that moment means nothing here.
func Fingerprint(s Snapshot) string {
	lines := make([]string, 0, len(s.Findings)+len(s.Items))
	for _, f := range s.Findings {
		lines = append(lines, strings.Join([]string{"f", f.App, f.CVE, f.Label, f.Severity, f.FixedIn, strconv.FormatBool(f.KEV), strconv.FormatBool(f.Absent)}, "\x00"))
	}
	for _, it := range s.Items {
		lines = append(lines, strings.Join([]string{"i", it.App, it.Version, it.AppVersion, it.Runtime}, "\x00"))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// newestFirst lists the scans in dir, newest first.
func newestFirst(dir string) ([]string, error) {
	names, err := filepath.Glob(filepath.Join(dir, dirName, "*.json.gz"))
	if err != nil {
		return nil, err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names, nil
}

// History is the newest scan and what it can be compared with.
type History struct {
	Latest Snapshot
	// Since is the earliest scan that already said the same as Latest. Zero when Latest is the first to.
	Since time.Time
	// Previous is the newest scan that said something different. Nil when there's none to compare.
	Previous *Snapshot
}

// LoadHistory reads the newest scan, then back to the last one that differed, so rescanning an unchanged machine
// doesn't erase what changed. A scan it can't read, such as an older format, is skipped.
func LoadHistory(dir string) (History, error) {
	names, err := newestFirst(dir)
	if err != nil {
		return History{}, err
	}
	if len(names) == 0 {
		return History{}, ErrNone
	}
	latest, err := Read(names[0])
	if err != nil {
		return History{}, err
	}
	h := History{Latest: latest}
	want := Fingerprint(latest)
	for _, name := range names[1:] {
		old, err := Read(name)
		if err != nil {
			continue
		}
		if Fingerprint(old) != want {
			h.Previous = &old
			break
		}
		h.Since = old.ScannedAt
	}
	return h, nil
}

// How much history to keep. Beyond the newest scan and what it's compared with, this is only a record of when
// things changed, so it doesn't need to be long.
const (
	keepDays  = 30
	keepKinds = 30
)

// Prune removes the scans that add nothing. It keeps the newest, and the earliest of each run of scans that say
// the same thing, which is when that state began. Of those, only the two newest states are kept regardless of age;
// older ones go after keepDays or past keepKinds. A file it can't read is left alone: it might be a newer
// format, and deleting what it doesn't understand isn't its call. It returns how many it removed.
func Prune(dir string, now time.Time) (int, error) {
	names, err := newestFirst(dir)
	if err != nil {
		return 0, err
	}
	if len(names) < 2 {
		return 0, nil
	}
	type scan struct {
		name, print string
		at          time.Time
	}
	var scans []scan
	for _, name := range names {
		s, err := Read(name)
		if err != nil {
			continue
		}
		scans = append(scans, scan{name, Fingerprint(s), s.ScannedAt})
	}
	keep := map[string]bool{}
	cutoff := now.AddDate(0, 0, -keepDays)
	kinds := 0
	for i, s := range scans {
		if i == 0 {
			keep[s.name] = true
		}
		if i+1 < len(scans) && scans[i+1].print == s.print {
			continue // not the earliest of its run
		}
		kinds++
		if kinds <= 2 || (kinds <= keepKinds && s.at.After(cutoff)) {
			keep[s.name] = true
		}
	}
	removed := 0
	for _, s := range scans {
		if keep[s.name] {
			continue
		}
		if err := os.Remove(s.name); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// Decode parses a snapshot's bytes.
func Decode(b []byte) (Snapshot, error) {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return Snapshot{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(gz, 1<<30))
	if err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return Snapshot{}, err
	}
	if s.Format != Format {
		return Snapshot{}, fmt.Errorf("snapshot has format %d; this binary reads format %d", s.Format, Format)
	}
	return s, nil
}

// Degraded lists the sources that didn't fully answer.
func (s Snapshot) Degraded() []string {
	var out []string
	for _, src := range s.Sources {
		if src.Status != "ok" {
			out = append(out, strings.TrimSpace(src.Name+" ("+src.Status+"): "+src.Detail))
		}
	}
	return out
}
