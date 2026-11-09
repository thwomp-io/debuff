// Package state owns the data directory: one private directory, JSON files written atomically, each
// carrying a format number. A binary refuses a format it doesn't know instead of guessing at it, so
// rolling back to an older binary can't quietly damage newer data.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Format is the on-disk format this binary reads and writes.
const Format = 1

const fileName = "state.json"

// State is the small record the server keeps. Real data will sit beside it, on the same rules.
type State struct {
	Format      int       `json:"format"`
	LastStart   time.Time `json:"last_start"`
	LastVersion string    `json:"last_version"`
}

// DefaultDir is the real data directory. Tests and rehearsals pass their own.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "debuff"), nil
}

// Ensure creates the directory private to the user, and tightens one that isn't.
func Ensure(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700) // #nosec G302 -- a directory needs its execute bit; 0700 is owner-only
}

// Load reads the state file. A missing file is a fresh start; an unknown format is an error.
func Load(dir string) (State, error) {
	b, err := os.ReadFile(filepath.Join(dir, fileName)) // #nosec G304 -- the operator's own data dir
	if errors.Is(err, fs.ErrNotExist) {
		return State{Format: Format}, nil
	}
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, fmt.Errorf("%s: %w", fileName, err)
	}
	if s.Format != Format {
		return State{}, fmt.Errorf("%s has format %d; this binary reads format %d", fileName, s.Format, Format)
	}
	return s, nil
}

// Token is the secret that lets a browser in, created on first use, readable only by the user.
func Token(dir string) (string, error) {
	p := filepath.Join(dir, "token")
	if b, err := os.ReadFile(p); err == nil { // #nosec G304 -- the operator's own data dir
		if t := strings.TrimSpace(string(b)); len(t) >= 32 {
			return t, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	t := hex.EncodeToString(raw)
	if err := Ensure(dir); err != nil {
		return "", err
	}
	return t, os.WriteFile(p, []byte(t+"\n"), 0o600)
}

// Save writes through a temp file and a rename, so a crash leaves the old file or the new one.
func Save(dir string, s State) error {
	s.Format = Format
	return writeJSON(dir, fileName, s)
}

func writeJSON(dir, name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, name+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

const scanRecordName = "last-scan.json"

// ScanRecord is how the last scan attempt went, whoever started it. A scan that fails writes no snapshot, so
// without this a failed scheduled scan would leave no mark on the page.
type ScanRecord struct {
	Format int       `json:"format"`
	At     time.Time `json:"at"`
	Error  string    `json:"error,omitempty"`
}

// RecordScan notes one attempt. err is nil for a success.
func RecordScan(dir string, at time.Time, failure error) error {
	r := ScanRecord{Format: Format, At: at.UTC()}
	if failure != nil {
		r.Error = failure.Error()
	}
	return writeJSON(dir, scanRecordName, r)
}

// LastScan reads the record. A missing file is an empty record: nothing has failed.
func LastScan(dir string) (ScanRecord, error) {
	b, err := os.ReadFile(filepath.Join(dir, scanRecordName)) // #nosec G304 -- the operator's own data dir
	if errors.Is(err, fs.ErrNotExist) {
		return ScanRecord{Format: Format}, nil
	}
	if err != nil {
		return ScanRecord{}, err
	}
	var r ScanRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return ScanRecord{}, fmt.Errorf("%s: %w", scanRecordName, err)
	}
	if r.Format != Format {
		return ScanRecord{}, fmt.Errorf("%s has format %d; this binary reads format %d", scanRecordName, r.Format, Format)
	}
	return r, nil
}

// TrimLog caps a log at limit bytes by moving it to path.1 and emptying it in place. launchd holds these
// files open for appending, so a rename would leave it writing to the old one.
func TrimLog(path string, limit int64) error {
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Size() <= limit {
		return nil
	}
	b, err := os.ReadFile(path) // #nosec G304 -- a log in the operator's own data dir
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".1", b, 0o600); err != nil { // #nosec G703 -- a log in the operator's own data dir
		return err
	}
	return os.Truncate(path, 0)
}
