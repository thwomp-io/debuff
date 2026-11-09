package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := State{LastStart: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), LastVersion: "1.2.3"}
	if err := Save(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != Format || !got.LastStart.Equal(want.LastStart) || got.LastVersion != "1.2.3" {
		t.Fatalf("got %+v", got)
	}
}

func TestTokenIsPrivateStableAndLong(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	a, err := Token(dir)
	if err != nil || len(a) < 32 {
		t.Fatal(a, err)
	}
	b, err := Token(dir)
	if err != nil || a != b {
		t.Fatal("the token should persist")
	}
	fi, err := os.Stat(filepath.Join(dir, "token"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal(fi, err)
	}
}

func TestMissingFileIsAFreshStart(t *testing.T) {
	s, err := Load(t.TempDir())
	if err != nil || s.Format != Format {
		t.Fatalf("%+v, %v", s, err)
	}
}

func TestUnknownFormatIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte(`{"format": 99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "format 99") {
		t.Fatalf("want a refusal naming format 99, got %v", err)
	}
}

func TestCorruptFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("want an error")
	}
}

func TestEnsureTightensTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- deliberately too open
		t.Fatal(err)
	}
	if err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
}

func TestScanRecord(t *testing.T) {
	dir := t.TempDir()
	if r, err := LastScan(dir); err != nil || r.Error != "" {
		t.Fatalf("%+v %v", r, err)
	}
	at := time.Date(2026, 11, 3, 6, 0, 0, 0, time.UTC)
	if err := RecordScan(dir, at, errors.New("no network")); err != nil {
		t.Fatal(err)
	}
	if r, err := LastScan(dir); err != nil || r.Error != "no network" || !r.At.Equal(at) {
		t.Fatalf("%+v %v", r, err)
	}
	if err := RecordScan(dir, at, nil); err != nil {
		t.Fatal(err)
	}
	if r, err := LastScan(dir); err != nil || r.Error != "" {
		t.Fatalf("a success clears it: %+v %v", r, err)
	}
	if err := os.WriteFile(filepath.Join(dir, scanRecordName), []byte(`{"format":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LastScan(dir); err == nil {
		t.Fatal("an unknown format must be refused")
	}
}

func TestTrimLogKeepsAppendingToTheSameFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.log")
	if err := TrimLog(p, 10); err != nil {
		t.Fatal("a missing log is fine:", err)
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- a temp dir; opened the way launchd holds it
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("small"); err != nil {
		t.Fatal(err)
	}
	if err := TrimLog(p, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + ".1"); err == nil {
		t.Fatal("under the limit it stays put")
	}
	if _, err := f.WriteString(" and now well over the limit"); err != nil {
		t.Fatal(err)
	}
	if err := TrimLog(p, 10); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p + ".1"); string(b) != "small and now well over the limit" { // #nosec G304 -- a temp dir
		t.Fatalf("%q", b)
	}
	if _, err := f.WriteString("after"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "after" { // #nosec G304 -- a temp dir
		t.Fatalf("the open handle must keep writing here: %q", b)
	}
}
