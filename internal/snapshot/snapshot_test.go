package snapshot

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestRoundTripAndLatest(t *testing.T) {
	dir := t.TempDir()
	if _, err := Latest(dir); !errors.Is(err, ErrNone) {
		t.Fatal(err)
	}
	for _, day := range []int{1, 3, 2} {
		s := Snapshot{ScannedAt: time.Date(2026, 11, day, 0, 0, 0, 0, time.UTC), Findings: []Finding{{CVE: "CVE-1", KEV: true}}}
		if _, err := Write(dir, s); err != nil {
			t.Fatal(err)
		}
	}
	p, err := Latest(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Read(p)
	if err != nil || got.ScannedAt.Day() != 3 || !got.Findings[0].KEV || got.Format != Format {
		t.Fatalf("%+v %v", got, err)
	}
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestAnUnknownFormatIsRefused(t *testing.T) {
	if _, err := Decode(gz(t, `{"format":99}`)); err == nil {
		t.Fatal("want a refusal")
	}
}

func TestDegradedNamesWhatDidntAnswer(t *testing.T) {
	s := Snapshot{Sources: []Source{{Name: "a", Status: "ok"}, {Name: "b", Status: "failed", Detail: "HTTP 500"}}}
	d := s.Degraded()
	if len(d) != 1 || d[0] != "b (failed): HTTP 500" {
		t.Fatalf("%v", d)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte("not gzip"))
	f.Add(gz(&testing.T{}, `{"format":1,"findings":[{"cve":"x"}]}`))
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = Decode(b) })
}

func scanOf(at time.Time, cves ...string) Snapshot {
	s := Snapshot{ScannedAt: at, Items: []Item{{App: "A", AppVersion: "1.0"}}}
	for _, c := range cves {
		s.Findings = append(s.Findings, Finding{CVE: c, App: "A", Label: Inferred, Severity: "High"})
	}
	return s
}

func TestFingerprintIsWhatWasFoundNotWhen(t *testing.T) {
	base := scanOf(time.Unix(1, 0), "CVE-1", "CVE-2")
	same := scanOf(time.Unix(2, 0), "CVE-2", "CVE-1")
	same.Findings[0].EPSS = 0.9
	same.Items[0].Running = true
	if Fingerprint(base) != Fingerprint(same) {
		t.Fatal("time, order, EPSS and running state aren't a change")
	}
	for name, change := range map[string]func(*Snapshot){
		"a closed finding": func(s *Snapshot) { s.Findings = s.Findings[:1] },
		"a label":          func(s *Snapshot) { s.Findings[0].Label = Confirmed },
		"known exploited":  func(s *Snapshot) { s.Findings[0].KEV = true },
		"a severity":       func(s *Snapshot) { s.Findings[0].Severity = "Low" },
		"an app version":   func(s *Snapshot) { s.Items[0].AppVersion = "2.0" },
		"a removed app":    func(s *Snapshot) { s.Items = nil },
	} {
		c := scanOf(time.Unix(1, 0), "CVE-1", "CVE-2")
		change(&c)
		if Fingerprint(c) == Fingerprint(base) {
			t.Errorf("%s should count", name)
		}
	}
}

func writeAll(t *testing.T, dir string, scans ...Snapshot) {
	t.Helper()
	for _, s := range scans {
		if _, err := Write(dir, s); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHistoryLooksPastScansThatChangedNothing(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadHistory(dir); !errors.Is(err, ErrNone) {
		t.Fatal(err)
	}
	day := func(d int) time.Time { return time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC) }
	writeAll(t, dir, scanOf(day(1), "CVE-1", "CVE-2"))
	h, err := LoadHistory(dir)
	if err != nil || h.Previous != nil || !h.Since.IsZero() {
		t.Fatalf("one scan: %+v %v", h, err)
	}
	writeAll(t, dir, scanOf(day(2), "CVE-2"))
	if h, err = LoadHistory(dir); err != nil || h.Previous == nil || !h.Previous.ScannedAt.Equal(day(1)) || !h.Since.IsZero() {
		t.Fatalf("a change: %+v %v", h, err)
	}
	writeAll(t, dir, scanOf(day(3), "CVE-2"), scanOf(day(4), "CVE-2"))
	h, err = LoadHistory(dir)
	if err != nil || h.Previous == nil || !h.Previous.ScannedAt.Equal(day(1)) || !h.Since.Equal(day(2)) || !h.Latest.ScannedAt.Equal(day(4)) {
		t.Fatalf("rescans must keep the change: %+v %v", h, err)
	}
}

func left(t *testing.T, dir string) []int {
	t.Helper()
	names, err := newestFirst(dir)
	if err != nil {
		t.Fatal(err)
	}
	var days []int
	for _, n := range names {
		s, err := Read(n)
		if err != nil {
			t.Fatal(err)
		}
		days = append(days, s.ScannedAt.Day())
	}
	return days
}

func TestPruneKeepsTheNewestAndWhenEachStateBegan(t *testing.T) {
	dir := t.TempDir()
	day := func(d int) time.Time { return time.Date(2026, 10, d, 0, 0, 0, 0, time.UTC) }
	writeAll(t, dir,
		scanOf(day(1), "A"), scanOf(day(2), "A"), scanOf(day(3), "A"), // state one, began on the 1st
		scanOf(day(4), "B"), scanOf(day(5), "B"), // state two, began on the 4th
		scanOf(day(6), "C"), scanOf(day(7), "C"), scanOf(day(8), "C")) // the current state, began on the 6th
	n, err := Prune(dir, day(9))
	if err != nil || n != 4 {
		t.Fatalf("removed %d, %v", n, err)
	}
	if got := left(t, dir); !slices.Equal(got, []int{8, 6, 4, 1}) {
		t.Fatalf("kept the scans of %v", got)
	}
	h, err := LoadHistory(dir)
	if err != nil || !h.Latest.ScannedAt.Equal(day(8)) || !h.Since.Equal(day(6)) || !h.Previous.ScannedAt.Equal(day(4)) {
		t.Fatalf("pruning must not change what the page says: %+v %v", h, err)
	}
	if n, err := Prune(dir, day(9)); err != nil || n != 0 {
		t.Fatalf("a second prune removed %d, %v", n, err)
	}
}

func TestPruneKeepsWhatTheComparisonNeedsHoweverOld(t *testing.T) {
	dir := t.TempDir()
	long := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	writeAll(t, dir, scanOf(long, "X"), scanOf(long.AddDate(0, 1, 0), "A"), scanOf(long.AddDate(0, 2, 0), "B"))
	if _, err := Prune(dir, time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	names, _ := newestFirst(dir)
	if len(names) != 2 {
		t.Fatalf("the newest and what it's compared with stay; older history ages out: %v", names)
	}
}

func TestPruneCapsHistory(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	for i := range keepKinds + 5 {
		writeAll(t, dir, scanOf(now.Add(time.Duration(i-40)*time.Hour), "CVE-"+strconv.Itoa(i)))
	}
	if n, err := Prune(dir, now); err != nil || n != 5 {
		t.Fatalf("removed %d, %v", n, err)
	}
}

func TestPruneLeavesWhatItCantRead(t *testing.T) {
	dir := t.TempDir()
	day := func(d int) time.Time { return time.Date(2026, 10, d, 0, 0, 0, 0, time.UTC) }
	writeAll(t, dir, scanOf(day(1), "A"), scanOf(day(2), "A"), scanOf(day(3), "A"))
	strange := filepath.Join(dir, dirName, "20200101-000000.json.gz")
	if err := os.WriteFile(strange, []byte("a future format"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, dirName, "notes.txt")
	if err := os.WriteFile(other, []byte("not a scan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := Prune(dir, day(4)); err != nil || n != 1 {
		t.Fatalf("removed %d, %v", n, err)
	}
	for _, p := range []string{strange, other} {
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPruneOnAnEmptyOrOneScanDir(t *testing.T) {
	dir := t.TempDir()
	if n, err := Prune(dir, time.Now()); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	writeAll(t, dir, scanOf(time.Unix(1, 0), "A"))
	if n, err := Prune(dir, time.Now()); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}
