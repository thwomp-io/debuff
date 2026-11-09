package version

import (
	"os"
	"regexp"
	"testing"
)

func TestVersionIsSemver(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(Version()) {
		t.Fatalf("VERSION is %q, want MAJOR.MINOR.PATCH", Version())
	}
}

// The changelog's newest release must be this version: a bump with no entry fails here.
func TestChangelogLeadsWithThisVersion(t *testing.T) {
	b, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`).FindSubmatch(b)
	if m == nil {
		t.Fatal("CHANGELOG.md has no release entry")
	}
	if string(m[1]) != Version() {
		t.Fatalf("CHANGELOG leads with %s, VERSION is %s", m[1], Version())
	}
}
