package registry

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestShippedListIsWellFormed(t *testing.T) {
	r, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	date := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	for _, e := range r.All() {
		if e.Name == "" || !strings.Contains(e.ID, ".") {
			t.Errorf("%+v needs an identity", e)
		}
		if e.CPE == "" && e.Cask == "" {
			t.Errorf("%s says nothing", e.Name)
		}
		if e.CPE != "" && (strings.Count(e.CPE, ":") != 1 || e.Check == "" || e.Evidence == "") {
			t.Errorf("%s: a CVE source needs vendor:product, a version to check and evidence", e.Name)
		}
		if e.Verified != "" && (!date.MatchString(e.Verified) || e.CPE == "") {
			t.Errorf("%s: bad verified %q", e.Name, e.Verified)
		}
		if e.Why != "" && (e.Exposure < 1 || e.Exposure > 3) {
			t.Errorf("%s: exposure %d", e.Name, e.Exposure)
		}
	}
	if len(r.All()) < 20 {
		t.Fatal("a short list would say what's installed here; it should cover common apps")
	}
}

func TestOverlayAddsAndOverrides(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "registry.json")
	body := `{"format":1,"apps":[{"id":"org.mozilla.firefox","name":"Mine","cpe":"a:b","check":"1"},{"id":"x.y.z","name":"Added","cask":"z"}]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := r.Lookup("org.mozilla.firefox"); !ok || e.Name != "Mine" || e.Verified != "" {
		t.Fatalf("%+v", e)
	}
	if _, ok := r.Lookup("x.y.z"); !ok {
		t.Fatal("the overlay should add")
	}
	if _, ok := r.Lookup("not.listed"); ok {
		t.Fatal("unlisted")
	}
	for _, bad := range []string{`{"format":99,"apps":[]}`, `not json`, `{"format":1,"apps":[{"name":"no id"}]}`} {
		if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil {
			t.Errorf("%s should be refused", bad)
		}
	}
}
