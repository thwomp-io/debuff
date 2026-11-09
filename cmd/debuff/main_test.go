package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thwomp-io/debuff/internal/state"
	"github.com/thwomp-io/debuff/internal/version"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"version"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != version.Version() {
		t.Fatalf("got %q", out.String())
	}
	out.Reset()
	if err := run([]string{"version", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var info version.Info
	if err := json.Unmarshal(out.Bytes(), &info); err != nil || info.Version != version.Version() {
		t.Fatalf("%v %+v", err, info)
	}
}

func TestUnknownAndMissingCommands(t *testing.T) {
	if err := run(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("no args should fail")
	}
	if err := run([]string{"nope"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown command should fail")
	}
}

func TestServeRefusesNonLoopbackBeforeTouchingState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "never")
	err := run([]string{"serve", "--addr", "0.0.0.0:0", "--state-dir", dir}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "loopback only") {
		t.Fatal(err)
	}
	if s, err := state.Load(dir); err != nil || !s.LastStart.IsZero() {
		t.Fatalf("state was touched: %+v %v", s, err)
	}
}

func TestStateDirOrder(t *testing.T) {
	t.Setenv("DEBUFF_STATE_DIR", "/env/dir")
	if got, _ := stateDir("/flag/dir"); got != "/flag/dir" {
		t.Fatal(got)
	}
	if got, _ := stateDir(""); got != "/env/dir" {
		t.Fatal(got)
	}
	t.Setenv("DEBUFF_STATE_DIR", "")
	got, err := stateDir("")
	if err != nil || !strings.HasSuffix(got, filepath.Join(".local", "state", "debuff")) {
		t.Fatal(got, err)
	}
}
