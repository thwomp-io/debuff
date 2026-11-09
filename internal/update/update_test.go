package update

import (
	"context"
	"testing"
)

func TestOpenTakesOnlyAnAppOrAFixedDestination(t *testing.T) {
	for target, want := range map[string]bool{
		SoftwareUpdate:                  true,
		AppStore:                        true,
		"/Applications/Some App.app":    true,
		"https://evil.example/x.app":    false,
		"file:///Applications/Mail.app": false,
		"Mail.app":                      false,
		"/tmp/script.command":           false,
		"/Applications/../tmp/x.app":    false,
		"-a":                            false,
		"":                              false,
		"x-apple.systempreferences:com.apple.Other": false,
	} {
		if got := Openable(target); got != want {
			t.Errorf("%q: got %v", target, got)
		}
	}
	if err := Open(context.Background(), "/tmp/script.command"); err == nil {
		t.Fatal("should refuse before running anything")
	}
}

func TestBrewRefusesWhatIsntAFormulaName(t *testing.T) {
	for _, name := range []string{"", "--force", "-v", "a b", "a;b", "$(x)"} {
		if err := Brew(context.Background(), []string{"ok", name}); err == nil {
			t.Errorf("%q should be refused before running anything", name)
		}
	}
	if err := Brew(context.Background(), nil); err == nil {
		t.Error("an empty list should be refused")
	}
}
