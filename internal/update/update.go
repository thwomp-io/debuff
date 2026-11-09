// Package update is the one place Debuff changes anything on this machine, and only when its page's button is
// pressed. Nothing here runs on a schedule or from a scan.
package update

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/thwomp-io/debuff/internal/collect"
)

// The two places an update is applied that aren't an app.
const (
	SoftwareUpdate = "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"
	AppStore       = "macappstore://showUpdatesPage"
)

// Brew upgrades formulae in one command: Homebrew holds a lock per install, so separate upgrades would only queue
// or collide, and one command lets it order the work. It has no terminal, so anything that would prompt fails
// instead of hanging. A cask is deliberately not offered: its uninstall step can quit a running app before an
// install that then needs sudo.
func Brew(ctx context.Context, formulae []string) error {
	if len(formulae) == 0 {
		return errors.New("no formulae to upgrade")
	}
	for _, f := range formulae {
		if !collect.FormulaName.MatchString(f) {
			return fmt.Errorf("not a formula name: %q", f)
		}
	}
	args := append([]string{"upgrade", "--formula"}, formulae...)
	// #nosec G204 -- a fixed tool at a fixed path; every name is checked above and can't read as a flag
	cmd := exec.CommandContext(ctx, collect.BrewPath(), args...)
	cmd.Env = append(cmd.Environ(), "HOMEBREW_NO_ENV_HINTS=1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, lastLine(out.String()))
	}
	return nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	line := lines[len(lines)-1]
	if len(line) > 300 {
		line = line[:300]
	}
	return line
}

// Openable says whether target is something Open may be given: an app bundle by absolute path, or one of the two
// fixed destinations. Never a URL from a scan or a request.
func Openable(target string) bool {
	if target == SoftwareUpdate || target == AppStore {
		return true
	}
	return filepath.IsAbs(target) && filepath.Clean(target) == target && strings.HasSuffix(target, ".app")
}

// Open brings up an app or a system updater, which is where the update then happens.
func Open(ctx context.Context, target string) error {
	if !Openable(target) {
		return errors.New("not something to open")
	}
	// #nosec G204 -- a fixed tool; the target is an absolute app path or a fixed URL, checked above
	if out, err := exec.CommandContext(ctx, "/usr/bin/open", target).CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, lastLine(string(out)))
	}
	return nil
}
