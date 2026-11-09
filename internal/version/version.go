// Package version reports what this binary is: the VERSION file embedded at build time, plus the
// commit the Go toolchain stamps into every build made from a git checkout.
package version

import (
	_ "embed"
	"runtime"
	"runtime/debug"
	"strings"
)

//go:embed VERSION
var raw string

// Version is the release version, from the one file that defines it.
func Version() string { return strings.TrimSpace(raw) }

// Info is what `debuff version` and /healthz report.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Dirty   bool   `json:"dirty"`
	Go      string `json:"go"`
}

// Get reads the build's VCS stamp. A test binary has none, so Commit is empty there.
func Get() Info {
	info := Info{Version: Version(), Go: runtime.Version()}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				info.Commit = s.Value
			case "vcs.modified":
				info.Dirty = s.Value == "true"
			}
		}
	}
	return info
}
