#!/usr/bin/env bash
# The gate: one command, no judgment calls. Every step must pass before a tag.
# A hook exports GIT_DIR and friends, which would point any git the checks spawn at the wrong repo.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX GIT_COMMON_DIR
set -uo pipefail
cd "$(dirname "$0")/.."
export GOFLAGS=-mod=readonly GOTOOLCHAIN=local CGO_ENABLED=1 # CGO only for -race; the build sets 0

tmp=$(mktemp -d)
pid=""
cleanup() {
	[ -n "$pid" ] && kill "$pid" 2>/dev/null
	rm -rf "$tmp"
}
trap cleanup EXIT

# A failure names its step on the last line, so the proof script can tell which step stopped it.
step() {
	local name=$1
	shift
	echo "── $name"
	if ! "$@"; then
		echo "✗ GATE FAILED at: $name"
		exit 1
	fi
}

need_tools() {
	local t missing=0
	for t in go golangci-lint govulncheck osv-scanner; do
		command -v "$t" >/dev/null || {
			echo "$t is not installed: a missing scanner must not read as a pass"
			missing=1
		}
	done
	return "$missing"
}

toolchain() {
	local want have
	want=$(sed -nE 's/^go ([0-9.]+)$/\1/p' go.mod)
	have=$(go env GOVERSION | sed 's/^go//')
	[ "$have" = "$want" ] || {
		echo "go.mod pins $want, this toolchain is $have. Update the go line in its own commit"
		return 1
	}
}

mod_clean() {
	go mod tidy -diff || return 1
	go mod verify >/dev/null
}

fuzz() {
	local pkg t
	for pkg in $(go list ./...); do
		for t in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
			echo "   $t ($pkg)"
			go test -run '^$' -fuzz "^$t\$" -fuzztime 5s "$pkg" >"$tmp/fuzz.log" 2>&1 || {
				cat "$tmp/fuzz.log"
				return 1
			}
		done
	done
}

# Strict on purpose: by default both scanners drop a vulnerability unless static analysis finds a
# call to it, and both exit 0. "Not called" is an inference, so here any known vulnerability in a
# required module or the standard library stops the release. Patch it, don't explain it.
vulns() {
	# -C: module mode runs from a directory with Go files, and the repo root has none.
	govulncheck -C cmd/debuff -scan module || return 1
	osv-scanner scan --no-call-analysis=all --lockfile=go.mod
}

# Same commit, same bytes: two clean builds must match, and the binary must know its version.
build_repro() {
	CGO_ENABLED=0 scripts/build.sh "$tmp/a" >/dev/null || return 1
	CGO_ENABLED=0 scripts/build.sh "$tmp/b" >/dev/null || return 1
	cmp "$tmp/a" "$tmp/b" || {
		echo "two builds of this tree differ"
		return 1
	}
	[ "$("$tmp/a" version)" = "$(cat internal/version/VERSION)" ] || {
		echo "the binary reports a different version"
		return 1
	}
}

# Run the built binary on a throwaway state dir, then probe it from the attacker's side too.
smoke() {
	"$tmp/a" serve --addr 127.0.0.1:0 --state-dir "$tmp/state" >"$tmp/serve.log" 2>&1 &
	pid=$!
	local url="" i
	for i in $(seq 1 50); do
		url=$(sed -nE 's#.*listening on (http://[^ ]+).*#\1#p' "$tmp/serve.log")
		[ -n "$url" ] && break
		sleep 0.1
	done
	[ -n "$url" ] || {
		cat "$tmp/serve.log"
		return 1
	}
	curl -fsS "$url/healthz" | grep -q '"status":"ok"' || {
		echo "healthz did not answer ok"
		return 1
	}
	local code
	code=$(curl -s -o /dev/null -w '%{http_code}' "$url/")
	[ "$code" = "401" ] || {
		echo "the page without a token got HTTP $code, want 401"
		return 1
	}
	curl -fsSL -c "$tmp/jar" -b "$tmp/jar" "$url/?token=$(cat "$tmp/state/token")" | grep -q "v$(cat internal/version/VERSION)" || {
		echo "the page did not render this version"
		return 1
	}
	code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.example' "$url/healthz")
	[ "$code" = "403" ] || {
		echo "a rebinding Host got HTTP $code, want 403"
		return 1
	}
	[ "$(stat -f '%Lp' "$tmp/state")" = "700" ] && [ "$(stat -f '%Lp' "$tmp/state/token")" = "600" ] || {
		echo "the state dir or the token isn't private"
		return 1
	}
	kill "$pid" && wait "$pid" 2>/dev/null
	pid=""
	return 0
}

clean_tree() {
	[ -z "$(git status --porcelain)" ] || {
		git status --short
		echo "working tree not clean: commit before tagging"
		return 1
	}
}

step "tools present" need_tools
step "toolchain matches go.mod" toolchain
step "format" golangci-lint fmt --diff
step "go.mod tidy + verify" mod_clean
step "vet" go vet ./...
step "lint" golangci-lint run
step "tests (-race, version consistency)" go test -race -count=1 ./...
step "fuzz (5s per target)" fuzz
step "vulnerability scan" vulns
step "reproducible build" build_repro
step "smoke (built binary, throwaway state)" smoke
if [ "${GATE_ALLOW_DIRTY:-}" != "1" ]; then
	step "clean tree" clean_tree
fi
echo
echo "✓ GATE PASS"
