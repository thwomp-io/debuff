#!/usr/bin/env bash
# Prove the gate refuses what it claims to: each fault goes into a throwaway worktree as a commit, and
# the gate must stop at the step that should catch it. Finishes by proving the hook blocks a tag.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
tmp=$(mktemp -d)
wt=$tmp/wt
git worktree add -q --detach "$wt" HEAD || exit 1
cleanup() {
	git -C "$root" worktree remove --force "$wt" 2>/dev/null
	git -C "$root" worktree prune
	rm -rf "$tmp"
}
trap cleanup EXIT
fails=0

reset_wt() { git -C "$wt" reset -q --hard "$(git -C "$root" rev-parse HEAD)" && git -C "$wt" clean -qfd; }
commit_wt() { git -C "$wt" add -A && git -C "$wt" -c user.email=p@p -c user.name=p commit -qm fault --no-verify; }

# expect NAME STEP [EVIDENCE]: the gate must fail, name exactly STEP, and (when given) show EVIDENCE, so
# a tool crashing at the right step can't pass as a catch.
expect() {
	local name=$1 want=$2 evidence=${3:-} log=$tmp/$1.log got
	if (cd "$wt" && scripts/gate.sh) >"$log" 2>&1; then
		echo "FAIL  $name: the gate PASSED"
		fails=1
		return
	fi
	got=$(sed -n 's/^✗ GATE FAILED at: //p' "$log")
	if [ "$got" = "$want" ] && { [ -z "$evidence" ] || grep -q "$evidence" "$log"; }; then
		echo "ok    $name → stopped at: $got"
	else
		echo "FAIL  $name → stopped at '$got', expected '$want'"
		tail -5 "$log"
		fails=1
	fi
}

reset_wt
cat >>"$wt/cmd/debuff/main.go" <<'GO'

func unchecked() { os.Remove("x") }

var _ = unchecked
GO
commit_wt
expect "lint violation (an unchecked error)" "lint" "errcheck"

reset_wt
cat >"$wt/internal/state/fault_test.go" <<'GO'
package state

import "testing"

func TestFault(t *testing.T) { t.Fatal("deliberately failing") }
GO
commit_wt
expect "failing test" "tests (-race, version consistency)" "deliberately failing"

reset_wt
printf 'package state\n\nfunc   badlyFormatted( ) {}\n\nvar _ = badlyFormatted\n' >"$wt/internal/state/fault.go"
commit_wt
expect "bad formatting" "format"

reset_wt
echo "0.0.99" >"$wt/internal/version/VERSION"
commit_wt
expect "version bump with no changelog entry" "tests (-race, version consistency)" "CHANGELOG leads with"

# A dependency with published vulnerabilities, two ways: the vulnerable function called, and imported
# but never called. The second is the one scanners wave through by default.
vuln_dep() {
	(cd "$wt" && GOFLAGS=-mod=mod GOTOOLCHAIN=local go get golang.org/x/text@v0.3.7 >/dev/null 2>&1)
	cat >"$wt/cmd/debuff/fault.go" <<GO
package main

import "golang.org/x/text/language"

func init() { _, _, _ = language.$1 }
GO
	(cd "$wt" && GOFLAGS=-mod=mod GOTOOLCHAIN=local go mod tidy >/dev/null 2>&1)
	commit_wt
}
reset_wt
vuln_dep 'ParseAcceptLanguage("en")'
expect "vulnerable dependency, called" "vulnerability scan" "GO-2022-1059"

reset_wt
vuln_dep 'ParseBase("en")'
sed -i '' 's/_, _, _ = language/_, _ = language/' "$wt/cmd/debuff/fault.go"
commit_wt
expect "vulnerable dependency, not called" "vulnerability scan" "GO-2022-1059"

reset_wt
echo "stray" >"$wt/stray.txt"
expect "dirty tree" "clean tree"

# The hook: a tag on a bad commit must not reach the remote; a normal push must pass untouched.
reset_wt
git init -q --bare "$tmp/remote.git"
git -C "$wt" remote add prove "$tmp/remote.git" 2>/dev/null || git -C "$wt" remote set-url prove "$tmp/remote.git"
if git -C "$wt" push -q prove HEAD:refs/heads/side >/dev/null 2>&1; then
	echo "ok    hook: a non-release push passes straight through"
else
	echo "FAIL  hook: a non-release push was blocked"
	fails=1
fi
cat >"$wt/internal/state/fault_test.go" <<'GO'
package state

import "testing"

func TestFault(t *testing.T) { t.Fatal("deliberately failing") }
GO
commit_wt
git -C "$wt" tag -a v0.0.98 -m prove
if git -C "$wt" push -q prove refs/tags/v0.0.98 >"$tmp/hook.log" 2>&1; then
	echo "FAIL  hook: a tag on a failing commit reached the remote"
	fails=1
elif grep -q "push blocked" "$tmp/hook.log" && [ -z "$(git -C "$tmp/remote.git" tag)" ]; then
	echo "ok    hook: a tag on a failing commit was blocked, and the remote has no tag"
else
	echo "FAIL  hook: push failed for some other reason"
	tail -5 "$tmp/hook.log"
	fails=1
fi
git -C "$wt" tag -d v0.0.98 >/dev/null
git -C "$wt" remote remove prove

[ "$fails" = 0 ] && echo && echo "✓ every fault stopped the gate" || echo "✗ the gate has a hole"
exit "$fails"
