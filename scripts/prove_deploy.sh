#!/usr/bin/env bash
# Rehearse the whole deploy path against a throwaway install: its own label, port, directories and
# state. Install, upgrade, three kinds of bad build, manual rollback. The real install is never touched.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
export DEBUFF_PREFIX=$tmp/bin DEBUFF_AGENTS_DIR=$tmp/agents DEBUFF_STATE_DIR=$tmp/state
export DEBUFF_LABEL=local.debuff.rehearse DEBUFF_SCAN_LABEL=local.debuff.rehearse-scan DEBUFF_ADDR=127.0.0.1:18737
source "$root/scripts/lib.sh"
wt=$tmp/wt
real_before=$(shasum "$HOME/.local/bin/debuff" "$HOME/Library/LaunchAgents/local.debuff.scan.plist" 2>/dev/null)
git -C "$root" worktree add -q --detach "$wt" HEAD || exit 1
cleanup() {
	launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null
	launchctl bootout "$DOMAIN/$SCAN_LABEL" 2>/dev/null
	git -C "$root" worktree remove --force "$wt" 2>/dev/null
	git -C "$root" worktree prune
	rm -rf "$tmp"
}
trap cleanup EXIT
fails=0
check() {
	if eval "$2"; then echo "ok    $1"; else
		echo "FAIL  $1"
		fails=1
	fi
}

# variant OUT VERSION [PATCH]: build this commit as VERSION, with an optional fault applied.
variant() {
	local out=$1 ver=$2 patch=${3:-}
	git -C "$wt" checkout -q -- . && git -C "$wt" clean -qfd
	echo "$ver" >"$wt/internal/version/VERSION"
	[ -n "$patch" ] && (cd "$wt" && eval "$patch")
	(cd "$wt" && CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -o "$out" ./cmd/debuff) || {
		echo "variant $ver failed to build"
		exit 1
	}
}
health500='sed -i "" "s|mux.HandleFunc(\"GET /healthz\", func(w http.ResponseWriter, _ \*http.Request) {|&\n\t\thttp.Error(w, \"bad build\", 500)\n\t\treturn|" internal/server/server.go'
crash='sed -i "" "s|^func main() {|&\n\tos.Exit(3)|" cmd/debuff/main.go'
variant "$tmp/a" 8.8.1
variant "$tmp/b" 8.8.2
variant "$tmp/bad-health" 8.8.3 "$health500"
variant "$tmp/bad-crash" 8.8.4 "$crash"

scripts=$root/scripts
echo "first install"
"$scripts/deploy.sh" "$tmp/a" >"$tmp/1.log" 2>&1
check "installs and answers 8.8.1" '[ "$(served_version)" = 8.8.1 ]'
check "status is clean" '"$scripts/status.sh" >/dev/null'
check "the state dir is private" '[ "$(stat -f %Lp "$STATE")" = 700 ]'
check "the daily scan is scheduled" 'scan_loaded'
check "the daily scan only touches this install" 'grep -q "$BIN" "$SCAN_PLIST" && grep -q "$STATE" "$SCAN_PLIST" && ! grep -q "$HOME/.local/state" "$SCAN_PLIST"'

echo "upgrade"
"$scripts/deploy.sh" "$tmp/b" >"$tmp/2.log" 2>&1
check "upgrades and answers 8.8.2" '[ "$(served_version)" = 8.8.2 ]'
check "keeps 8.8.1 for rollback" '[ "$("$PREV" version)" = 8.8.1 ]'

echo "bad build: healthz answers 500"
"$scripts/deploy.sh" "$tmp/bad-health" >"$tmp/3.log" 2>&1
check "deploy exits non-zero" '[ $? -ne 0 ] || ! grep -q "✓ deployed" "$tmp/3.log"'
check "says it rolled back" 'grep -q "previous version restored" "$tmp/3.log"'
check "8.8.2 is serving again" '[ "$(served_version)" = 8.8.2 ]'
check "8.8.2 is the installed binary" '[ "$("$BIN" version)" = 8.8.2 ]'
check "the bad build is gone from the rollback slot" '[ "$("$PREV" version)" = 8.8.1 ]'

echo "bad build: runs, then crashes on start"
"$scripts/deploy.sh" "$tmp/b" >/dev/null 2>&1 # back to a known state, so PREV is 8.8.2
if "$scripts/deploy.sh" "$tmp/bad-crash" >"$tmp/4.log" 2>&1; then
	check "a crashing binary is refused" 'false'
else
	check "a crashing binary is refused before install" 'grep -q "nothing installed" "$tmp/4.log"'
fi
check "8.8.2 still serving" '[ "$(served_version)" = 8.8.2 ]'

echo "bad build: starts, then dies serving (a state format it can't read)"
echo '{"format": 99}' >"$STATE/state.json"
"$scripts/deploy.sh" "$tmp/a" >"$tmp/5.log" 2>&1
check "a binary that can't start doesn't report success" '! grep -q "✓ deployed" "$tmp/5.log"'
check "the log names the cause" 'grep -q "format 99" "$STATE/serve.log"'
rm -f "$STATE/state.json"
launchctl kickstart -k "$DOMAIN/$LABEL"
check "service recovers once the data is readable" 'wait_for_version "$("$BIN" version)"'

echo "manual rollback, there and back"
"$scripts/deploy.sh" "$tmp/a" >/dev/null 2>&1
"$scripts/deploy.sh" "$tmp/b" >/dev/null 2>&1
"$scripts/rollback.sh" >/dev/null 2>&1
check "rollback serves 8.8.1" '[ "$(served_version)" = 8.8.1 ]'
"$scripts/rollback.sh" >/dev/null 2>&1
check "rolling back again goes forward to 8.8.2" '[ "$(served_version)" = 8.8.2 ]'

echo "status notices a failed scan and a missing schedule"
launchctl bootout "$DOMAIN/$SCAN_LABEL" 2>/dev/null
for _ in $(seq 1 20); do scan_loaded || break; sleep 0.25; done
check "status fails with no daily scan" '! "$scripts/status.sh" >/dev/null'
"$scripts/deploy.sh" "$tmp/b" >/dev/null 2>&1
check "a deploy puts the daily scan back" 'scan_loaded'
printf '{"format":1,"at":"2026-01-01T00:00:00Z","error":"rehearsed failure"}\n' >"$STATE/last-scan.json"
check "status fails after a failed scan" '! "$scripts/status.sh" >/dev/null'
rm -f "$STATE/last-scan.json"

echo "status notices trouble"
launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null
for _ in $(seq 1 20); do loaded || break; sleep 0.25; done
check "status fails when the service is down" '! "$scripts/status.sh" >/dev/null'

echo "status notices a binary replaced underneath a running service"
"$scripts/deploy.sh" "$tmp/a" >/dev/null 2>&1
cp "$tmp/b" "$BIN.new" && mv -f "$BIN.new" "$BIN"
check "status fails while the old build keeps serving" '! "$scripts/status.sh" >/dev/null'
launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null

check "the real install was never touched" '[ "$(shasum "$HOME/.local/bin/debuff" "$HOME/Library/LaunchAgents/local.debuff.scan.plist" 2>/dev/null)" = "$real_before" ]'
[ "$fails" = 0 ] && echo && echo "✓ deploy path proven" || echo "✗ deploy path has a hole"
exit "$fails"
