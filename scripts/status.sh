#!/usr/bin/env bash
# Is Debuff up, and is what's running what's installed? Needs no agent. Exit 1 on any problem.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/scripts/lib.sh"
bad=0
ok() { echo "ok    $1"; }
no() {
	echo "FAIL  $1"
	bad=1
}

if [ -x "$BIN" ]; then ok "installed: $("$BIN" version) at $BIN"; else no "no binary at $BIN (just deploy)"; fi
if [ -x "$PREV" ]; then ok "rollback ready: $("$PREV" version)"; else echo "note  no previous binary yet"; fi
if loaded; then
	ok "launchd unit loaded: $LABEL"
	pid=$(launchctl print "$DOMAIN/$LABEL" | sed -nE 's/^[[:space:]]*pid = ([0-9]+)/\1/p' | head -1)
	if [ -n "$pid" ]; then
		# The binary the process actually started from: a file replaced underneath a running
		# service looks patched on disk while the old code keeps serving.
		ran=$(lsof -p "$pid" 2>/dev/null | awk '$4=="txt"{print $NF; exit}')
		# realpath both sides: /var and /tmp are symlinks on macOS.
		if [ "$(realpath "$ran" 2>/dev/null)" = "$(realpath "$BIN" 2>/dev/null)" ]; then
			ok "running pid $pid from $BIN"
		else
			no "pid $pid is running ${ran:-a deleted file}, not $BIN: restart it"
		fi
		ok "up since $(ps -o lstart= -p "$pid" | xargs)"
	else
		no "unit loaded, but no process"
	fi
else
	no "launchd unit not loaded: $LABEL"
fi
sv=$(served_version)
if [ -n "$sv" ]; then
	ok "healthy on http://$ADDR, serving $sv"
	if [ -x "$BIN" ] && [ "$sv" != "$("$BIN" version)" ]; then no "serving $sv but $("$BIN" version) is installed: restart it"; fi
else
	no "no healthy answer on http://$ADDR"
fi
if scan_loaded; then
	code=$(launchctl print "$DOMAIN/$SCAN_LABEL" | sed -nE 's/^[[:space:]]*last exit code = (.*)/\1/p' | head -1)
	case "$code" in
	0 | *never*) ok "daily scan loaded: $SCAN_LABEL, last exit: ${code:-none}" ;;
	*) no "the daily scan last exited $code: tail $STATE/scan.log" ;;
	esac
else
	no "daily scan not loaded: $SCAN_LABEL (just deploy)"
fi
if [ -f "$STATE/last-scan.json" ] && grep -q '"error"' "$STATE/last-scan.json"; then
	no "the last scan failed: $(sed -nE 's/.*"error": "(.*)".*/\1/p' "$STATE/last-scan.json")"
fi
if [ -d "$STATE" ]; then
	m=$(stat -f '%Lp' "$STATE")
	[ "$m" = "700" ] && ok "state dir private: $STATE" || no "state dir is mode $m: $STATE"
else
	no "no state dir at $STATE"
fi
exit "$bad"
