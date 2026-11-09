#!/usr/bin/env bash
# Install a built binary and bring the service up on it. The running version must then answer
# healthy, or the previous binary goes back automatically and this exits non-zero.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/scripts/lib.sh"
new=${1:-$root/dist/debuff}
[ -x "$new" ] || {
	echo "✗ no binary at $new (just build)"
	exit 1
}
want=$("$new" version) || {
	echo "✗ $new won't even report a version: nothing installed"
	exit 1
}
mkdir -p "$PREFIX" "$AGENTS" "$STATE"
chmod 700 "$STATE"

rendered=$(mktemp)
trap 'rm -f "$rendered"' EXIT
sed -e "s#@LABEL@#$LABEL#g" -e "s#@BIN@#$BIN#g" -e "s#@ADDR@#$ADDR#g" -e "s#@STATE@#$STATE#g" \
	"$root/launchd/serve.plist.in" >"$rendered"
plutil -lint "$rendered" >/dev/null || {
	echo "✗ the rendered plist is invalid"
	exit 1
}

had_prev=0
rm -f "$PREV.keep"
if [ -x "$BIN" ]; then
	# The rollback slot's current occupant, in case this deploy fails and has to be undone.
	[ -x "$PREV" ] && cp -p "$PREV" "$PREV.keep"
	cp -p "$BIN" "$PREV.new" && mv -f "$PREV.new" "$PREV"
	had_prev=1
	echo "kept previous: $("$PREV" version)"
fi
# A new file then a rename: overwriting a running binary in place gets it killed on macOS.
cp "$new" "$BIN.new" && chmod 755 "$BIN.new" && mv -f "$BIN.new" "$BIN"

restart() {
	if ! loaded; then
		launchctl bootstrap "$DOMAIN" "$PLIST"
	else
		launchctl kickstart -k "$DOMAIN/$LABEL"
	fi
}
if ! cmp -s "$rendered" "$PLIST"; then
	loaded && launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null
	for _ in $(seq 1 20); do loaded || break; sleep 0.25; done
	cp "$rendered" "$PLIST"
fi
restart

# The daily scan. It runs whatever binary is installed, so only a change to its plist needs a reload.
install_schedule() {
	local rendered
	rendered=$(mktemp)
	sed -e "s#@LABEL@#$SCAN_LABEL#g" -e "s#@BIN@#$BIN#g" -e "s#@STATE@#$STATE#g" "$root/launchd/scan.plist.in" >"$rendered"
	plutil -lint "$rendered" >/dev/null || {
		rm -f "$rendered"
		return 1
	}
	if ! cmp -s "$rendered" "$SCAN_PLIST"; then
		scan_loaded && launchctl bootout "$DOMAIN/$SCAN_LABEL" 2>/dev/null
		for _ in $(seq 1 20); do scan_loaded || break; sleep 0.25; done
		cp "$rendered" "$SCAN_PLIST"
	fi
	rm -f "$rendered"
	scan_loaded || launchctl bootstrap "$DOMAIN" "$SCAN_PLIST"
}

if wait_for_version "$want"; then
	rm -f "$PREV.keep"
	if ! install_schedule; then
		echo "✗ deployed $want, but the daily scan wasn't installed"
		exit 1
	fi
	echo "✓ deployed $want on http://$ADDR"
	exit 0
fi
echo "✗ $want did not answer healthy on http://$ADDR"
tail -5 "$STATE/serve.log" 2>/dev/null
if [ "$had_prev" = 1 ]; then
	echo "rolling back…"
	# Undo the deploy completely: a plain rollback would leave the bad build in the rollback slot.
	if "$root/scripts/rollback.sh"; then
		rm -f "$PREV"
		[ -x "$PREV.keep" ] && mv -f "$PREV.keep" "$PREV"
		echo "✗ deploy failed; previous version restored"
		exit 1
	fi
	echo "✗✗ deploy failed AND the rollback failed: see RUNBOOK.md"
else
	echo "✗ deploy failed and there is no previous version to restore"
fi
exit 1
