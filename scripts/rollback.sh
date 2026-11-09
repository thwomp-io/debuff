#!/usr/bin/env bash
# Put the previous binary back and prove it answers healthy. It swaps with the current one, so a
# second rollback goes forward again.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/scripts/lib.sh"
[ -x "$PREV" ] || {
	echo "✗ no previous binary at $PREV"
	exit 1
}
want=$("$PREV" version) || {
	echo "✗ the previous binary won't run"
	exit 1
}
mv -f "$BIN" "$BIN.swap" && mv -f "$PREV" "$BIN" && mv -f "$BIN.swap" "$PREV"
launchctl kickstart -k "$DOMAIN/$LABEL" || exit 1
if wait_for_version "$want"; then
	echo "✓ rolled back to $want"
	exit 0
fi
echo "✗ rollback to $want did not answer healthy"
exit 1
