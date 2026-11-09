#!/usr/bin/env bash
# Build this tree, serve the labeled sample data on a throwaway state dir, and shoot every layout that
# matters into dist/shots/. The eye for UI work: build → serve → shoot → read the images.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
tmp=$(mktemp -d)
scripts/build.sh "$tmp/debuff" >/dev/null
"$tmp/debuff" serve --demo --addr 127.0.0.1:0 --state-dir "$tmp/state" >"$tmp/log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null; rm -rf "$tmp"' EXIT
url=""
for _ in $(seq 1 50); do
	url=$(sed -nE 's#.*listening on (http://[^ ]+).*#\1#p' "$tmp/log")
	[ -n "$url" ] && break
	sleep 0.1
done
[ -n "$url" ] || {
	cat "$tmp/log"
	exit 1
}
out=dist/shots
# Sample data only, so these are safe under the repo. Real scans go through `just shot`, into the data dir.
url="$url/?token=$(cat "$tmp/state/token")&x="
open=".findings summary||.row summary"
source "$root/scripts/playwright.sh"
# Sample data's rescan pretends for longer than a press waits, so this also proves the scanning state.
node scripts/press.mjs "$PLAYWRIGHT_DIR" "$url" "$out/rescan-done-dark.png" expect-scanning
# The same for an update: the button runs (pretends to), the page says so, then a rescan catches it up.
node scripts/press.mjs "$PLAYWRIGHT_DIR" "$url&view=updates" "$out/update-done-dark.png" expect-updating
scripts/shot.sh "$url" "$out/inbox-dark.png" 2555x1209 dark
scripts/shot.sh "$url&view=updates" "$out/updates-dark.png" 2555x1209 dark
scripts/shot.sh "$url&view=updates" "$out/updates-laptop-light.png" desktop light
scripts/shot.sh "$url&view=updates" "$out/updates-phone-dark.png" phone dark
# A real machine's size: long lists are where a layout breaks.
scripts/shot.sh "$url&sample=many" "$out/many-dark.png" 2555x1209 dark
scripts/shot.sh "$url&sample=many" "$out/many-laptop-light.png" desktop light
scripts/shot.sh "$url&sample=many" "$out/many-phone-dark.png" phone dark
scripts/shot.sh "$url&sample=many" "$out/many-open-light.png" 2555x1209 light ".card:nth-child(2) .findings summary"
scripts/shot.sh "$url" "$out/inbox-light.png" 2555x1209 light
scripts/shot.sh "$url" "$out/laptop-dark.png" desktop dark
scripts/shot.sh "$url" "$out/row-open-light.png" desktop light "$open"
scripts/shot.sh "$url&min=all" "$out/all-dark.png" desktop dark
scripts/shot.sh "$url&app=Example+Mail&min=all" "$out/app-dark.png" desktop dark
scripts/shot.sh "$url" "$out/phone-dark.png" phone dark
scripts/shot.sh "$url" "$out/phone-open-light.png" phone light "$open"
scripts/shot.sh "$url&view=exploited" "$out/exploited-dark.png" desktop dark
