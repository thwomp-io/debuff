#!/usr/bin/env bash
# Record the README's tour: build this tree, serve the labeled sample data on a throwaway state dir, walk
# the console in a real browser, and write docs/assets/tour.gif. Sample data only, so it is safe to commit.
# Needs ffmpeg and gifsicle as well as Playwright (scripts/playwright.sh).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
source "$root/scripts/playwright.sh"
for t in ffmpeg gifsicle; do
	command -v "$t" >/dev/null || {
		echo "✗ $t is not installed"
		exit 1
	}
done
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
node scripts/tour.mjs "$PLAYWRIGHT_DIR" "$url/?token=$(cat "$tmp/state/token")" "$tmp/video" "${1:-light}"
video=$(ls "$tmp"/video/*.webm | head -1)
out=docs/assets/tour.gif
mkdir -p "$(dirname "$out")"
ffmpeg -loglevel error -y -i "$video" -vf "fps=5,scale=960:-1:flags=lanczos,palettegen=max_colors=64" "$tmp/palette.png"
ffmpeg -loglevel error -y -i "$video" -i "$tmp/palette.png" -lavfi "fps=5,scale=960:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=none" "$tmp/tour.gif"
gifsicle -O3 --lossy=120 "$tmp/tour.gif" -o "$out"
echo "$out ($(($(stat -f %z "$out") / 1024)) KB)"
