#!/usr/bin/env bash
# Screenshot the console: url out [viewport] [dark|light] [selector to click]. Fails on a console error,
# a CSP violation or horizontal overflow, so reading the image isn't the only check.
set -euo pipefail
url=$1
out=$2
viewport=${3:-desktop}
theme=${4:-dark}
click=${5:-}
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/scripts/playwright.sh"
mkdir -p "$(dirname "$out")"
node "$root/scripts/shot.mjs" "$PLAYWRIGHT_DIR" "$url" "$out" "$viewport" "$theme" "$click"
echo "$out"
