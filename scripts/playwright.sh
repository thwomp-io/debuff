# Sourced by the screenshot scripts. They are the only thing here that needs Node, so Playwright isn't a
# dependency of this repo: point PLAYWRIGHT_DIR at any directory holding node_modules/playwright.
#   mkdir -p ~/.cache/debuff-shots && cd ~/.cache/debuff-shots && npm init -y && npm i playwright && npx playwright install chromium
PLAYWRIGHT_DIR=${PLAYWRIGHT_DIR:-$HOME/.cache/debuff-shots}
[ -d "$PLAYWRIGHT_DIR/node_modules/playwright" ] || {
	echo "✗ no Playwright under $PLAYWRIGHT_DIR: set PLAYWRIGHT_DIR (see scripts/playwright.sh)"
	exit 1
}
export PLAYWRIGHT_DIR
