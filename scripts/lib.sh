# Shared by deploy, rollback and status. Every path can be overridden, so a rehearsal runs the same
# code against a throwaway install and never touches the real one.
PREFIX=${DEBUFF_PREFIX:-$HOME/.local/bin}
LABEL=${DEBUFF_LABEL:-local.debuff.serve}
ADDR=${DEBUFF_ADDR:-127.0.0.1:8737}
STATE=${DEBUFF_STATE_DIR:-$HOME/.local/state/debuff}
AGENTS=${DEBUFF_AGENTS_DIR:-$HOME/Library/LaunchAgents}
BIN=$PREFIX/debuff
PREV=$PREFIX/debuff.prev
PLIST=$AGENTS/$LABEL.plist
SCAN_LABEL=${DEBUFF_SCAN_LABEL:-local.debuff.scan}
SCAN_PLIST=$AGENTS/$SCAN_LABEL.plist
DOMAIN=gui/$(id -u)

loaded() { launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1; }

scan_loaded() { launchctl print "$DOMAIN/$SCAN_LABEL" >/dev/null 2>&1; }

served_version() {
	curl -fsS --max-time 2 "http://$ADDR/healthz" 2>/dev/null | sed -nE 's/.*"status":"ok".*"version":"([^"]+)".*/\1/p'
}

# Wait for the server to answer ok as exactly this version.
wait_for_version() {
	local want=$1 i
	for i in $(seq 1 ${2:-30}); do
		[ "$(served_version)" = "$want" ] && return 0
		sleep 0.5
	done
	return 1
}
