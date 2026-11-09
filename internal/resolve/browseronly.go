package resolve

import (
	"regexp"
	"strings"
)

// Chrome features an Electron app doesn't ship or expose. A heuristic: findings here get hidden unless
// asked for, never dropped, and a plain Chromium keeps all of them.
var browserOnly = regexp.MustCompile(`(?i)^(Extensions?|Mobile|Passwords?|WebAppInstalls?|Chromoting|Omnibox|Payments?|Actor|Autofill|Safe ?browsing|Downloads?|Transactions Platform|Tab ?Strip|Tabs?|Side ?Panel|Browser UI|Bookmarks?|History|Sync|Sign-?in|Custom Tabs|WebView|Android|Feedback|Enterprise|Glic|Lens|Reader ?Mode|Translate|New Tab Page|Profiles?|Split ?View|Toolbar|Installer|Updater|PageInfo|Page Info)\b`)

// BrowserOnly says whether a CVE's component is a Chrome feature rather than the engine.
func BrowserOnly(component string) bool {
	area := component
	if i := strings.LastIndex(area, " in "); i >= 0 {
		area = area[i+4:]
	}
	return browserOnly.MatchString(area)
}
