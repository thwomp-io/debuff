package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/thwomp-io/debuff/internal/fetch"
)

// NVDHost is NVD's API. It allows 5 requests in 30 seconds without a key, and an old version's answer can take a
// minute (verified 2026-11-03), so it gets its own pace and deadline.
const NVDHost = "services.nvd.nist.gov"

// NVDRule is the pace and deadline for that host.
var NVDRule = fetch.HostRule{Pace: 6500 * time.Millisecond, Timeout: 120 * time.Second}

// NVD's answer doesn't change by the hour, and a new version is a new question, so an update is seen at once.
const nvdTTL = 24 * time.Hour

const maxNVDPages = 5

// NVDFinding is one CVE NVD lists for a product at a version.
type NVDFinding struct {
	CVE, Severity, Title, Published, FixedIn string
	// Ranged: NVD names this version or a range around it. Without that, an entry can match every version there is.
	Ranged bool
}

type nvdPage struct {
	Total           int `json:"totalResults"`
	PerPage         int `json:"resultsPerPage"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			Status       string `json:"vulnStatus"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics        map[string][]nvdMetric `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Vulnerable          bool   `json:"vulnerable"`
						Criteria            string `json:"criteria"`
						VersionEndExcluding string `json:"versionEndExcluding"`
						VersionEndIncluding string `json:"versionEndIncluding"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	Data struct {
		Severity string `json:"baseSeverity"`
	} `json:"cvssData"`
	Severity string `json:"baseSeverity"` // where version 2 keeps it
}

func (m nvdMetric) severity() string {
	if m.Data.Severity != "" {
		return m.Data.Severity
	}
	return m.Severity
}

// ParseNVD reads one page, which is untrusted. It keeps only what it can use, and a rejected CVE isn't a finding.
func ParseNVD(b []byte, cpe, version string) ([]NVDFinding, int, error) {
	var p nvdPage
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, 0, err
	}
	out := make([]NVDFinding, 0, len(p.Vulnerabilities))
	for _, v := range p.Vulnerabilities {
		c := v.CVE
		if c.ID == "" || strings.EqualFold(c.Status, "Rejected") {
			continue
		}
		f := NVDFinding{CVE: c.ID, Published: c.Published}
		if len(f.Published) > 10 {
			f.Published = f.Published[:10]
		}
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				f.Title = firstSentence(d.Value)
				break
			}
		}
		for _, k := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			if m := c.Metrics[k]; len(m) > 0 && m[0].severity() != "" {
				f.Severity = m[0].severity()
				break
			}
		}
		want := ":" + cpe + ":"
		for _, cfg := range c.Configurations {
			for _, n := range cfg.Nodes {
				for _, m := range n.CPEMatch {
					if m.Vulnerable && strings.Contains(m.Criteria, want) && (m.VersionEndExcluding != "" || m.VersionEndIncluding != "" || exactVersion(m.Criteria)) {
						f.Ranged = true
					}
					end := m.VersionEndExcluding
					if !m.Vulnerable || end == "" || !strings.Contains(m.Criteria, want) || CompareVersions(end, version) <= 0 {
						continue
					}
					if f.FixedIn == "" || CompareVersions(end, f.FixedIn) < 0 {
						f.FixedIn = end
					}
				}
			}
		}
		out = append(out, f)
	}
	return out, p.Total, nil
}

// exactVersion: the CPE's version field names a version, not a wildcard. cpe:2.3:a:vendor:product:version:...
func exactVersion(criteria string) bool {
	p := strings.Split(criteria, ":")
	return len(p) > 5 && p[5] != "*" && p[5] != "-"
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i > 0 {
		s = s[:i]
	}
	const limit = 120
	if r := []rune(s); len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return s
}

// NVDAffected asks what NVD lists for a product at a version. A version that isn't plain digits can't go in the
// question, and comes back as an error rather than as no findings.
func NVDAffected(ctx context.Context, c *fetch.Client, cpe, version string) ([]NVDFinding, fetch.Result, error) {
	if !plainVersion.MatchString(version) {
		return nil, fetch.Result{}, fmt.Errorf("version %q can't be asked about", version)
	}
	if strings.Count(cpe, ":") != 1 {
		return nil, fetch.Result{}, errors.New("a CPE here is vendor:product")
	}
	var all []NVDFinding
	var last fetch.Result
	for start, page := 0, 0; page < maxNVDPages; page++ {
		q := url.Values{"virtualMatchString": {"cpe:2.3:a:" + cpe + ":" + version}, "resultsPerPage": {"2000"}}
		if start > 0 {
			q.Set("startIndex", fmt.Sprint(start))
		}
		name := fmt.Sprintf("nvd/%s-%s-%d.json", fetch.SafeName(cpe), fetch.SafeName(version), page)
		res, err := c.Cached(ctx, name, nvdTTL, "https://"+NVDHost+"/rest/json/cves/2.0?"+q.Encode())
		if err != nil {
			return all, res, err
		}
		last = res
		found, total, err := ParseNVD(res.Body, cpe, version)
		if err != nil {
			return all, res, err
		}
		all = append(all, found...)
		start += 2000
		if start >= total {
			return all, last, nil
		}
	}
	return all, last, errors.New("NVD's answer ran past the page cap")
}
