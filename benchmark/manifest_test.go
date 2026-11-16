package benchmark_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/benchmark"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadManifests(t *testing.T) {
	manifests, err := benchmark.LoadManifests(".")
	require.NoError(t, err)
	require.NotEmpty(t, manifests)
	for _, m := range manifests {
		assert.NotEmpty(t, m.Scans, m.Name)
	}
}

func TestLoadManifest_Invalid(t *testing.T) {
	tests := map[string]string{
		"unknown key":   "name: x\nversion: '1'\nscans: []\nfoo: bar\n",
		"no scan":       "name: x\nversion: '1'\nscans: []\n",
		"no check":      "name: x\nversion: '1'\nscans:\n  - name: s\n    args: [scan]\n    issues:\n      - { id: a, title: A }\n",
		"check and nc":  "name: x\nversion: '1'\nscans:\n  - name: s\n    args: [scan]\n    issues:\n      - { id: a, title: A, check: c, notCovered: https://example.com }\n",
		"duplicate":     "name: x\nversion: '1'\nscans:\n  - name: s\n    args: [scan]\n    issues:\n      - { id: a, title: A, check: c }\n      - { id: a, title: B, check: d }\n",
		"miss no check": "name: x\nversion: '1'\nscans:\n  - name: s\n    args: [scan]\n    issues:\n      - { id: a, title: A, notCovered: https://example.com, knownMiss: https://example.com }\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "expected.yaml")
			require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
			_, err := benchmark.LoadManifest(path)
			assert.Error(t, err)
		})
	}
}

func testScan() benchmark.Scan {
	return benchmark.Scan{Name: "openapi", Issues: []benchmark.Issue{
		{ID: "weak-secret", Title: "Weak secret", Check: "jwt.weak_secret"},
		{ID: "headers", Title: "Headers", Check: "misconfiguration.http_headers"},
		{ID: "alg-none", Title: "Alg none", Check: "jwt.alg_none", Operation: "getUser"},
		{ID: "fuzz", Title: "Fuzz", Check: "jwt.fuzz", KnownMiss: "https://example.com/1"},
		{ID: "trace", Title: "Trace", Check: "misconfiguration.http_trace", KnownMiss: "https://example.com/2"},
		{ID: "bola", Title: "BOLA", NotCovered: "https://example.com/3"},
	}}
}

func TestCompare(t *testing.T) {
	report := &benchmark.Report{Findings: []benchmark.Finding{
		{ID: "jwt.weak_secret", Status: "active", CVSS40Score: 9.3},
		{ID: "misconfiguration.http_headers_hsts_missing", CVSS40Score: 0},
		{ID: "jwt.alg_none", Status: "active", CVSS40Score: 9.3, Extra: map[string]string{"operation_id": "listUsers"}},
		{ID: "misconfiguration.http_trace", Status: "active", CVSS40Score: 0},
		{ID: "no_verification", Status: "active", CVSS40Score: 9.3},
		{ID: "no_verification", Status: "active", CVSS40Score: 9.3},
		{ID: "discover.accept_unauthenticated", Status: "active", CVSS40Score: 0},
		{ID: "jwt.null_signature", Status: "accepted_risk", CVSS40Score: 9.3},
	}}

	result := benchmark.Compare("VAmPI", testScan(), report)

	statuses := map[string]benchmark.Status{}
	for _, issue := range result.Issues {
		statuses[issue.Issue.ID] = issue.Status
	}
	assert.Equal(t, map[string]benchmark.Status{
		"weak-secret": benchmark.StatusDetected,
		"headers":     benchmark.StatusDetected,
		"alg-none":    benchmark.StatusMissed,
		"fuzz":        benchmark.StatusKnownMiss,
		"trace":       benchmark.StatusNowDetected,
		"bola":        benchmark.StatusNotCovered,
	}, statuses)
	assert.Equal(t, map[string]int{"no_verification": 2, "jwt.alg_none": 1}, result.Unexpected)
	assert.Equal(t, 3, result.UnexpectedCount())
	require.Len(t, result.Regressions(), 1)
	assert.Equal(t, "alg-none", result.Regressions()[0].ID)
}

func TestCompare_LegacyCheckIDs(t *testing.T) {
	report := &benchmark.Report{Findings: []benchmark.Finding{{ID: "secret", Status: "active", CVSS40Score: 9.3}}}
	result := benchmark.Compare("VAmPI", benchmark.Scan{Name: "s", Issues: []benchmark.Issue{{ID: "a", Title: "A", Check: "jwt.weak_secret"}}}, report)
	assert.Equal(t, benchmark.StatusDetected, result.Issues[0].Status)
}

func TestParseReport(t *testing.T) {
	report, err := benchmark.ParseReport([]byte(`{"findings":[{"id":"jwt.alg_none","status":"active","cvss40_score":9.3,"extra":{"operation_id":"getUser"}}]}`))
	require.NoError(t, err)
	assert.Equal(t, []benchmark.Finding{{ID: "jwt.alg_none", Status: "active", CVSS40Score: 9.3, Extra: map[string]string{"operation_id": "getUser"}}}, report.Findings)
}

func TestRunMarkdown(t *testing.T) {
	m := &benchmark.Manifest{Name: "VAmPI", URL: "https://github.com/erev0s/VAmPI", Version: "erev0s/vampi@sha256:0a5a"}
	result := benchmark.Compare("VAmPI", testScan(), &benchmark.Report{Findings: []benchmark.Finding{
		{ID: "jwt.weak_secret", CVSS40Score: 9.3},
		{ID: "no_verification", CVSS40Score: 9.3},
	}})
	run := benchmark.Run{VulnAPIVersion: "v1.2.3", Date: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC), Manifests: []*benchmark.Manifest{m}, Results: []benchmark.ScanResult{result}}

	en := run.Markdown("en")
	assert.Contains(t, en, "VulnAPI v1.2.3, 2026-11-15.")
	assert.Contains(t, en, "**1 of 6 known issues detected (17%)**, 2 missed, 2 known misses, 1 not covered by a check yet, 1 unexpected findings.")
	assert.Contains(t, en, "| [VAmPI](https://github.com/erev0s/VAmPI) | `erev0s/vampi@sha256:0a5a` | 6 | 1 | 2 | 2 | 1 | 1 |")
	assert.Contains(t, en, "| openapi | BOLA | - | [not covered](https://example.com/3) |")
	assert.Contains(t, en, "- openapi: `no_verification` (1)")

	fr := run.Markdown("fr")
	assert.Contains(t, fr, "**1 problèmes connus détectés sur 6 (17%)**")
	assert.Contains(t, fr, "[non couvert](https://example.com/3)")
}
