package config_test

import (
	"testing"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/vulnapi/config"
	"github.com/stretchr/testify/assert"
)

func date(t *testing.T, value string) config.Date {
	d, err := time.Parse(config.DateLayout, value)
	if err != nil {
		t.Fatal(err)
	}
	return config.Date{Time: d}
}

func TestApplySuppressions(t *testing.T) {
	newReport := func() *reportx.Report {
		return &reportx.Report{Findings: []reportx.Finding{
			{ID: "misconfiguration.http_headers_hsts_missing", Status: reportx.StatusActive, Extra: map[string]string{"operation_id": "getHealth"}},
			{ID: "misconfiguration.http_headers_hsts_missing", Status: reportx.StatusActive, Extra: map[string]string{"operation_id": "getUsers"}},
			{ID: "jwt.alg_none", Status: reportx.StatusActive, Extra: map[string]string{"operation_id": "getHealth"}},
		}}
	}
	exact := func(pattern, id string) bool { return pattern == id }
	suppression := config.Suppression{Check: "misconfiguration.http_headers_hsts_missing", Operation: "getHealth", Reason: "behind a TLS proxy", Expires: date(t, "2027-03-01")}

	t.Run("active suppression", func(t *testing.T) {
		r := newReport()
		result := config.ApplySuppressions(r, []config.Suppression{suppression}, date(t, "2027-03-01").Add(12*time.Hour), exact)

		assert.Equal(t, 1, result.Suppressed)
		assert.Empty(t, result.Expired)
		assert.Equal(t, reportx.StatusAcceptedRisk, r.Findings[0].Status)
		assert.Equal(t, "behind a TLS proxy", r.Findings[0].Extra["suppression_reason"])
		assert.Equal(t, reportx.StatusActive, r.Findings[1].Status)
		assert.Equal(t, reportx.StatusActive, r.Findings[2].Status)
	})

	t.Run("expired suppression reopens the finding", func(t *testing.T) {
		r := newReport()
		result := config.ApplySuppressions(r, []config.Suppression{suppression}, date(t, "2027-03-02").Time, exact)

		assert.Equal(t, 0, result.Suppressed)
		assert.Equal(t, []config.Suppression{suppression}, result.Expired)
		assert.Equal(t, reportx.StatusActive, r.Findings[0].Status)
	})

	t.Run("every operation", func(t *testing.T) {
		r := newReport()
		all := suppression
		all.Operation = ""
		result := config.ApplySuppressions(r, []config.Suppression{all}, date(t, "2026-01-01").Time, exact)

		assert.Equal(t, 2, result.Suppressed)
		assert.Equal(t, reportx.StatusActive, r.Findings[2].Status)
	})
}
