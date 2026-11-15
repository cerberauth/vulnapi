package config

import (
	"time"

	"github.com/cerberauth/reportx"
)

type SuppressionResult struct {
	Suppressed int
	Expired    []Suppression
}

func (s Suppression) Expired(now time.Time) bool {
	return !now.Before(s.Expires.AddDate(0, 0, 1))
}

// ApplySuppressions marks the active findings matched by an unexpired
// suppression as accepted risk. Findings matched only by an expired
// suppression stay active. matchCheck reports whether a suppression check
// ID selects a finding's check ID.
func ApplySuppressions(r *reportx.Report, suppressions []Suppression, now time.Time, matchCheck func(pattern, checkID string) bool) SuppressionResult {
	var result SuppressionResult
	if r == nil || len(suppressions) == 0 {
		return result
	}
	expired := map[int]bool{}
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.Status != reportx.StatusActive && f.Status != "" {
			continue
		}
		for j, s := range suppressions {
			if !matchCheck(s.Check, f.ID) || (s.Operation != "" && s.Operation != f.Extra["operation_id"]) {
				continue
			}
			if s.Expired(now) {
				expired[j] = true
				continue
			}
			f.Status = reportx.StatusAcceptedRisk
			if f.Extra == nil {
				f.Extra = map[string]string{}
			}
			f.Extra["suppression_reason"] = s.Reason
			f.Extra["suppression_expires"] = s.Expires.Format(DateLayout)
			result.Suppressed++
			break
		}
	}
	for j, s := range suppressions {
		if expired[j] {
			result.Expired = append(result.Expired, s)
		}
	}
	return result
}
