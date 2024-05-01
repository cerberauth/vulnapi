package api_test

import (
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/api"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestFormatReports(t *testing.T) {
	startTime := time.Now()
	endTime := time.Now().Add(time.Second)
	reports := []*report.ScanReport{
		{
			ID:        "123",
			Name:      "Test Report",
			StartTime: startTime,
			EndTime:   endTime,
			Vulns: []*report.VulnerabilityReport{
				{
					OWASP2023Category: report.OWASP2023BFLACategory,

					ID:   "vulnerability-1",
					Name: "Vulnerability 1",
				},
				{
					OWASP2023Category: report.OWASP2023BOPLCategory,

					ID:   "vulnerability-2",
					Name: "Vulnerability 2",
				},
			},
		},
	}

	expected := []api.HTTPResponseReport{
		{
			ID:        "123",
			Name:      "Test Report",
			StartTime: startTime,
			EndTime:   endTime,
			Vulns: []api.HTTPResponseVulnerability{
				{
					OWASP2023Category: report.OWASP2023BFLACategory,

					ID:   "vulnerability-1",
					Name: "Vulnerability 1",
				},
				{
					OWASP2023Category: report.OWASP2023BOPLCategory,

					ID:   "vulnerability-2",
					Name: "Vulnerability 2",
				},
			},
		},
	}
	result := api.FormatReports(reports)

	assert.Equal(t, expected, result)
}

func TestFormatReportsWithNoVulnerabilities(t *testing.T) {
	startTime := time.Now()
	endTime := time.Now().Add(time.Second)
	reports := []*report.ScanReport{
		{
			ID:        "123",
			Name:      "Test Report",
			StartTime: startTime,
			EndTime:   endTime,
			Vulns:     nil,
		},
	}

	expected := []api.HTTPResponseReport{
		{
			ID:        "123",
			Name:      "Test Report",
			StartTime: startTime,
			EndTime:   endTime,
			Vulns:     []api.HTTPResponseVulnerability{},
		},
	}
	result := api.FormatReports(reports)

	assert.Equal(t, expected, result)
}
