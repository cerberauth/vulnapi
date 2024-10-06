package printtable_test

import (
	"testing"

	printtable "github.com/cerberauth/vulnapi/internal/cmd/printtable"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewScanVulnerabilityReports(t *testing.T) {
	sr := &report.Report{
		Vulns: []*report.VulnerabilityReport{
			{
				Issue: report.Issue{
					Name: "Vuln1",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status: report.VulnerabilityReportStatusFailed,
			},
			{
				Issue: report.Issue{
					Name: "Vuln2",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status: report.VulnerabilityReportStatusFailed,
			},
		},

		Operation: report.ReportOperation{
			Method: "GET",
			URL:    "/api/v1/",
		},
	}

	vulns := printtable.NewScanVulnerabilityReports(sr)

	assert.Len(t, vulns, 2)
	assert.Equal(t, "GET", vulns[0].OperationMethod)
	assert.Equal(t, "/api/v1/", vulns[0].OperationPath)
	assert.Equal(t, "Vuln1", vulns[0].Vuln.Issue.Name)
	assert.Equal(t, "GET", vulns[1].OperationMethod)
	assert.Equal(t, "/api/v1/", vulns[1].OperationPath)
	assert.Equal(t, "Vuln2", vulns[1].Vuln.Issue.Name)
}

func TestNewFullScanVulnerabilityReports(t *testing.T) {
	sr1 := &report.Report{
		Vulns: []*report.VulnerabilityReport{
			{
				Issue: report.Issue{
					Name: "Vuln1",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status: report.VulnerabilityReportStatusFailed,
			},
			{
				Issue: report.Issue{
					Name: "Vuln2",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status: report.VulnerabilityReportStatusFailed,
			},
		},

		Operation: report.ReportOperation{
			Method: "GET",
			URL:    "/api/v1/",
		},
	}
	sr2 := &report.Report{
		Vulns: []*report.VulnerabilityReport{
			{
				Issue: report.Issue{
					Name: "Vuln3",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status: report.VulnerabilityReportStatusFailed,
			},
			{
				Issue: report.Issue{
					Name: "Vuln4",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status: report.VulnerabilityReportStatusFailed,
			},
		},

		Operation: report.ReportOperation{
			Method: "GET",
			URL:    "/api/v1/",
		},
	}

	vulns := printtable.NewFullScanVulnerabilityReports([]*report.Report{sr1, sr2})

	assert.Len(t, vulns, 4)
	assert.Equal(t, "GET", vulns[0].OperationMethod)
	assert.Equal(t, "/api/v1/", vulns[0].OperationPath)
	assert.Equal(t, "Vuln1", vulns[0].Vuln.Issue.Name)
	assert.Equal(t, "GET", vulns[1].OperationMethod)
	assert.Equal(t, "/api/v1/", vulns[1].OperationPath)
	assert.Equal(t, "Vuln2", vulns[1].Vuln.Issue.Name)
	assert.Equal(t, "GET", vulns[2].OperationMethod)
	assert.Equal(t, "/api/v1/", vulns[2].OperationPath)
	assert.Equal(t, "Vuln3", vulns[2].Vuln.Issue.Name)
	assert.Equal(t, "GET", vulns[3].OperationMethod)
	assert.Equal(t, "/api/v1/", vulns[3].OperationPath)
	assert.Equal(t, "Vuln4", vulns[3].Vuln.Issue.Name)
}
