package cmd_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewScanVulnerabilityReports(t *testing.T) {
	operation, _ := request.NewOperation(request.DefaultClient, "GET", "/api/v1/")
	sr := &report.ScanReport{
		Vulns: []*report.VulnerabilityReport{
			{
				Issue: report.Issue{
					Name: "Vuln1",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status: report.VulnerabilityReportStatusFail,
			},
			{
				Issue: report.Issue{
					Name: "Vuln2",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status: report.VulnerabilityReportStatusFail,
			},
		},

		Operation: operation,
	}

	vulns := cmd.NewScanVulnerabilityReports(sr)

	assert.Len(t, vulns, 2)
	assert.Equal(t, "GET", vulns[0].OperationMethod)
	assert.Equal(t, "/api/v1/", vulns[0].OperationPath)
	assert.Equal(t, "Vuln1", vulns[0].Vuln.Issue.Name)
	assert.Equal(t, "GET", vulns[1].OperationMethod)
	assert.Equal(t, "/api/v1/", vulns[1].OperationPath)
	assert.Equal(t, "Vuln2", vulns[1].Vuln.Issue.Name)
}

func TestNewFullScanVulnerabilityReports(t *testing.T) {
	operation, _ := request.NewOperation(request.DefaultClient, "GET", "/api/v1/")
	sr1 := &report.ScanReport{
		Vulns: []*report.VulnerabilityReport{
			{
				Issue: report.Issue{
					Name: "Vuln1",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status: report.VulnerabilityReportStatusFail,
			},
			{
				Issue: report.Issue{
					Name: "Vuln2",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status: report.VulnerabilityReportStatusFail,
			},
		},

		Operation: operation,
	}
	sr2 := &report.ScanReport{
		Vulns: []*report.VulnerabilityReport{
			{
				Issue: report.Issue{
					Name: "Vuln3",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status: report.VulnerabilityReportStatusFail,
			},
			{
				Issue: report.Issue{
					Name: "Vuln4",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status: report.VulnerabilityReportStatusFail,
			},
		},

		Operation: operation,
	}

	vulns := cmd.NewFullScanVulnerabilityReports([]*report.ScanReport{sr1, sr2})

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
