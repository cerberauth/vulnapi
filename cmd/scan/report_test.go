package scan_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/cmd/scan"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewScanVulnerabilityReports(t *testing.T) {
	operation, _ := request.NewOperation(request.DefaultClient, "GET", "/api/v1/", nil, nil, nil)
	sr := &report.ScanReport{
		Vulns: []*report.VulnerabilityReport{
			{
				Issue: report.Issue{
					Name: "Vuln1",
				},
			},
			{
				Issue: report.Issue{
					Name: "Vuln2",
				},
			},
		},

		Operation: operation,
	}

	vulns := scan.NewScanVulnerabilityReports(sr)

	assert.Len(t, vulns, 2)
	assert.Equal(t, "GET", vulns[0].OperationMethod)
	assert.Equal(t, "/api/v1/", vulns[0].OperationPath)
	assert.Equal(t, "Vuln1", vulns[0].Vuln.Issue.Name)
	assert.Equal(t, "GET", vulns[1].OperationMethod)
	assert.Equal(t, "/api/v1/", vulns[1].OperationPath)
	assert.Equal(t, "Vuln2", vulns[1].Vuln.Issue.Name)
}

func TestNewFullScanVulnerabilityReports(t *testing.T) {
	operation, _ := request.NewOperation(request.DefaultClient, "GET", "/api/v1/", nil, nil, nil)
	sr1 := &report.ScanReport{
		Vulns: []*report.VulnerabilityReport{
			{
				Issue: report.Issue{
					Name: "Vuln1",
				},
			},
			{
				Issue: report.Issue{
					Name: "Vuln2",
				},
			},
		},

		Operation: operation,
	}
	sr2 := &report.ScanReport{
		Vulns: []*report.VulnerabilityReport{
			{
				Issue: report.Issue{
					Name: "Vuln3",
				},
			},
			{
				Issue: report.Issue{
					Name: "Vuln4",
				},
			},
		},

		Operation: operation,
	}

	vulns := scan.NewFullScanVulnerabilityReports([]*report.ScanReport{sr1, sr2})

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
