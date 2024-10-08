package printtable_test

import (
	"testing"

	printtable "github.com/cerberauth/vulnapi/internal/cmd/printtable"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewScanIssueReports(t *testing.T) {
	operation, _ := request.NewOperation("GET", "/api/v1/", nil, nil)
	sr := &report.ScanReport{
		Issues: []*report.IssueReport{
			{
				Issue: report.Issue{
					Name: "Vuln1",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status:    report.IssueReportStatusFailed,
				Operation: operation,
			},
			{
				Issue: report.Issue{
					Name: "Vuln2",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status:    report.IssueReportStatusFailed,
				Operation: operation,
			},
		},
	}

	issues := printtable.NewScanIssueReports(sr)

	assert.Len(t, issues, 2)
	assert.Equal(t, "GET", issues[0].OperationMethod)
	assert.Equal(t, "/api/v1/", issues[0].OperationPath)
	assert.Equal(t, "Vuln1", issues[0].Issue.Name)
	assert.Equal(t, "GET", issues[1].OperationMethod)
	assert.Equal(t, "/api/v1/", issues[1].OperationPath)
	assert.Equal(t, "Vuln2", issues[1].Issue.Name)
}

func TestNewFullScanIssueReports(t *testing.T) {
	operation, _ := request.NewOperation("GET", "/api/v1/", nil, nil)
	sr1 := &report.ScanReport{
		Issues: []*report.IssueReport{
			{
				Issue: report.Issue{
					Name: "Vuln1",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status:    report.IssueReportStatusFailed,
				Operation: operation,
			},
			{
				Issue: report.Issue{
					Name: "Vuln2",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status:    report.IssueReportStatusFailed,
				Operation: operation,
			},
		},
	}
	sr2 := &report.ScanReport{
		Issues: []*report.IssueReport{
			{
				Issue: report.Issue{
					Name: "Vuln3",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status:    report.IssueReportStatusFailed,
				Operation: operation,
			},
			{
				Issue: report.Issue{
					Name: "Vuln4",
					CVSS: report.CVSS{
						Score: 5.0,
					},
				},
				Status:    report.IssueReportStatusFailed,
				Operation: operation,
			},
		},

		Operation: &report.ScanReportOperation{
			ID: "id",
		},
	}

	issues := printtable.NewFullScanIssueReports([]*report.ScanReport{sr1, sr2})

	assert.Len(t, issues, 4)
	assert.Equal(t, "GET", issues[0].OperationMethod)
	assert.Equal(t, "/api/v1/", issues[0].OperationPath)
	assert.Equal(t, "Vuln1", issues[0].Issue.Name)
	assert.Equal(t, "GET", issues[1].OperationMethod)
	assert.Equal(t, "/api/v1/", issues[1].OperationPath)
	assert.Equal(t, "Vuln2", issues[1].Issue.Name)
	assert.Equal(t, "GET", issues[2].OperationMethod)
	assert.Equal(t, "/api/v1/", issues[2].OperationPath)
	assert.Equal(t, "Vuln3", issues[2].Issue.Name)
	assert.Equal(t, "GET", issues[3].OperationMethod)
	assert.Equal(t, "/api/v1/", issues[3].OperationPath)
	assert.Equal(t, "Vuln4", issues[3].Issue.Name)
}
