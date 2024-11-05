package analytics

import (
	"context"

	"github.com/cerberauth/vulnapi/report"
)

func TrackScanReport(ctx context.Context, reporter *report.Reporter) {
	failedIssueReports := reporter.GetFailedIssueReports()
	var higherSeverityCVSS float64 = 0
	for _, failedIssueReport := range failedIssueReports {
		if failedIssueReport.CVSS.Score > higherSeverityCVSS {
			higherSeverityCVSS = failedIssueReport.CVSS.Score
		}
	}
}
