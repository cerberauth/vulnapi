package api

import (
	"github.com/cerberauth/vulnapi/report"
)

type HTTPResponseReports struct {
	Reports []*report.Report `json:"reports"`
}
