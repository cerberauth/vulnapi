package api

import (
	"github.com/cerberauth/vulnapi/report"
)

const errorKey = "error"

type HTTPResponseReports struct {
	Reports []*report.ScanReport `json:"reports"`
}
