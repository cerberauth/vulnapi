package scan

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

type OperationScanHandlerFunc func(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error)

type OperationScanHandler struct {
	ID      string
	Handler OperationScanHandlerFunc
}

type OperationScan struct {
	Operation   *request.Operation
	ScanHandler *OperationScanHandler
}

func NewOperationScanHandler(id string, handler OperationScanHandlerFunc) *OperationScanHandler {
	return &OperationScanHandler{
		ID:      id,
		Handler: handler,
	}
}
