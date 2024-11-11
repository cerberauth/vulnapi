package scan

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/report"
)

type OperationScanHandlerFunc func(operation *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error)

type OperationScanHandler struct {
	ID      string
	Handler OperationScanHandlerFunc
}

type OperationScan struct {
	Operation   *operation.Operation
	ScanHandler *OperationScanHandler
}

func NewOperationScanHandler(id string, handler OperationScanHandlerFunc) *OperationScanHandler {
	return &OperationScanHandler{
		ID:      id,
		Handler: handler,
	}
}
