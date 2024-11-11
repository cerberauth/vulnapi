package scan_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/stretchr/testify/assert"
)

func TestNewOperationScanHandler(t *testing.T) {
	handlerFunc := func(operation *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
		return &report.ScanReport{ID: "test-report"}, nil
	}
	handlerID := "test-handler"

	handler := scan.NewOperationScanHandler(handlerID, handlerFunc)

	assert.NotNil(t, handler)
	assert.Equal(t, handlerID, handler.ID)
	assert.NotNil(t, handler.Handler)
}
