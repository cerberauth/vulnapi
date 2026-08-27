package scan_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/stretchr/testify/assert"
)

func TestOperationScanStruct(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	os := scan.OperationScan{
		Operation: op,
		CheckID:   "test-check",
		CheckName: "Test Check",
	}

	assert.Equal(t, op, os.Operation)
	assert.Equal(t, "test-check", os.CheckID)
	assert.Equal(t, "Test Check", os.CheckName)
}
