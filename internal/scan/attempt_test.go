package scan

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/stretchr/testify/assert"
)

func TestNewIssueScanAttempt(t *testing.T) {
	req, _ := request.NewRequest(http.MethodGet, "http://example.com", nil, nil)
	res := &request.Response{}
	err := error(nil)
	op, _ := operation.NewOperationFromRequest(req)

	scanAttempt := NewIssueScanAttempt(op, req, res, err)

	assert.NotNil(t, scanAttempt)
	assert.Equal(t, IssueScanAttemptStatusNone, scanAttempt.Status)
	assert.Equal(t, req, scanAttempt.Request)
	assert.Equal(t, res, scanAttempt.Response)
	assert.Equal(t, err, scanAttempt.Err)
}

func TestIssueScanAttempt_WithBooleanStatus(t *testing.T) {
	req, _ := request.NewRequest(http.MethodGet, "http://example.com", nil, nil)
	res := &request.Response{}
	err := error(nil)
	op, _ := operation.NewOperationFromRequest(req)

	scanAttempt := NewIssueScanAttempt(op, req, res, err)

	scanAttempt.WithBooleanStatus(true)
	assert.Equal(t, IssueScanAttemptStatusPassed, scanAttempt.Status)

	scanAttempt.WithBooleanStatus(false)
	assert.Equal(t, IssueScanAttemptStatusFailed, scanAttempt.Status)
}

func TestIssueScanAttempt_Fail(t *testing.T) {
	req, _ := request.NewRequest(http.MethodGet, "http://example.com", nil, nil)
	res := &request.Response{}
	err := error(nil)
	op, _ := operation.NewOperationFromRequest(req)

	scanAttempt := NewIssueScanAttempt(op, req, res, err)
	scanAttempt.Fail()

	assert.Equal(t, IssueScanAttemptStatusFailed, scanAttempt.Status)
}

func TestIssueScanAttempt_Pass(t *testing.T) {
	req, _ := request.NewRequest(http.MethodGet, "http://example.com", nil, nil)
	res := &request.Response{}
	err := error(nil)
	op, _ := operation.NewOperationFromRequest(req)

	scanAttempt := NewIssueScanAttempt(op, req, res, err)
	scanAttempt.Pass()

	assert.Equal(t, IssueScanAttemptStatusPassed, scanAttempt.Status)
}

func TestIssueScanAttempt_HasPassed(t *testing.T) {
	req, _ := request.NewRequest(http.MethodGet, "http://example.com", nil, nil)
	res := &request.Response{}
	err := error(nil)
	op, _ := operation.NewOperationFromRequest(req)

	scanAttempt := NewIssueScanAttempt(op, req, res, err)
	scanAttempt.Pass()

	assert.True(t, scanAttempt.HasPassed())
	assert.False(t, scanAttempt.HasFailed())
}

func TestIssueScanAttempt_HasFailed(t *testing.T) {
	req, _ := request.NewRequest(http.MethodGet, "http://example.com", nil, nil)
	res := &request.Response{}
	err := error(nil)
	op, _ := operation.NewOperationFromRequest(req)

	scanAttempt := NewIssueScanAttempt(op, req, res, err)
	scanAttempt.Fail()

	assert.True(t, scanAttempt.HasFailed())
	assert.False(t, scanAttempt.HasPassed())
}
