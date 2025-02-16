package scan

import (
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
)

type IssueScanAttemptStatus string

func (attemptStatus IssueScanAttemptStatus) String() string {
	return string(attemptStatus)
}

const (
	IssueScanAttemptStatusPassed IssueScanAttemptStatus = "passed"
	IssueScanAttemptStatusFailed IssueScanAttemptStatus = "failed"
	IssueScanAttemptStatusNone   IssueScanAttemptStatus = "none"
)

type IssueScanAttempt struct {
	ID       string
	Status   IssueScanAttemptStatus
	Request  *request.Request
	Response *request.Response
	Err      error
}

func NewIssueScanAttempt(operation *operation.Operation, req *request.Request, res *request.Response, err error) *IssueScanAttempt {
	return &IssueScanAttempt{
		ID:     operation.GetID() + "-" + req.GetID(),
		Status: IssueScanAttemptStatusNone,

		Request:  req,
		Response: res,
		Err:      err,
	}
}

func (scanAttempt *IssueScanAttempt) WithBooleanStatus(status bool) *IssueScanAttempt {
	if status {
		return scanAttempt.Pass()
	}
	return scanAttempt.Fail()
}

func (scanAttempt *IssueScanAttempt) Fail() *IssueScanAttempt {
	scanAttempt.Status = IssueScanAttemptStatusFailed
	return scanAttempt
}

func (scanAttempt *IssueScanAttempt) Pass() *IssueScanAttempt {
	scanAttempt.Status = IssueScanAttemptStatusPassed
	return scanAttempt
}

func (scanAttempt *IssueScanAttempt) HasPassed() bool {
	return scanAttempt.Status == IssueScanAttemptStatusPassed
}

func (scanAttempt *IssueScanAttempt) HasFailed() bool {
	return scanAttempt.Status == IssueScanAttemptStatusFailed
}
