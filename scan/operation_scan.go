package scan

import "github.com/cerberauth/vulnapi/internal/operation"

type OperationScan struct {
	Operation *operation.Operation
	CheckID   string
	CheckName string
}
