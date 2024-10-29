package report

import (
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/getkin/kin-openapi/openapi3"
)

func findOperationByMethodAndPath(operations operation.Operations, method string, path string) *operation.Operation {
	for _, operation := range operations {
		if operation.Method == method && operation.GetOpenAPIDocPath() != nil && *operation.GetOpenAPIDocPath() == path {
			return operation
		}
	}

	return nil
}

type OpenAPIReportOperation struct {
	ID   string   `json:"operationId" yaml:"operationId"`
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`

	SecuritySchemes []OperationSecurityScheme `json:"securitySchemes" yaml:"securitySchemes"`

	Issues []*IssueReport `json:"issues" yaml:"issues"`
}

func NewOpenAPIReportOperation(operation *openapi3.Operation, requestOperation *operation.Operation) OpenAPIReportOperation {
	reportSecuritySchemes := []OperationSecurityScheme{}
	for _, ss := range requestOperation.GetSecuritySchemes() {
		reportSecuritySchemes = append(reportSecuritySchemes, NewOperationSecurityScheme(ss))
	}

	return OpenAPIReportOperation{
		ID:   requestOperation.GetID(),
		Tags: operation.Tags,

		SecuritySchemes: reportSecuritySchemes,

		Issues: []*IssueReport{},
	}
}

type OpenAPIReportMethods map[string]OpenAPIReportOperation
type OpenAPIReportPaths map[string]OpenAPIReportMethods
type OpenAPIReport struct {
	Paths OpenAPIReportPaths `json:"paths" yaml:"paths"`
}

func NewOpenAPIReport(doc *openapi3.T, operations operation.Operations) *OpenAPIReport {
	paths := OpenAPIReportPaths{}
	for docPath, p := range doc.Paths.Map() {
		paths[docPath] = OpenAPIReportMethods{}
		for method, o := range p.Operations() {
			var requestOperation *operation.Operation
			if o.OperationID != "" {
				requestOperation = operations.GetByID(o.OperationID)
			}

			if requestOperation == nil {
				requestOperation = findOperationByMethodAndPath(operations, method, docPath)
			}

			if requestOperation == nil {
				continue
			}

			openAPIOperation := NewOpenAPIReportOperation(o, requestOperation)
			paths[docPath][method] = openAPIOperation
		}
	}

	return &OpenAPIReport{
		Paths: paths,
	}
}

func (or *OpenAPIReport) AddReport(r *ScanReport) {
	if r == nil || !r.HasFailedIssueReport() || r.Operation == nil {
		return
	}

	for path, methods := range or.Paths {
		for method, operationReport := range methods {
			if operationReport.ID == r.Operation.ID {
				operationReport.Issues = append(operationReport.Issues, r.GetFailedIssueReports()...)
				or.Paths[path][method] = operationReport
			}
		}
	}
}
