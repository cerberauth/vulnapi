package report_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewOpenAPIReportOperation(t *testing.T) {
	doc, _ := openapi.LoadOpenAPI(context.Background(), "../test/stub/simple_http_bearer.openapi.json")
	securitySchemesMap, _ := doc.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, _ := doc.Operations(nil, securitySchemesMap)
	securitySchemes := operations[0].GetSecuritySchemes()

	o := operations.GetByID("getRoot")

	r := report.NewOpenAPIReportOperation(doc.Doc.Paths.Map()["/"].Get, o)

	assert.NotNil(t, r)
	assert.Equal(t, "getRoot", r.ID)
	assert.Equal(t, report.NewOperationSecurityScheme(securitySchemes[0]), r.SecuritySchemes[0])
	assert.Equal(t, []*report.IssueReport{}, r.Issues)
}

func TestNewOpenAPIReport(t *testing.T) {
	doc, _ := openapi.LoadOpenAPI(context.Background(), "../test/stub/simple_http_bearer.openapi.json")
	securitySchemesMap, _ := doc.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, _ := doc.Operations(nil, securitySchemesMap)

	r := report.NewOpenAPIReport(doc.Doc, operations)

	assert.NotNil(t, r)
	assert.Contains(t, r.Paths, "/")
	assert.Contains(t, r.Paths["/"], http.MethodGet)
	assert.Equal(t, "getRoot", r.Paths["/"][http.MethodGet].ID)
	assert.Equal(t, []*report.IssueReport{}, r.Paths["/"][http.MethodGet].Issues)
}

func Test_OpenAPIReport_AddReport(t *testing.T) {
	doc, _ := openapi.LoadOpenAPI(context.Background(), "../test/stub/simple_http_bearer.openapi.json")
	securitySchemesMap, _ := doc.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, _ := doc.Operations(nil, securitySchemesMap)

	r := report.NewOpenAPIReport(doc.Doc, operations)

	scanReport := report.NewScanReport("id", "test", operations[0])
	issue := report.Issue{
		Name: "issue 1",
	}
	issueReport := report.NewIssueReport(issue).Fail()
	scanReport.AddIssueReport(issueReport)
	r.AddReport(scanReport)

	assert.NotNil(t, r)
	assert.Contains(t, r.Paths, "/")
	assert.Contains(t, r.Paths["/"], http.MethodGet)
	assert.Equal(t, "getRoot", r.Paths["/"][http.MethodGet].ID)
	assert.Equal(t, 1, len(r.Paths["/"][http.MethodGet].Issues))
	assert.Equal(t, issueReport, r.Paths["/"][http.MethodGet].Issues[0])
}

func Test_OpenAPIReport_AddReport_NoFailedIssue(t *testing.T) {
	doc, _ := openapi.LoadOpenAPI(context.Background(), "../test/stub/simple_http_bearer.openapi.json")
	securitySchemesMap, _ := doc.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, _ := doc.Operations(nil, securitySchemesMap)

	r := report.NewOpenAPIReport(doc.Doc, operations)

	scanReport := report.NewScanReport("id", "test", operations[0])
	issue := report.Issue{
		Name: "issue 1",
	}
	issueReport := report.NewIssueReport(issue).Pass()
	scanReport.AddIssueReport(issueReport)
	r.AddReport(scanReport)

	assert.NotNil(t, r)
	assert.Contains(t, r.Paths, "/")
	assert.Contains(t, r.Paths["/"], http.MethodGet)
	assert.Equal(t, "getRoot", r.Paths["/"][http.MethodGet].ID)
	assert.Equal(t, 0, len(r.Paths["/"][http.MethodGet].Issues))
}
