package report_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewCurlReport(t *testing.T) {
	method := http.MethodGet
	url := "http://example.com"
	data := map[string]interface{}{"key": "value"}
	header := http.Header{"Content-Type": []string{"application/json"}}
	cookies := []*http.Cookie{{Name: "session_id", Value: "abc123"}}
	value := jwt.FakeJWT
	securityScheme := auth.MustNewAuthorizationBearerSecurityScheme("token", &value)
	securitySchemes := []*auth.SecurityScheme{securityScheme}

	curlReport := report.NewCurlReport(method, url, data, header, cookies, securitySchemes)

	assert.Equal(t, method, curlReport.Method)
	assert.Equal(t, url, curlReport.URL)
	assert.Equal(t, data, curlReport.Data)
	assert.Equal(t, header, curlReport.Header)
	assert.Equal(t, cookies, curlReport.Cookies)
	assert.Len(t, curlReport.SecuritySchemes, len(securitySchemes))
	assert.Equal(t, auth.HttpType, curlReport.SecuritySchemes[0].Type)
	assert.Equal(t, auth.InHeader, *curlReport.SecuritySchemes[0].In)
	assert.Equal(t, "token", curlReport.SecuritySchemes[0].Name)
	assert.Empty(t, curlReport.Issues)
}

func Test_CurlReport_AddReport(t *testing.T) {
	method := http.MethodGet
	url := "http://example.com"
	data := map[string]interface{}{"key": "value"}
	header := http.Header{"Content-Type": []string{"application/json"}}
	cookies := []*http.Cookie{{Name: "session_id", Value: "abc123"}}
	securitySchemes := []*auth.SecurityScheme{}

	curlReport := report.NewCurlReport(method, url, data, header, cookies, securitySchemes)

	operation := operation.MustNewOperation(method, url, nil, nil)
	scanReport := report.NewScanReport("id", "test", operation)
	firstIssue := report.Issue{
		Name: "issue 1",
	}
	secondIssue := report.Issue{
		Name: "issue 2",
	}
	firstIssueReport := report.NewIssueReport(firstIssue).Fail()
	secondIssueReport := report.NewIssueReport(secondIssue).Fail()
	scanReport.AddIssueReport(firstIssueReport).AddIssueReport(secondIssueReport)

	curlReport.AddReport(scanReport)

	assert.Len(t, curlReport.Issues, 2)
	assert.Equal(t, firstIssue.Name, curlReport.Issues[0].Name)
	assert.Equal(t, secondIssue.Name, curlReport.Issues[1].Name)
}

func TestAddReport_WhenScanReportHasNoFailedIssueReport(t *testing.T) {
	method := http.MethodGet
	url := "http://example.com"
	data := map[string]interface{}{"key": "value"}
	header := http.Header{"Content-Type": []string{"application/json"}}
	cookies := []*http.Cookie{{Name: "session_id", Value: "abc123"}}
	securitySchemes := []*auth.SecurityScheme{}

	curlReport := report.NewCurlReport(method, url, data, header, cookies, securitySchemes)

	operation := operation.MustNewOperation(method, url, nil, nil)
	scanReport := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "issue 1",
	}
	issueReport := report.NewIssueReport(issue).Pass()
	scanReport.AddIssueReport(issueReport)

	curlReport.AddReport(scanReport)

	assert.Empty(t, curlReport.Issues)
}
