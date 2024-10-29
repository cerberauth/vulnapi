package introspectionenabled

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	GraphqlIntrospectionScanID   = "graphql.introspection_enabled"
	GraphqlIntrospectionScanName = "GraphQL Introspection Enabled"
)

var issue = report.Issue{
	ID:   "graphql.introspection_enabled",
	Name: "GraphQL Introspection enabled",
	URL:  "https://vulnapi.cerberauth.com/docs/vulnerabilities/security-misconfiguration/graphql-introspection?utm_source=vulnapi",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

const graphqlQuery = `query{__schema{queryType{name}}}`

func newPostGraphqlIntrospectionRequest(client *request.Client, endpoint url.URL) (*request.Request, error) {
	payload := strings.NewReader("{\"query\":\"" + graphqlQuery + "\"}")
	req, err := request.NewRequest(http.MethodPost, endpoint.String(), payload, client)
	if err != nil {
		return nil, err
	}

	req.SetHeader("Content-Type", "application/json")
	return req, nil
}

func newGetGraphqlIntrospectionRequest(client *request.Client, endpoint url.URL) (*request.Request, error) {
	values := url.Values{}
	values.Add("query", graphqlQuery)
	endpoint.RawQuery = values.Encode()

	req, err := request.NewRequest(http.MethodGet, endpoint.String(), nil, client)
	if err != nil {
		return nil, err
	}

	req.SetHeader("Content-Type", "application/json")
	return req, nil
}

func ScanHandler(op *operation.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	securitySchemes := []auth.SecurityScheme{securityScheme}
	vulnReport := report.NewIssueReport(issue).WithOperation(op).WithSecurityScheme(securityScheme)

	r := report.NewScanReport(GraphqlIntrospectionScanID, GraphqlIntrospectionScanName, op)
	newRequest, err := newPostGraphqlIntrospectionRequest(op.Client, op.URL)
	if err != nil {
		return r, err
	}
	newOperation, err := operation.NewOperationFromRequest(newRequest)
	if err != nil {
		return r, err
	}

	newOperation.SetSecuritySchemes(securitySchemes)
	attempt, err := scan.ScanURL(newOperation, &securityScheme)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(attempt)

	if attempt.Response.GetStatusCode() == http.StatusOK && strings.Contains(attempt.Response.GetBody().String(), "queryType") {
		r.AddIssueReport(vulnReport.Fail()).End()
		return r, nil
	}

	newRequest, err = newGetGraphqlIntrospectionRequest(op.Client, op.URL)
	if err != nil {
		return r, err
	}
	newOperation, err = operation.NewOperationFromRequest(newRequest)
	if err != nil {
		return r, err
	}

	newOperation.SetSecuritySchemes(securitySchemes)
	attempt, err = scan.ScanURL(newOperation, &securityScheme)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(attempt)

	if attempt.Response.GetStatusCode() == http.StatusOK { // TODO: check the GraphQL response
		r.AddIssueReport(vulnReport.Fail()).End()
		return r, nil
	}

	r.AddIssueReport(vulnReport.Pass()).End()
	return r, nil
}
