package introspectionenabled

import (
	"bytes"
	"net/http"
	"net/url"

	"github.com/cerberauth/vulnapi/internal/auth"
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

const graphqlQuery = `{
	"query": "query{__schema
	{queryType{name}}}"
}`

func newPostGraphqlIntrospectionRequest(client *request.Client, endpoint *url.URL) (*request.Request, error) {
	return request.NewRequest(http.MethodPost, endpoint.String(), bytes.NewReader([]byte(graphqlQuery)), client)
}

func newGetGraphqlIntrospectionRequest(client *request.Client, endpoint *url.URL) (*request.Request, error) {
	values := url.Values{}
	values.Add("query", graphqlQuery)
	endpoint.RawQuery = values.Encode()

	return request.NewRequest(http.MethodGet, endpoint.String(), nil, client)
}

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	securitySchemes := []auth.SecurityScheme{securityScheme}
	vulnReport := report.NewVulnerabilityReport(issue).WithOperation(operation).WithSecurityScheme(securityScheme)

	r := report.NewScanReport(GraphqlIntrospectionScanID, GraphqlIntrospectionScanName, operation)
	newRequest, err := newPostGraphqlIntrospectionRequest(operation.Client, operation.URL)
	if err != nil {
		return r, err
	}
	newOperation := request.NewOperationFromRequest(newRequest)
	newOperation.SetSecuritySchemes(securitySchemes)
	attempt, err := scan.ScanURL(newOperation, &securityScheme)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(attempt).End()

	if attempt.Response.StatusCode == http.StatusOK { // TODO: check the GraphQL response
		r.AddVulnerabilityReport(vulnReport.Fail()).End()
		return r, nil
	}

	newRequest, err = newGetGraphqlIntrospectionRequest(operation.Client, operation.URL)
	if err != nil {
		return r, err
	}
	newOperation = request.NewOperationFromRequest(newRequest)
	newOperation.SetSecuritySchemes(securitySchemes)
	attempt, err = scan.ScanURL(newOperation, &securityScheme)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(attempt).End()

	if attempt.Response.StatusCode == http.StatusOK { // TODO: check the GraphQL response
		r.AddVulnerabilityReport(vulnReport.Fail()).End()
		return r, nil
	}

	r.AddVulnerabilityReport(vulnReport.Pass()).End()
	return r, nil
}
