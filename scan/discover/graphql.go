package discover

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
	DiscoverableGraphQLPathScanID   = "discover.graphql"
	DiscoverableGraphQLPathScanName = "Discoverable GraphQL Path"

	DiscoverableGraphQLPathSeverityLevel     = 0
	DiscoverableGraphQLPathOWASP2023Category = report.OWASP2023SSRFCategory
	DiscoverableGraphQLPathVulnerabilityID   = "ssrf.graphql_discover_endpoint"
	DiscoverableGraphQLPathVulnerabilityName = "Discoverable GraphQL Endpoint"
	DiscoverableGraphQLPathVulnerabilityURL  = ""

	GraphqlIntrospectionScanID   = "discover.graphql_introspection"
	GraphqlIntrospectionScanName = "GraphQL Introspection"

	GraphqlIntrospectionEnabledSeverityLevel     = 0
	GraphqlIntrospectionEnabledOWASP2023Category = report.OWASP2023SSRFCategory
	GraphqlIntrospectionEnabledVulnerabilityID   = "ssrf.graphql_introspection_enabled"
	GraphqlIntrospectionEnabledVulnerabilityName = "GraphQL Introspection enabled"
	GraphqlIntrospectionEnabledVulnerabilityURL  = "https://vulnapi.cerberauth.com/docs/vulnerabilities/security-misconfiguration/graphql-introspection/?utm_source=vulnapi"
)

var potentialGraphQLEndpoints = []string{
	"/graphql",
	"/graph",
	"/api/graphql",
	"/graphql/console",
	"/v1/graphql",
	"/v1/graphiql",
	"/v1/explorer",
}

const graphqlQuery = `{
	"query": "query{__schema
	{queryType{name}}}"
}`

var graphqlSeclistUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt"

func newPostGraphqlIntrospectionRequest(client *request.Client, endpoint *url.URL) (*request.Request, error) {
	return request.NewRequest(client, http.MethodPost, endpoint.String(), bytes.NewReader([]byte(graphqlQuery)))
}

func newGetGraphqlIntrospectionRequest(client *request.Client, endpoint *url.URL) (*request.Request, error) {
	values := url.Values{}
	values.Add("query", graphqlQuery)
	endpoint.RawQuery = values.Encode()

	return request.NewRequest(client, http.MethodGet, endpoint.String(), nil)
}

func GraphqlIntrospectionScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	base := ExtractBaseURL(operation.Request.URL)

	r := report.NewScanReport(GraphqlIntrospectionScanID, GraphqlIntrospectionScanName, operation)
	for _, path := range potentialGraphQLEndpoints {
		newRequest, err := newPostGraphqlIntrospectionRequest(operation.Client, base.ResolveReference(&url.URL{Path: path}))
		if err != nil {
			return r, err
		}

		newOperation := request.NewOperationFromRequest(newRequest, []auth.SecurityScheme{securityScheme})
		attempt, err := scan.ScanURL(newOperation, &securityScheme)
		r.AddScanAttempt(attempt).End()
		if err != nil {
			return r, err
		}

		if attempt.Response.StatusCode < 300 {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: GraphqlIntrospectionEnabledSeverityLevel,

				OWASP2023Category: GraphqlIntrospectionEnabledOWASP2023Category,

				ID:   GraphqlIntrospectionEnabledVulnerabilityID,
				Name: GraphqlIntrospectionEnabledVulnerabilityName,
				URL:  GraphqlIntrospectionEnabledVulnerabilityURL,
			})

			return r, nil
		}
	}

	for _, path := range potentialGraphQLEndpoints {
		newRequest, err := newGetGraphqlIntrospectionRequest(operation.Client, base.ResolveReference(&url.URL{Path: path}))
		if err != nil {
			return r, err
		}

		newOperation := request.NewOperationFromRequest(newRequest, []auth.SecurityScheme{securityScheme})
		attempt, err := scan.ScanURL(newOperation, &securityScheme)
		r.AddScanAttempt(attempt).End()
		if err != nil {
			return r, err
		}

		if attempt.Response.StatusCode < 300 {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: GraphqlIntrospectionEnabledSeverityLevel,

				OWASP2023Category: GraphqlIntrospectionEnabledOWASP2023Category,

				ID:   GraphqlIntrospectionEnabledVulnerabilityID,
				Name: GraphqlIntrospectionEnabledVulnerabilityName,
				URL:  GraphqlIntrospectionEnabledVulnerabilityURL,
			})

			return r, nil
		}
	}

	return r, nil
}

func DiscoverableGraphQLPathScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(DiscoverableGraphQLPathScanID, DiscoverableGraphQLPathScanName, operation)
	handler := CreateURLScanHandler("GraphQL", graphqlSeclistUrl, potentialGraphQLEndpoints, r, &report.VulnerabilityReport{
		SeverityLevel: DiscoverableGraphQLPathSeverityLevel,

		OWASP2023Category: DiscoverableGraphQLPathOWASP2023Category,

		ID:   DiscoverableGraphQLPathVulnerabilityID,
		Name: DiscoverableGraphQLPathVulnerabilityName,
		URL:  DiscoverableGraphQLPathVulnerabilityURL,
	})

	return handler(operation, securityScheme)
}
