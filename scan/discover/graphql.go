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
	DiscoverableGraphQLPathSeverityLevel            = 0
	DiscoverableGraphQLPathVulnerabilityName        = "Discoverable GraphQL Path"
	DiscoverableGraphQLPathVulnerabilityDescription = "GraphQL path seems discoverable and can lead to information disclosure and security issues"

	GraphqlIntrospectionEnabledSeverityLevel            = 0
	GraphqlIntrospectionEnabledVulnerabilityName        = "GraphQL Introspection enabled"
	GraphqlIntrospectionEnabledVulnerabilityDescription = "GraphQL Introspection seems enabled and can lead to information disclosure and security issues"
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

func newPostGraphqlIntrospectionRequest(endpoint *url.URL) (*http.Request, error) {
	return http.NewRequest(http.MethodPost, endpoint.String(), bytes.NewReader([]byte(graphqlQuery)))
}

func newGetGraphqlIntrospectionRequest(endpoint *url.URL) (*http.Request, error) {
	values := url.Values{}
	values.Add("query", graphqlQuery)
	endpoint.RawQuery = values.Encode()

	return http.NewRequest(http.MethodGet, endpoint.String(), nil)
}

func GraphqlIntrospectionScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()

	securityScheme.SetAttackValue(securityScheme.GetValidValue())

	base := ExtractBaseURL(operation.Request.URL)

	for _, path := range potentialGraphQLEndpoints {
		newRequest, err := newPostGraphqlIntrospectionRequest(base.ResolveReference(&url.URL{Path: path}))
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
				Name:          GraphqlIntrospectionEnabledVulnerabilityName,
				Description:   GraphqlIntrospectionEnabledVulnerabilityDescription,
				Operation:     operation,
			})

			return r, nil
		}
	}

	for _, path := range potentialGraphQLEndpoints {
		newRequest, err := newGetGraphqlIntrospectionRequest(base.ResolveReference(&url.URL{Path: path}))
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
				Name:          GraphqlIntrospectionEnabledVulnerabilityName,
				Description:   GraphqlIntrospectionEnabledVulnerabilityDescription,
				Operation:     operation,
			})

			return r, nil
		}
	}

	return r, nil
}

func DiscoverableGraphQLPathScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	handler := CreateURLScanHandler("GraphQL", graphqlSeclistUrl, potentialGraphQLEndpoints, &report.VulnerabilityReport{
		SeverityLevel: DiscoverableGraphQLPathSeverityLevel,
		Name:          DiscoverableGraphQLPathVulnerabilityName,
		Description:   DiscoverableGraphQLPathVulnerabilityDescription,
	})

	return handler(operation, securityScheme)
}
