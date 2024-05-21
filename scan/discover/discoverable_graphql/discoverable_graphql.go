package discoverablegraphql

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan/discover"
)

const (
	DiscoverableGraphQLPathScanID   = "discover.graphql"
	DiscoverableGraphQLPathScanName = "Discoverable GraphQL Path"
)

type DiscoverableGraphQLPathData = discover.DiscoverData

var issue = report.Issue{
	ID:   "discover.discoverable_graphql",
	Name: "Discoverable GraphQL Endpoint",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SSRF,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var potentialGraphQLEndpoints = []string{
	"/graphql",
	"/graph",
	"/api/graphql",
	"/graphql/console",
	"/v1/graphql",
	"/v1/graphiql",
	"/v1/explorer",
}

var graphqlSeclistUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt"

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewVulnerabilityReport(issue).WithOperation(operation).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(DiscoverableGraphQLPathScanID, DiscoverableGraphQLPathScanName, operation)
	handler := discover.CreateURLScanHandler("GraphQL", graphqlSeclistUrl, potentialGraphQLEndpoints, r, vulnReport)

	return handler(operation, securityScheme)
}
