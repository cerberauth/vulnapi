package report

import "github.com/cerberauth/vulnapi/internal/auth"

type GraphQLOperationReport struct {
	ID   string   `json:"id" yaml:"id"`
	Tags []string `json:"tags" yaml:"tags"`

	SecuritySchemes []OperationSecurityScheme `json:"securitySchemes" yaml:"securitySchemes"`
	Issues          []*IssueReport            `json:"issues" yaml:"issues"`
}

func NewGraphQLOperationReport() GraphQLOperationReport {
	return GraphQLOperationReport{
		SecuritySchemes: []OperationSecurityScheme{}, // TODO

		Issues: []*IssueReport{},
	}
}

type GraphQLOperationsMethods map[string]GraphQLOperationReport
type GraphQLReport struct {
	URL string `json:"url" yaml:"url"`

	Queries   GraphQLOperationsMethods `json:"queries" yaml:"queries"`
	Mutations GraphQLOperationsMethods `json:"mutations" yaml:"mutations"`
}

func NewGraphQLReport(url string, securitySchemes []auth.SecurityScheme) *GraphQLReport {
	queries := GraphQLOperationsMethods{}
	mutations := GraphQLOperationsMethods{}

	return &GraphQLReport{
		URL: url,

		Queries:   queries,
		Mutations: mutations,
	}
}

func (gr *GraphQLReport) AddReport(r *ScanReport) {
	for _, operation := range gr.Queries {
		if operation.ID == r.Operation.ID {
			operation.Issues = append(operation.Issues, r.Issues...)
		}
	}

	for _, operation := range gr.Mutations {
		if operation.ID == r.Operation.ID {
			operation.Issues = append(operation.Issues, r.Issues...)
		}
	}
}
