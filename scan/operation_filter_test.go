package scan_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/stretchr/testify/assert"
)

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"/internal/**", "/internal", true},
		{"/internal/**", "/internal/users/1", true},
		{"/internal/**", "/internals", false},
		{"/users/*", "/users/{id}", true},
		{"/users/*", "/users/{id}/posts", false},
		{"/**/health", "/v1/status/health", true},
		{"/users", "/users", true},
		{"/users", "/users/1", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, scan.MatchPath(tt.pattern, tt.path), "%s %s", tt.pattern, tt.path)
	}
}

func TestOperationFilter_Match(t *testing.T) {
	newOp := func(method, path, id string, tags ...string) *operation.Operation {
		op := operation.MustNewOperation(method, "http://localhost:8080"+path, nil, nil)
		op.SetID(id)
		op.Tags = tags
		return op
	}
	getUser := newOp(http.MethodGet, "/users/1", "getUser", "public")
	deleteUser := newOp(http.MethodDelete, "/users/1", "deleteUser", "admin")
	internal := newOp(http.MethodGet, "/internal/metrics", "getMetrics", "public")

	tests := []struct {
		name   string
		filter scan.OperationFilter
		want   []*operation.Operation
	}{
		{"no filter", scan.OperationFilter{}, []*operation.Operation{getUser, deleteUser, internal}},
		{"paths", scan.OperationFilter{Paths: []string{"/users/**"}}, []*operation.Operation{getUser, deleteUser}},
		{"exclude paths", scan.OperationFilter{ExcludePaths: []string{"/internal/**"}}, []*operation.Operation{getUser, deleteUser}},
		{"tags", scan.OperationFilter{Tags: []string{"public"}}, []*operation.Operation{getUser, internal}},
		{"operation ids", scan.OperationFilter{OperationIDs: []string{"deleteUser"}}, []*operation.Operation{deleteUser}},
		{"methods", scan.OperationFilter{Methods: []string{"get"}}, []*operation.Operation{getUser, internal}},
		{"combined", scan.OperationFilter{Tags: []string{"public"}, ExcludePaths: []string{"/internal/**"}}, []*operation.Operation{getUser}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, operation.Operations(tt.want), tt.filter.Filter(operation.Operations{getUser, deleteUser, internal}))
		})
	}
}
