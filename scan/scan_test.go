package scan_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanWithNoOperations(t *testing.T) {
	_, err := scan.NewScan(operation.Operations{}, nil)

	require.Error(t, err)
}

func TestNewScan(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}

	s, err := scan.NewScan(operations, nil)

	require.NoError(t, err)
	assert.Equal(t, operations, s.Operations)
	assert.Equal(t, []scan.OperationScan{}, s.OperationsScans)
}

func TestNewScanWithOptions(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	opts := &scan.ScanOptions{
		Title: "custom title",
	}

	s, err := scan.NewScan(operations, opts)

	require.NoError(t, err)
	assert.Equal(t, operations, s.Operations)
	assert.Equal(t, "custom title", s.Title)
	assert.Equal(t, []scan.OperationScan{}, s.OperationsScans)
}

func TestScanGetOperationsScansWhenEmpty(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, nil)

	operationsScans := s.GetOperationsScans()

	assert.Equal(t, s.OperationsScans, operationsScans)
}

func TestScanGetOperationsScans(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, nil)
	s.AddCheck(harnessx.Check{
		ID:    "test-handler",
		Scope: harnessx.ScopePerResource,
		RunResource: func(_ context.Context, _ harnessx.Target, _ harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{Data: &finding.Finding{Parameter: "test-finding"}}, nil
		},
	}, nil)

	operationsScans := s.GetOperationsScans()

	assert.Equal(t, 1, len(operationsScans))
}

func TestScanExecuteWithNoHandlers(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, nil)

	report, errs, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Equal(t, 0, len(report.Findings))
}

func TestScanExecuteWithHandler(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, nil)
	s.AddCheck(harnessx.Check{
		ID:    "test-handler",
		Scope: harnessx.ScopePerResource,
		RunResource: func(_ context.Context, _ harnessx.Target, _ harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{Data: &finding.Finding{Parameter: "test-finding"}}, nil
		},
	}, nil)

	report, errs, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Equal(t, 1, len(report.Findings))
	assert.Equal(t, "test-finding", report.Findings[0].Parameter)
}

func TestScanExecuteWithIncludeScans(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		IncludeScans: []string{"test-handler"},
	})
	s.AddCheck(harnessx.Check{
		ID:    "test-handler",
		Scope: harnessx.ScopePerResource,
		RunResource: func(_ context.Context, _ harnessx.Target, _ harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{Data: &finding.Finding{Parameter: "test-finding"}}, nil
		},
	}, nil)

	report, errs, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Equal(t, 1, len(report.Findings))
	assert.Equal(t, "test-finding", report.Findings[0].Parameter)
}

func TestScanExecuteWithEmptyStringIncludeScans(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		IncludeScans: []string{""},
	})
	s.AddCheck(harnessx.Check{
		ID:    "test-handler",
		Scope: harnessx.ScopePerResource,
		RunResource: func(_ context.Context, _ harnessx.Target, _ harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{Data: &finding.Finding{Parameter: "test-finding"}}, nil
		},
	}, nil)

	report, errs, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Equal(t, 1, len(report.Findings))
	assert.Equal(t, "test-finding", report.Findings[0].Parameter)
}

func TestScanExecuteWithMatchStringIncludeScans(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		IncludeScans: []string{"category.*"},
	})
	s.AddCheck(harnessx.Check{
		ID:    "category.test-handler",
		Scope: harnessx.ScopePerResource,
		RunResource: func(_ context.Context, _ harnessx.Target, _ harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{Data: &finding.Finding{Parameter: "test-finding"}}, nil
		},
	}, nil)

	report, errs, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Equal(t, 1, len(report.Findings))
	assert.Equal(t, "test-finding", report.Findings[0].Parameter)
}

func TestScanExecuteWithWrongMatchStringIncludeScans(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		IncludeScans: []string{"wrong-category.*"},
	})
	s.AddCheck(harnessx.Check{
		ID:    "category.test-handler",
		Scope: harnessx.ScopePerResource,
		RunResource: func(_ context.Context, _ harnessx.Target, _ harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{Data: &finding.Finding{Parameter: "test-finding"}}, nil
		},
	}, nil)

	report, errs, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Equal(t, 0, len(report.Findings))
}

func TestScanExecuteWithExcludeScans(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		ExcludeScans: []string{"test-handler"},
	})
	s.AddCheck(harnessx.Check{
		ID:    "test-handler",
		Scope: harnessx.ScopePerResource,
		RunResource: func(_ context.Context, _ harnessx.Target, _ harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{Data: &finding.Finding{Parameter: "test-finding"}}, nil
		},
	}, nil)

	report, errs, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Equal(t, 0, len(report.Findings))
}

func TestScanExecuteWithMatchStringExcludeScans(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		ExcludeScans: []string{"category.*"},
	})
	s.AddCheck(harnessx.Check{
		ID:    "category.test-handler",
		Scope: harnessx.ScopePerResource,
		RunResource: func(_ context.Context, _ harnessx.Target, _ harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{Data: &finding.Finding{Parameter: "test-finding"}}, nil
		},
	}, nil)

	report, errs, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Equal(t, 0, len(report.Findings))
}

func TestScanExecuteWithWrongMatchStringExcludeScans(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		ExcludeScans: []string{"wrong-category.*"},
	})
	s.AddCheck(harnessx.Check{
		ID:    "category.test-handler",
		Scope: harnessx.ScopePerResource,
		RunResource: func(_ context.Context, _ harnessx.Target, _ harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{Data: &finding.Finding{Parameter: "test-finding"}}, nil
		},
	}, nil)

	report, errs, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Equal(t, 1, len(report.Findings))
	assert.Equal(t, "test-finding", report.Findings[0].Parameter)
}

func TestScanExecuteWithLegacyAliasExcludeScans(t *testing.T) {
	scan.RegisterLegacyCheckIDAlias("new-handler-id-exclude", "old-handler-id-exclude")

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		ExcludeScans: []string{"old-handler-id-exclude"},
	})
	s.AddCheck(harnessx.Check{
		ID:    "new-handler-id-exclude",
		Scope: harnessx.ScopePerResource,
		RunResource: func(_ context.Context, _ harnessx.Target, _ harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{Data: &finding.Finding{Parameter: "test-finding"}}, nil
		},
	}, nil)

	report, errs, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Equal(t, 0, len(report.Findings))
}

func TestScanExecuteWithLegacyAliasIncludeScans(t *testing.T) {
	scan.RegisterLegacyCheckIDAlias("new-handler-id-include", "old-handler-id-include")

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		IncludeScans: []string{"old-handler-id-include"},
	})
	s.AddCheck(harnessx.Check{
		ID:    "new-handler-id-include",
		Scope: harnessx.ScopePerResource,
		RunResource: func(_ context.Context, _ harnessx.Target, _ harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{Data: &finding.Finding{Parameter: "test-finding"}}, nil
		},
	}, nil)

	report, errs, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Equal(t, 1, len(report.Findings))
	assert.Equal(t, "test-finding", report.Findings[0].Parameter)
}
