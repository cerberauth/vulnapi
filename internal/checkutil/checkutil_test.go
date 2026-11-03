package checkutil_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/checkutil"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/stretchr/testify/assert"
)

type fetchResult struct{ value string }

func TestOperation(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)

	got, ok := checkutil.Operation(harnessx.Resource{Data: op})
	assert.True(t, ok)
	assert.Same(t, op, got)

	_, ok = checkutil.Operation(harnessx.Resource{Data: "not an operation"})
	assert.False(t, ok)
}

func TestDependency(t *testing.T) {
	store := harnessx.NewStaticResultStore(harnessx.Result{CheckID: "fetch", ResourceID: "op", Data: &fetchResult{value: "ok"}})

	got, ok := checkutil.Dependency[*fetchResult](store, "fetch", "op")
	assert.True(t, ok)
	assert.Equal(t, "ok", got.value)

	_, ok = checkutil.Dependency[*fetchResult](store, "other-check", "op")
	assert.False(t, ok)

	_, ok = checkutil.Dependency[string](store, "fetch", "op")
	assert.False(t, ok)
}
