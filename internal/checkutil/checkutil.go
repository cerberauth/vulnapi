// Package checkutil holds helpers shared by vulnapi's harnessx checks.
package checkutil

import (
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/operation"
)

// Operation returns the *operation.Operation carried by resource.
func Operation(resource harnessx.Resource) (*operation.Operation, bool) {
	return harnessx.ResourceDataAs[*operation.Operation](resource)
}

// Dependency returns the data of type T that the check checkID stored for
// resourceID, typically a fetch result shared by sibling checks.
func Dependency[T any](store harnessx.ResultStore, checkID harnessx.CheckID, resourceID string) (T, bool) {
	res, ok := store.GetForResource(checkID, resourceID)
	if !ok {
		var zero T
		return zero, false
	}
	return harnessx.DataAs[T](res)
}
