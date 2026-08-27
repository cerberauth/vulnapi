// Package jwtcheck holds what vulnapi's JWT delegation to jwtop needs that
// jwtop itself has no concept of: deciding whether a resource's security
// scheme is a JWT bearer token worth scanning, and pulling the
// *operation.Operation back out of a harnessx.Resource.
package jwtcheck

import (
	"context"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
)

func ShouldBeScanned(securityScheme *auth.SecurityScheme) bool {
	return securityScheme != nil && securityScheme.GetType() != auth.None &&
		securityScheme.GetTokenFormat() != nil && *securityScheme.GetTokenFormat() == auth.JWTTokenFormat
}

func operationOf(resource harnessx.Resource) (*operation.Operation, bool) {
	return harnessx.ResourceDataAs[*operation.Operation](resource)
}

func SkipUnlessJWT() harnessx.SkipDecision {
	return harnessx.SkipResourceWhen(func(_ context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) string {
		op, ok := operationOf(resource)
		if !ok {
			return "resource is missing operation data"
		}
		if !ShouldBeScanned(op.GetSecurityScheme()) {
			return "security scheme is not a JWT bearer token"
		}
		return ""
	})
}

func Operation(resource harnessx.Resource) (*operation.Operation, bool) {
	return operationOf(resource)
}
