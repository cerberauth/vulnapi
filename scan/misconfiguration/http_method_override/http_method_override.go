package httpmethodoverride

import (
	"context"
	_ "embed"
	"errors"
	"net/http"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("http_method_override", checkYAML)

var httpMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
}

var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-Http-Method-Override",
	"X-HTTP-Method",
	"X-Http-Method",
	"X-Method-Override",
}

var methodOverrideQueryParams = []string{
	"_method",
	"method",
	"httpMethod",
	"_httpMethod",
}

var Check = hxcheckdef.NewResourceCheck(Def, func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	op, ok := harnessx.ResourceDataAs[*operation.Operation](resource)
	if !ok {
		return harnessx.Result{Err: errors.New("http_method_override: resource missing *operation.Operation")}, nil
	}
	securityScheme := op.GetSecurityScheme()

	newOperation, err := op.Clone()
	if err != nil {
		return harnessx.Result{}, err
	}

	initialAttempt, err := finding.Fetch(ctx, newOperation, securityScheme)
	if err != nil {
		return harnessx.Result{}, err
	}

	if initialAttempt.Response.GetStatusCode() == http.StatusMethodNotAllowed {
		return harnessx.Result{Skipped: true, SkipReason: "operation already returns 405 for its own method"}, nil
	}

	var methodAttempt *finding.Attempt
	for _, method := range httpMethods {
		if method == op.Method {
			continue
		}

		newOperation, err = op.Clone()
		if err != nil {
			return harnessx.Result{}, err
		}

		newOperation.Method = method
		methodAttempt, err = finding.Fetch(ctx, newOperation, securityScheme)
		if err != nil {
			return harnessx.Result{}, err
		}
		if methodAttempt.Response.GetStatusCode() == http.StatusMethodNotAllowed {
			break
		}
	}

	if methodAttempt.Response.GetStatusCode() == initialAttempt.Response.GetStatusCode() {
		return harnessx.Result{}, nil
	}

	var attemptFailed = false
	var attempt *finding.Attempt
	var winningOperation *operation.Operation
	newOperationMethod := methodAttempt.Request.Method
	for _, header := range methodOverrideHeaders {
		newOperation, err = op.Clone()
		if err != nil {
			return harnessx.Result{}, err
		}

		newOperation.Header.Set(header, op.Method)
		newOperation.Method = newOperationMethod
		attempt, err = finding.Fetch(ctx, newOperation, securityScheme)
		if err != nil {
			return harnessx.Result{}, err
		}

		if attempt.Response.GetStatusCode() == initialAttempt.Response.GetStatusCode() {
			attemptFailed = true
			winningOperation = newOperation
			break
		}
	}

	if !attemptFailed {
		for _, queryParam := range methodOverrideQueryParams {
			newOperation, err = op.Clone()
			if err != nil {
				return harnessx.Result{}, err
			}

			newOperationQueryValues := newOperation.URL.Query()
			newOperationQueryValues.Set(queryParam, op.Method)
			newOperation.URL.RawQuery = newOperationQueryValues.Encode()
			newOperation.Method = newOperationMethod
			attempt, err = finding.Fetch(ctx, newOperation, securityScheme)
			if err != nil {
				return harnessx.Result{}, err
			}

			if attempt.Response.GetStatusCode() == initialAttempt.Response.GetStatusCode() {
				attemptFailed = true
				winningOperation = newOperation
				break
			}
		}
	}

	if !attemptFailed {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Data: &finding.Finding{
		Attempt: attempt,
		Data:    winningOperation,
	}}, nil
})
