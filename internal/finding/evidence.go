package finding

import (
	"github.com/cerberauth/reportx/evidence"
)

// NewHTTPEvidence builds reportx HTTP evidence from an attempt's
// request/response. Returns nil if attempt has no request to describe.
func NewHTTPEvidence(attempt *Attempt) *evidence.HTTPEvidence {
	if attempt == nil || attempt.Request == nil {
		return nil
	}

	ev := &evidence.HTTPEvidence{
		RequestMethod:  attempt.Request.Method,
		RequestURL:     attempt.Request.URL.String(),
		RequestHeaders: attempt.Request.Header,
		RequestBody:    attempt.RequestBody,
	}

	if attempt.Response != nil {
		ev.ResponseStatus = attempt.Response.GetStatusCode()
		ev.ResponseHeaders = attempt.Response.GetHeader()
		if body := attempt.Response.GetBody(); body != nil {
			ev.ResponseBody = body.Bytes()
		}
	}

	return ev
}
