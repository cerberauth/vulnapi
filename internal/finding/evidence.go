package finding

import (
	"github.com/cerberauth/reportx/enrich"
	"github.com/cerberauth/reportx/evidence"
)

// MaxEvidenceBodySize caps request and response bodies kept as evidence.
const MaxEvidenceBodySize = 16 * 1024

// NewHTTPEvidence builds reportx HTTP evidence from an attempt's
// request/response. Returns nil if attempt has no request to describe.
//
// Credential headers (Authorization, Cookie, Set-Cookie, X-Api-Key, ...) and
// any redactHeaders are masked, and bodies are truncated to
// MaxEvidenceBodySize, since reports can be written to disk or uploaded.
func NewHTTPEvidence(attempt *Attempt, redactHeaders ...string) *evidence.HTTPEvidence {
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

	enrich.RedactCredentials(ev,
		enrich.WithExtraHeaders(redactHeaders...),
		enrich.WithMaxBodySize(MaxEvidenceBodySize),
	)

	return ev
}
