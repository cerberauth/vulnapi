package finding

import (
	"bytes"
	"context"
	"net/http"

	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/google/uuid"
)

// Response is the HTTP response half of an Attempt.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       *bytes.Buffer
}

func (r *Response) GetStatusCode() int { return r.StatusCode }

func (r *Response) GetHeader() http.Header { return r.Header }

func (r *Response) GetBody() *bytes.Buffer { return r.Body }

func (r *Response) GetCookies() []*http.Cookie {
	return (&http.Response{Header: r.Header}).Cookies()
}

// Attempt is the decisive request/response pair a check made against an
// operation, used both to decide pass/fail and as report evidence.
type Attempt struct {
	ID          string
	Request     *http.Request
	RequestBody []byte
	Response    *Response
	Err         error
}

// Fetch sends a request against op, applying securityScheme's headers/
// cookies (or op's own security scheme if securityScheme is nil), and
// returns the resulting Attempt. The returned Attempt is non-nil even when
// err is non-nil, mirroring the previous scan.ScanURL contract.
func Fetch(ctx context.Context, op *operation.Operation, securityScheme *auth.SecurityScheme) (*Attempt, error) {
	if securityScheme == nil {
		securityScheme = op.GetSecurityScheme()
	}

	req, err := op.NewHTTPRequest(ctx, auth.RequestMutators(securityScheme)...)
	if err != nil {
		return nil, err
	}

	attempt := &Attempt{
		ID:          op.GetID() + "-" + uuid.New().String(),
		Request:     req,
		RequestBody: op.Body,
	}

	if err := request.Wait(ctx); err != nil {
		attempt.Err = err
		return attempt, err
	}

	statusCode, header, body, _, doErr := probe.Do(ctx, op.HTTPClient(), req)
	if doErr != nil {
		attempt.Err = doErr
		return attempt, doErr
	}

	attempt.Response = &Response{
		StatusCode: statusCode,
		Header:     header,
		Body:       bytes.NewBuffer(body),
	}
	return attempt, nil
}

// IsUnauthorizedStatusCodeOrSimilar reports whether res's status code looks
// like an authorization/validation rejection rather than a success.
func IsUnauthorizedStatusCodeOrSimilar(res *Response) bool {
	return res.GetStatusCode() == http.StatusUnauthorized ||
		res.GetStatusCode() == http.StatusForbidden ||
		res.GetStatusCode() == http.StatusBadRequest ||
		res.GetStatusCode() == http.StatusNotFound ||
		res.GetStatusCode() == http.StatusInternalServerError
}
