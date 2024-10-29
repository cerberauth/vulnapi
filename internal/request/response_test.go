package request_test

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/stretchr/testify/assert"
)

func TestNewResponse(t *testing.T) {
	bodyContent := "test body"
	httpResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString(bodyContent)),
		Header:     make(http.Header),
	}

	res, err := request.NewResponse(httpResponse)

	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, bodyContent, res.Body.String())
	assert.Equal(t, http.StatusOK, res.GetStatusCode())
	assert.Equal(t, httpResponse.Header, res.GetHeader())
	assert.Equal(t, httpResponse.Cookies(), res.GetCookies())
}
