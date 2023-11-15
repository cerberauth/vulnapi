package request

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type SecuritySchemeMock struct {
	Cookies     []*http.Cookie
	Headers     http.Header
	ValidValue  interface{}
	AttackValue interface{}
}

func NewSecuritySchemeMock() *SecuritySchemeMock {
	return &SecuritySchemeMock{
		Cookies:     []*http.Cookie{},
		Headers:     http.Header{},
		ValidValue:  nil,
		AttackValue: nil,
	}
}

func (ss *SecuritySchemeMock) GetCookies() []*http.Cookie {
	return ss.Cookies
}

func (ss *SecuritySchemeMock) GetHeaders() http.Header {
	return ss.Headers
}

func (ss *SecuritySchemeMock) GetValidValue() interface{} {
	return ss.ValidValue
}

func (ss *SecuritySchemeMock) SetAttackValue(v interface{}) {
	ss.AttackValue = v
}

func (ss *SecuritySchemeMock) GetAttackValue() interface{} {
	return ss.AttackValue
}

var reqMethod = "GET"
var reqUrl = "http://localhost:8080"

func setupSuite(tb testing.TB) func(tb testing.TB) {
	httpmock.Activate()
	httpmock.RegisterResponder(reqMethod, reqUrl, httpmock.NewBytesResponder(204, nil))

	return func(tb testing.TB) {
		defer httpmock.DeactivateAndReset()
	}
}

func TestNewRequestUserMethodAndUrl(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	req, err := NewRequest(reqMethod, reqUrl)
	require.NoError(t, err)
	assert.Equal(t, reqMethod, req.Method)
	assert.Equal(t, &url.URL{Scheme: "http", Host: "localhost:8080"}, req.URL)

	reqMethod2 := "PUT"

	req2, err2 := NewRequest(reqMethod2, reqUrl)
	require.NoError(t, err2)
	assert.Equal(t, reqMethod2, req2.Method)
	assert.Equal(t, &url.URL{Scheme: "http", Host: "localhost:8080"}, req2.URL)
}

func TestNewRequestAddUserAgent(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	req, err := NewRequest(reqMethod, reqUrl)
	require.NoError(t, err)
	assert.Equal(t, "vulnapi/0.1", req.UserAgent())
}

func TestNewRequestWithWrongUrl(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	_, err := NewRequest(reqMethod, "://localhost:8080")
	require.Error(t, err)
}

func TestDoRequestWithoutSecurityScheme(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	client := &http.Client{}
	req, _ := NewRequest(reqMethod, reqUrl)

	req, res, err := DoRequest(client, req, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, len(req.Cookies()))
	assert.Equal(t, req, req)
	assert.NotNil(t, res)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestDoRequestWithSecuritySchemeAndCookies(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	ss := NewSecuritySchemeMock()
	ss.Cookies = append(ss.Cookies, &http.Cookie{
		Name:  "cookie",
		Value: "cookie value",
	})
	client := &http.Client{}
	req, _ := NewRequest(reqMethod, reqUrl)

	req, res, err := DoRequest(client, req, ss)
	require.NoError(t, err)
	assert.Equal(t, 1, len(req.Cookies()))
	assert.Equal(t, ss.Cookies[0].Name, req.Cookies()[0].Name)
	assert.Equal(t, ss.Cookies[0].Value, req.Cookies()[0].Value)
	assert.NotNil(t, res)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestDoRequestWithSecuritySchemeAndHeaders(t *testing.T) {
	teardownSuite := setupSuite(t)
	defer teardownSuite(t)

	ss := NewSecuritySchemeMock()
	ss.Headers = http.Header{}
	ss.Headers.Add("header1", "value1")
	client := &http.Client{}
	req, _ := NewRequest(reqMethod, reqUrl)

	req, res, err := DoRequest(client, req, ss)
	require.NoError(t, err)
	assert.Equal(t, 0, len(req.Cookies()))
	assert.Equal(t, "value1", req.Header.Get("header1"))
	assert.NotNil(t, res)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}
