package request_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/stretchr/testify/assert"
)

func TestNewClient_DefaultOptions(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{})

	assert.NotNil(t, client)
	assert.Nil(t, client.Transport.(*http.Transport).TLSClientConfig)
	assert.Equal(t, 10*time.Second, client.Timeout)
	assert.Equal(t, 100, client.Transport.(*http.Transport).MaxIdleConns)
	assert.Equal(t, 100, client.Transport.(*http.Transport).MaxIdleConnsPerHost)
	assert.Empty(t, client.Header)
	assert.Empty(t, client.Cookies)
}

func TestNewClient_CustomOptions(t *testing.T) {
	header := http.Header{"Custom-Header": []string{"value"}}
	cookies := []*http.Cookie{{Name: "test", Value: "cookie"}}

	client := request.NewClient(request.NewClientOptions{
		Timeout:            5 * time.Second,
		InsecureSkipVerify: true,

		Header:  header,
		Cookies: cookies,
	})

	assert.NotNil(t, client)
	assert.Equal(t, 5*time.Second, client.Timeout)
	assert.NotNil(t, client.Transport.(*http.Transport).TLSClientConfig)
	assert.True(t, client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify)
	assert.Equal(t, header, client.Header)
	assert.Equal(t, cookies, client.Cookies)
}

func TestGetClient(t *testing.T) {
	client := request.GetDefaultClient()
	assert.NotNil(t, client)
}

func TestSetClient(t *testing.T) {
	newClient := request.NewClient(request.NewClientOptions{})
	request.SetDefaultClient(newClient)
	assert.Equal(t, newClient, request.GetDefaultClient())
}

func TestClient_WithHeader(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{})
	header := http.Header{"Custom-Header": []string{"value"}}
	client = client.WithHeader(header)

	assert.Equal(t, header, client.Header)
}

func TestClient_WithCookies(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{})
	cookies := []*http.Cookie{{Name: "test", Value: "cookie"}}
	client = client.WithCookies(cookies)

	assert.Equal(t, cookies, client.Cookies)
}

func TestClient_ClearHeaderWithSecurityScheme(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{})
	client.Header.Set("Authorization", "Bearer token")

	value := "token"
	securityScheme := auth.MustNewAuthorizationBearerSecurityScheme("token", &value)
	client.ClearSecurityScheme(securityScheme)

	assert.Empty(t, client.Header.Get("Authorization"))
}

// func TestClient_ClearCookieWithSecurityScheme(t *testing.T) {
// 	client := request.NewClient(request.NewClientOptions{})
// 	client.Cookies = []*http.Cookie{{Name: "session", Value: "12345"}}

// 	value := "token"
// 	securityScheme := &auth.SecurityScheme{
// 		Cookies: []*http.Cookie{{Name: "session", Value: "12345"}},
// 	}
// 	client.ClearSecurityScheme(securityScheme)

// 	assert.Empty(t, client.Header.Get("Authorization"))
// }

func TestClient_ClearSecuritySchemes(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{})
	client.Header.Set("Authorization", "Bearer token")
	client.Cookies = []*http.Cookie{{Name: "session", Value: "12345"}}

	value := "token"
	securityScheme1 := auth.MustNewAuthorizationBearerSecurityScheme("token", &value)
	securityScheme2 := auth.MustNewNoAuthSecurityScheme()

	client.ClearSecuritySchemes([]*auth.SecurityScheme{securityScheme1, securityScheme2})

	assert.Empty(t, client.Header.Get("Authorization"))
	// assert.Empty(t, client.Cookies)
}
