package request

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewClient_DefaultOptions(t *testing.T) {
	client := NewClient(NewClientOptions{})

	assert.NotNil(t, client)
	assert.Equal(t, 10*time.Second, client.Timeout)
	assert.Equal(t, 100, client.Transport.(*http.Transport).MaxIdleConns)
	assert.Equal(t, 100, client.Transport.(*http.Transport).MaxIdleConnsPerHost)
	assert.Empty(t, client.Header)
	assert.Empty(t, client.Cookies)
}

func TestNewClient_CustomOptions(t *testing.T) {
	header := http.Header{"Custom-Header": []string{"value"}}
	cookies := []*http.Cookie{{Name: "test", Value: "cookie"}}

	client := NewClient(NewClientOptions{
		Timeout: 5 * time.Second,
		Header:  header,
		Cookies: cookies,
	})

	assert.NotNil(t, client)
	assert.Equal(t, 5*time.Second, client.Timeout)
	assert.Equal(t, header, client.Header)
	assert.Equal(t, cookies, client.Cookies)
}

func TestGetClient(t *testing.T) {
	client := GetDefaultClient()
	assert.NotNil(t, client)
}

func TestSetClient(t *testing.T) {
	newClient := NewClient(NewClientOptions{})
	SetDefaultClient(newClient)
	assert.Equal(t, newClient, GetDefaultClient())
}

func TestClient_WithHeader(t *testing.T) {
	client := NewClient(NewClientOptions{})
	header := http.Header{"Custom-Header": []string{"value"}}
	client = client.WithHeader(header)

	assert.Equal(t, header, client.Header)
}

func TestClient_WithCookies(t *testing.T) {
	client := NewClient(NewClientOptions{})
	cookies := []*http.Cookie{{Name: "test", Value: "cookie"}}
	client = client.WithCookies(cookies)

	assert.Equal(t, cookies, client.Cookies)
}
