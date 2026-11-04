package openapi

import (
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// expandServerURL replaces the server variables in server's URL with their
// default values.
func expandServerURL(server *openapi3.Server) string {
	serverURL := server.URL
	for name, variable := range server.Variables {
		if variable == nil {
			continue
		}
		serverURL = strings.ReplaceAll(serverURL, "{"+name+"}", variable.Default)
	}
	return serverURL
}

// BaseUrl returns the URL operations are resolved against: the URL set with
// SetBaseUrl, or else the first usable server. Server variables use their
// default value, and relative server URLs are resolved against the URL the
// document was loaded from.
func (openapi *OpenAPI) BaseUrl() *url.URL {
	if openapi.baseUrl != nil {
		return openapi.baseUrl
	}

	for _, server := range openapi.Doc.Servers {
		if server == nil || server.URL == "" {
			continue
		}

		serverUrl, err := url.Parse(expandServerURL(server))
		if err != nil {
			continue
		}
		if serverUrl.Host == "" && openapi.docURL != nil {
			serverUrl = openapi.docURL.ResolveReference(serverUrl)
		}
		if serverUrl.Host == "" || serverUrl.Scheme == "" {
			continue
		}

		if serverUrl.Path == "" {
			serverUrl.Path = "/"
		}

		openapi.SetBaseUrl(serverUrl)
		return serverUrl
	}

	return nil
}

func (openapi *OpenAPI) SetBaseUrl(baseUrl *url.URL) *OpenAPI {
	openapi.baseUrl = baseUrl
	return openapi
}
