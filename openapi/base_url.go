package openapi

import (
	"net/url"
)

func (openapi *OpenAPI) BaseUrl() *url.URL {
	if openapi.baseUrl != nil {
		return openapi.baseUrl
	}

	for _, server := range openapi.Doc.Servers {
		if server.URL == "" {
			continue
		}

		serverUrl, err := url.Parse(server.URL)
		if err != nil || serverUrl.Host == "" || serverUrl.Scheme == "" {
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
