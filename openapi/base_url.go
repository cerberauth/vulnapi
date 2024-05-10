package openapi

import (
	"net/url"
)

func (openapi *OpenAPI) BaseUrl() *url.URL {
	var baseUrl *url.URL
	for _, server := range openapi.doc.Servers {
		if server.URL == "" {
			continue
		}

		serverUrl, err := url.Parse(server.URL)
		if err != nil || serverUrl.Host == "" || serverUrl.Scheme == "" || len(serverUrl.Query()) > 0 || serverUrl.Fragment != "" {
			continue
		}

		if serverUrl.Path == "" {
			serverUrl.Path = "/"
		}

		baseUrl = serverUrl
		break
	}

	return baseUrl
}
