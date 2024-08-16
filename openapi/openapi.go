package openapi

import (
	"net/url"

	"github.com/getkin/kin-openapi/openapi3"
)

type OpenAPI struct {
	baseUrl *url.URL

	doc *openapi3.T
}

func NewOpenAPI(doc *openapi3.T) *OpenAPI {
	return &OpenAPI{doc: doc}
}
