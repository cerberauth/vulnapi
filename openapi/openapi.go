package openapi

import "github.com/getkin/kin-openapi/openapi3"

type OpenAPI struct {
	doc *openapi3.T
}

func NewOpenAPI(doc *openapi3.T) *OpenAPI {
	return &OpenAPI{doc: doc}
}
