package openapi

import (
	"net/url"

	"github.com/getkin/kin-openapi/openapi3"
	"go.opentelemetry.io/otel"
)

var tracer = otel.Tracer("openapi")

type OpenAPI struct {
	baseUrl *url.URL

	Doc *openapi3.T
}

func NewOpenAPI(doc *openapi3.T) *OpenAPI {
	return &OpenAPI{Doc: doc}
}
