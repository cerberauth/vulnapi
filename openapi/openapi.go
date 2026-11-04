package openapi

import (
	"net/url"

	"github.com/getkin/kin-openapi/openapi3"
	"go.opentelemetry.io/otel/attribute"
)

const (
	otelName = "github.com/cerberauth/vulnapi/openapi"

	otelErrorReasonAttributeKey = attribute.Key("error_reason")
)

type OpenAPI struct {
	baseUrl *url.URL
	// docURL is the URL the document was loaded from, if any.
	docURL *url.URL

	Doc *openapi3.T
}

func NewOpenAPI(doc *openapi3.T) *OpenAPI {
	return &OpenAPI{Doc: doc}
}
