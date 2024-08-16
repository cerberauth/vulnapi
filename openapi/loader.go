package openapi

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/getkin/kin-openapi/openapi3"
)

func newLoader(ctx context.Context) *openapi3.Loader {
	loader := openapi3.Loader{
		Context: ctx,

		IsExternalRefsAllowed: false,
	}

	return &loader
}

func LoadFromData(ctx context.Context, data []byte) (*OpenAPI, error) {
	doc, err := newLoader(ctx).LoadFromData(data)
	if err != nil {
		return nil, err
	}

	return NewOpenAPI(doc), nil
}

func LoadOpenAPI(ctx context.Context, urlOrPath string) (*OpenAPI, error) {
	if urlOrPath == "" {
		return nil, errors.New("url or path must not be empty")
	}

	if uri, urlerr := url.Parse(urlOrPath); urlerr == nil && uri.Hostname() != "" {
		doc, err := newLoader(ctx).LoadFromURI(uri)
		if err != nil {
			return nil, err
		}

		return NewOpenAPI(doc), nil
	}

	if _, err := os.Stat(urlOrPath); err != nil {
		return nil, fmt.Errorf("the openapi file has not been found on %s", urlOrPath)
	}

	doc, err := newLoader(ctx).LoadFromFile(urlOrPath)
	if err != nil {
		return nil, err
	}

	return NewOpenAPI(doc), nil
}
