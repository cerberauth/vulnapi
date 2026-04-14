package openapi

import (
	"context"
	"errors"
	"net/url"

	"github.com/cerberauth/x/fsx"
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

		openapi := NewOpenAPI(doc)
		if openapi.BaseUrl() == nil {
			baseUri := uri
			baseUri.Path = "/"
			openapi.SetBaseUrl(baseUri)
		}

		return openapi, nil
	}

	data, err := fsx.ReadFile(urlOrPath)
	if err != nil {
		return nil, err
	}

	doc, err := newLoader(ctx).LoadFromDataWithPath(data, &url.URL{Path: urlOrPath})
	if err != nil {
		return nil, err
	}

	return NewOpenAPI(doc), nil
}
