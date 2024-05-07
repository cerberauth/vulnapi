package openapi

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"

	"github.com/getkin/kin-openapi/openapi3"
)

var urlPatternRe = regexp.MustCompile(`^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/|\/|\/\/)?[A-z0-9_-]*?[:]?[A-z0-9_-]*?[@]?[A-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$`)

func newLoader(ctx context.Context) *openapi3.Loader {
	loader := openapi3.Loader{
		Context: ctx,

		IsExternalRefsAllowed: false,
	}

	return &loader
}

func LoadFromData(ctx context.Context, data []byte) (*openapi3.T, error) {
	return newLoader(ctx).LoadFromData(data)
}

func LoadOpenAPI(ctx context.Context, urlOrPath string) (*openapi3.T, error) {
	if urlOrPath == "" {
		return nil, errors.New("url or path must not be empty")
	}

	if urlPatternRe.MatchString(urlOrPath) {
		uri, urlerr := url.Parse(urlOrPath)
		if urlerr != nil {
			return nil, urlerr
		}

		return newLoader(ctx).LoadFromURI(uri)
	}

	if _, err := os.Stat(urlOrPath); err != nil {
		return nil, fmt.Errorf("the openapi file has not been found on %s", urlOrPath)
	}

	return newLoader(ctx).LoadFromFile(urlOrPath)
}
