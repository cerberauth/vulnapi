package openapi

import (
	"context"
	"fmt"
)

func (openapi *OpenAPI) Validate(ctx context.Context) error {
	if err := openapi.doc.Validate(ctx); err != nil {
		return fmt.Errorf("the OpenAPI file is not valid: %w", err)
	}

	if openapi.BaseUrl() == nil {
		return fmt.Errorf("no valid base url has been found in OpenAPI file")
	}

	return nil
}
