package openapi

import (
	"context"
	"fmt"
)

func (openapi *OpenAPI) Validate(ctx context.Context) error {
	if openapi.BaseUrl() == nil {
		return fmt.Errorf("no valid base url has been found in OpenAPI file")
	}

	return nil
}
