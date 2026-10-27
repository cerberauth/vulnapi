package openapi

import (
	"bytes"
	"context"
	"maps"
	"net/http"
	"net/url"
	"path"
	"slices"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/x/telemetryx"
	"github.com/getkin/kin-openapi/openapi3"
	stduritemplate "github.com/std-uritemplate/std-uritemplate/go/v2"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	otelMethodAttributeKey               = attribute.Key("method")
	otelMediaTypeAttributeKey            = attribute.Key("media_type")
	otelSecuritySchemesTypesAttributeKey = attribute.Key("security_schemes")
)

// getOperationSecuritySchemes returns one security scheme per security
// requirement: the alternatives the operation accepts. A requirement that
// lists several schemes needs all of them (AND); the first one, by name, is
// the scheme under test and the others are returned as companions, whose
// credentials must be sent along with it.
func getOperationSecuritySchemes(securityRequirements *openapi3.SecurityRequirements, securitySchemes map[string]*auth.SecurityScheme) ([]*auth.SecurityScheme, [][]*auth.SecurityScheme) {
	operationsSecuritySchemes := []*auth.SecurityScheme{}
	companions := [][]*auth.SecurityScheme{}
	for _, security := range *securityRequirements {
		var requirementSchemes []*auth.SecurityScheme
		for _, name := range slices.Sorted(maps.Keys(security)) {
			if securityScheme := securitySchemes[name]; securityScheme != nil {
				requirementSchemes = append(requirementSchemes, securityScheme)
			}
		}
		if len(requirementSchemes) == 0 {
			continue
		}

		operationsSecuritySchemes = append(operationsSecuritySchemes, requirementSchemes[0])
		companions = append(companions, requirementSchemes[1:])
	}

	return operationsSecuritySchemes, companions
}

// mergeParameters returns the path item parameters overridden by the
// operation parameters with the same name and location.
func mergeParameters(pathParams openapi3.Parameters, operationParams openapi3.Parameters) openapi3.Parameters {
	params := openapi3.Parameters{}
	for _, p := range pathParams {
		if p == nil || p.Value == nil || operationParams.GetByInAndName(p.Value.In, p.Value.Name) != nil {
			continue
		}
		params = append(params, p)
	}
	for _, p := range operationParams {
		if p == nil || p.Value == nil {
			continue
		}
		params = append(params, p)
	}
	return params
}

func GetOperationPath(p string, params openapi3.Parameters) (string, error) {
	subs := map[string]interface{}{}
	for _, v := range params {
		if v == nil || v.Value == nil || v.Value.In != "path" || v.Value.Schema == nil {
			continue
		}
		subs[v.Value.Name] = getSchemaValue(v.Value.Schema.Value, 0)
	}

	return stduritemplate.Expand(p, subs)
}

// joinOperationURL appends the escaped operation path to baseUrl. Path keeps
// the decoded path and RawPath the escaped one, so values encoded by the
// URI template are not encoded a second time.
func joinOperationURL(baseUrl url.URL, operationPath string) (url.URL, error) {
	escapedPath := path.Join(baseUrl.EscapedPath(), operationPath)
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return url.URL{}, err
	}
	baseUrl.Path = decodedPath
	baseUrl.RawPath = escapedPath
	return baseUrl, nil
}

func (openapi *OpenAPI) Operations(ctx context.Context, client *request.Client, securitySchemes auth.SecuritySchemesMap) (operation.Operations, error) {
	telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
	telemetryPathCounter, _ := telemetryMeter.Int64Counter("openapi.path.counter")
	telemetryOperationCounter, _ := telemetryMeter.Int64Counter("openapi.operation.counter")
	telemetryOperationErrorCounter, _ := telemetryMeter.Int64Counter("openapi.operation.error.counter")
	telemetryOperationHeadersCounter, _ := telemetryMeter.Int64Counter("openapi.operation.headers.counter")
	telemetryOperationCookiesCounter, _ := telemetryMeter.Int64Counter("openapi.operation.cookies.counter")

	baseUrl := openapi.BaseUrl()

	// sort paths and methods so the operation order, and so the scan target
	// and the reachability check made on the first operation, are stable
	pathItems := openapi.Doc.Paths.Map()
	operations := operation.Operations{}
	for _, docPath := range slices.Sorted(maps.Keys(pathItems)) {
		p := pathItems[docPath]
		telemetryPathCounter.Add(ctx, 1)

		pathOperations := p.Operations()
		for _, method := range slices.Sorted(maps.Keys(pathOperations)) {
			o := pathOperations[method]
			var otelAttributes = []attribute.KeyValue{
				otelMethodAttributeKey.String(method),
			}

			params := mergeParameters(p.Parameters, o.Parameters)
			operationPath, err := GetOperationPath(docPath, params)
			if err != nil {
				telemetryOperationErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid operation path"))...))
				return nil, err
			}

			operationUrl, err := joinOperationURL(*baseUrl, operationPath)
			if err != nil {
				telemetryOperationErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid operation path"))...))
				return nil, err
			}

			header := http.Header{}
			cookies := []*http.Cookie{}
			query := operationUrl.Query()
			for _, h := range params {
				if !h.Value.Required {
					continue
				}

				name := h.Value.Name
				value := getParameterValue(h.Value)

				switch h.Value.In {
				case "query":
					query.Add(name, value)
				case "header":
					header.Add(name, value)
				case "cookie":
					cookies = append(cookies, &http.Cookie{
						Name:     name,
						Value:    value,
						HttpOnly: true,
						Secure:   true,
						SameSite: http.SameSiteLaxMode,
					})
				}
			}
			operationUrl.RawQuery = query.Encode()
			telemetryOperationHeadersCounter.Add(ctx, int64(len(header)), metric.WithAttributes(otelAttributes...))
			telemetryOperationCookiesCounter.Add(ctx, int64(len(cookies)), metric.WithAttributes(otelAttributes...))

			var body *bytes.Buffer
			var mediaType string
			if o.RequestBody != nil {
				body, mediaType, _ = getRequestBodyValue(o.RequestBody.Value)
			}
			if body != nil && mediaType != "" {
				header.Set("Content-Type", mediaType)
			} else {
				body = bytes.NewBuffer(nil)
			}
			otelAttributes = append(otelAttributes, otelMediaTypeAttributeKey.String(mediaType))

			operation, err := operation.NewOperation(method, operationUrl.String(), body, client)
			if err != nil {
				telemetryOperationErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("new operation error"))...))
				return nil, err
			}
			operation.WithOpenapiOperation(docPath, o)
			operation.WithCookies(cookies).WithHeader(header)

			securityRequirements := o.Security
			if securityRequirements == nil && openapi.Doc.Security != nil {
				securityRequirements = &openapi.Doc.Security
			}
			if securityRequirements != nil {
				operationSecuritySchemes, companions := getOperationSecuritySchemes(securityRequirements, securitySchemes)
				operation.SetSecuritySchemes(operationSecuritySchemes)
				// With a single requirement, its companion schemes are always
				// needed, so their credentials are sent with every request.
				if len(companions) == 1 {
					for _, companion := range companions[0] {
						for k, v := range companion.GetHeaders() {
							for _, value := range v {
								operation.Header.Add(k, value)
							}
						}
						operation.Cookies = append(operation.Cookies, companion.GetCookies()...)
					}
				}
			}

			telemetrySecuritySchemesTypes := []string{}
			for _, v := range operation.GetSecuritySchemes() {
				telemetrySecuritySchemesTypes = append(telemetrySecuritySchemesTypes, string(v.GetType()))
			}
			otelAttributes = append(otelAttributes, otelSecuritySchemesTypesAttributeKey.StringSlice(telemetrySecuritySchemesTypes))

			operations = append(operations, operation)
			telemetryOperationCounter.Add(ctx, 1, metric.WithAttributes(otelAttributes...))
		}
	}

	return operations, nil
}
