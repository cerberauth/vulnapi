package openapi

import (
	"bytes"
	"context"
	"net/http"
	"path"

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

func getOperationSecuritySchemes(securityRequirements *openapi3.SecurityRequirements, securitySchemes map[string]*auth.SecurityScheme) []*auth.SecurityScheme {
	operationsSecuritySchemes := []*auth.SecurityScheme{}
	for _, security := range *securityRequirements {
		if len(security) == 0 {
			continue
		}

		keys := make([]string, 0, len(security))
		for k := range security {
			keys = append(keys, k)
		}

		operationSecurityScheme := securitySchemes[keys[0]]
		if operationSecurityScheme == nil {
			continue
		}

		operationsSecuritySchemes = append(operationsSecuritySchemes, operationSecurityScheme)
	}

	return operationsSecuritySchemes
}

func GetOperationPath(p string, params openapi3.Parameters) (string, error) {
	subs := map[string]interface{}{}
	for _, v := range params {
		if v.Value.In != "path" {
			continue
		}
		subs[v.Value.Name] = getSchemaValue(v.Value.Schema.Value, 0)
	}

	return stduritemplate.Expand(p, subs)
}

func (openapi *OpenAPI) Operations(ctx context.Context, client *request.Client, securitySchemes auth.SecuritySchemesMap) (operation.Operations, error) {
	telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
	telemetryPathCounter, _ := telemetryMeter.Int64Counter("openapi.path.counter")
	telemetryOperationCounter, _ := telemetryMeter.Int64Counter("openapi.operation.counter")
	telemetryOperationErrorCounter, _ := telemetryMeter.Int64Counter("openapi.operation.error.counter")
	telemetryOperationHeadersCounter, _ := telemetryMeter.Int64Counter("openapi.operation.headers.counter")
	telemetryOperationCookiesCounter, _ := telemetryMeter.Int64Counter("openapi.operation.cookies.counter")

	baseUrl := openapi.BaseUrl()

	operations := operation.Operations{}
	for docPath, p := range openapi.Doc.Paths.Map() {
		telemetryPathCounter.Add(ctx, 1)

		for method, o := range p.Operations() {
			var otelAttributes = []attribute.KeyValue{
				otelMethodAttributeKey.String(method),
			}

			operationPath, err := GetOperationPath(docPath, o.Parameters)
			if err != nil {
				telemetryOperationErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid operation path"))...))
				return nil, err
			}

			operationUrl := *baseUrl
			operationUrl.Path = path.Join(operationUrl.Path, operationPath)

			header := http.Header{}
			cookies := []*http.Cookie{}
			for _, h := range o.Parameters {
				if !h.Value.Required {
					continue
				}

				name := h.Value.Name
				value := getParameterValue(h.Value)

				switch h.Value.In {
				case "header":
					header.Add(name, value)
				case "cookie":
					cookies = append(cookies, &http.Cookie{
						Name:  name,
						Value: value,
					})
				}
			}
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

			if o.Security != nil {
				operation.SetSecuritySchemes(getOperationSecuritySchemes(o.Security, securitySchemes))
			} else if openapi.Doc.Security != nil {
				operation.SetSecuritySchemes(getOperationSecuritySchemes(&openapi.Doc.Security, securitySchemes))
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
