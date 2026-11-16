package openapi

import (
	"bytes"
	"context"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/x/telemetryx"
	"github.com/getargvio/argvio-go"
	"github.com/getkin/kin-openapi/openapi3"
	stduritemplate "github.com/std-uritemplate/std-uritemplate/go/v2"
)

// Argvio product metrics, declared in the Argvio catalog.
var (
	pathsCounter            = argvio.NewCounter("openapi.paths")
	operationsCounter       = argvio.NewCounter("openapi.operations", argvio.Dims("method"))
	operationParamsCounter  = argvio.NewCounter("openapi.operation-params", argvio.Dims("method", "in"))
	operationBodiesCounter  = argvio.NewCounter("openapi.operation-bodies", argvio.Dims("method", "media-type"))
	operationSchemesCounter = argvio.NewCounter("openapi.operation-schemes", argvio.Dims("method", "scheme"))
	loadDuration            = argvio.NewDuration("openapi.load")
	httpMethods             = []string{"get", "post", "put", "patch", "delete", "head", "options", "trace", "connect"}
)

// mediaTypeLabel names a request body media type from a fixed vocabulary
// (parameters such as charset are ignored), "other" for anything else.
func mediaTypeLabel(mediaType string) string {
	mt, _, err := mime.ParseMediaType(mediaType)
	if err != nil {
		return "other"
	}
	switch {
	case isJSONMediaType(mt):
		return "json"
	case mt == "application/xml" || mt == "text/xml" || strings.HasSuffix(mt, "+xml"):
		return "xml"
	case mt == formURLEncodedMediaType:
		return "form"
	case mt == "multipart/form-data":
		return "multipart"
	case mt == "application/octet-stream":
		return "binary"
	case strings.HasPrefix(mt, "text/"):
		return "text"
	default:
		return "other"
	}
}

// operationSchemeLabel names an operation's security scheme like
// SecuritySchemeMap names the spec's, from the same fixed vocabulary.
func operationSchemeLabel(s *auth.SecurityScheme) string {
	var in string
	if s.GetIn() != nil {
		in = string(*s.GetIn())
	}
	return schemeCounterLabel(strings.ToLower(string(s.GetType())), string(s.GetScheme()), in)
}

// recordOperationSchemes counts the security schemes an operation declares,
// each scheme once, or "none" for an operation that declares no scheme.
func recordOperationSchemes(ctx context.Context, method string, schemes []*auth.SecurityScheme) {
	seen := map[string]bool{}
	for _, s := range schemes {
		label := operationSchemeLabel(s)
		if seen[label] {
			continue
		}
		seen[label] = true
		operationSchemesCounter.Add(ctx, 1, method, label)
	}
	if len(seen) == 0 {
		operationSchemesCounter.Add(ctx, 1, method, "none")
	}
}

// getOperationSecuritySchemes returns one security scheme per security
// requirement: the alternatives the operation accepts. A requirement that
// lists several schemes needs all of them (AND); the first one, by name, is
// the scheme under test and the others are returned as companions, whose
// credentials must be sent along with it.
func getOperationSecuritySchemes(securityRequirements *openapi3.SecurityRequirements, securitySchemes map[string]*auth.SecurityScheme) ([]*auth.SecurityScheme, [][]*auth.SecurityScheme) {
	operationsSecuritySchemes := []*auth.SecurityScheme{}
	companions := [][]*auth.SecurityScheme{}
	optional := false
	for _, security := range *securityRequirements {
		if len(security) == 0 {
			optional = true
			continue
		}
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
	if optional && len(operationsSecuritySchemes) > 0 {
		operationsSecuritySchemes = append(operationsSecuritySchemes, auth.MustNewNoAuthSecurityScheme())
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
	start := time.Now()
	baseUrl := openapi.BaseUrl()

	// sort paths and methods so the operation order, and so the scan target
	// and the reachability check made on the first operation, are stable
	pathItems := openapi.Doc.Paths.Map()
	operations := operation.Operations{}
	for _, docPath := range slices.Sorted(maps.Keys(pathItems)) {
		p := pathItems[docPath]
		pathsCounter.Add(ctx, 1)

		pathOperations := p.Operations()
		for _, method := range slices.Sorted(maps.Keys(pathOperations)) {
			o := pathOperations[method]
			methodLabel := telemetryx.Vocab(method, httpMethods...)

			params := mergeParameters(p.Parameters, o.Parameters)
			operationPath, err := GetOperationPath(docPath, params)
			if err != nil {
				return nil, telemetryx.Reason(err, "invalid-operation-path")
			}

			operationUrl, err := joinOperationURL(*baseUrl, operationPath)
			if err != nil {
				return nil, telemetryx.Reason(err, "invalid-operation-path")
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

			if n := len(header); n > 0 {
				operationParamsCounter.Add(ctx, int64(n), methodLabel, "header")
			}
			if n := len(cookies); n > 0 {
				operationParamsCounter.Add(ctx, int64(n), methodLabel, "cookie")
			}

			var body *bytes.Buffer
			var mediaType string
			if o.RequestBody != nil {
				body, mediaType, _ = getRequestBodyValue(o.RequestBody.Value)
			}
			if body != nil && mediaType != "" {
				header.Set("Content-Type", mediaType)
				operationBodiesCounter.Add(ctx, 1, methodLabel, mediaTypeLabel(mediaType))
			} else {
				body = bytes.NewBuffer(nil)
			}

			operation, err := operation.NewOperation(method, operationUrl.String(), body, client)
			if err != nil {
				return nil, telemetryx.Reason(err, "new-operation-error")
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

			operations = append(operations, operation)
			operationsCounter.Add(ctx, 1, methodLabel)
			recordOperationSchemes(ctx, methodLabel, operation.GetSecuritySchemes())
		}
	}

	loadDuration.Record(ctx, time.Since(start))
	return operations, nil
}
