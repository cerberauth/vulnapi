package scan

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/getkin/kin-openapi/openapi3"
	stduritemplate "github.com/std-uritemplate/std-uritemplate/go"
)

func getBaseUrl(doc *openapi3.T) (*url.URL, error) {
	var baseUrl *url.URL
	var err error
	for _, server := range doc.Servers {
		baseUrl, err = url.Parse(server.URL)
		if err != nil {
			continue
		}

		basePath, err := server.BasePath()
		if err != nil {
			continue
		}

		baseUrl.Path = path.Join(baseUrl.Path, basePath)
		break
	}

	if baseUrl == nil {
		return nil, fmt.Errorf("no valid base url has been found in OpenAPI file")
	}

	return baseUrl, nil
}

func getOperationSecuritySchemes(securityRequirements *openapi3.SecurityRequirements, securitySchemes map[string]auth.SecurityScheme) []auth.SecurityScheme {
	operationsSecuritySchemes := []auth.SecurityScheme{}
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

func getOperationPath(p string, params openapi3.Parameters) (string, error) {
	subs := map[string]interface{}{}
	for _, v := range params {
		if v.Value.In != "path" {
			continue
		}

		var value interface{}
		if v.Value.Example != nil {
			value = v.Value.Example
		} else if len(v.Value.Schema.Value.Enum) > 0 {
			value = v.Value.Schema.Value.Enum[0]
		}

		// if there is no example generate random param
		if value == nil {
			if v.Value.Schema.Value.Type.Is("string") {
				value = gofakeit.Word()
			} else if v.Value.Schema.Value.Type.Is("number") || v.Value.Schema.Value.Type.Is("integer") {
				value = gofakeit.Number(0, 5)
			}
		}

		subs[v.Value.Name] = value
	}

	return stduritemplate.Expand(p, subs)
}

func NewOpenAPIScan(doc *openapi3.T, validToken *string, reporter *report.Reporter) (*Scan, error) {
	baseUrl, err := getBaseUrl(doc)
	if err != nil {
		return nil, err
	}

	securitySchemes := map[string]auth.SecurityScheme{}
	for name, scheme := range doc.Components.SecuritySchemes {
		switch strings.ToLower(scheme.Value.Type) {
		case "http":
			if strings.ToLower(scheme.Value.Scheme) == string(auth.BearerScheme) {
				switch strings.ToLower(scheme.Value.BearerFormat) {
				case "jwt":
					securitySchemes[name], err = auth.NewAuthorizationJWTBearerSecurityScheme(name, validToken)
					if err != nil {
						return nil, err
					}
				default:
					securitySchemes[name] = auth.NewAuthorizationBearerSecurityScheme(name, validToken)
				}
			}
		}
	}

	operations := request.Operations{}
	for docPath, p := range doc.Paths.Map() {
		for method, o := range p.Operations() {
			header := http.Header{}
			cookies := []*http.Cookie{}
			for _, h := range o.Parameters {
				if !h.Value.Required {
					continue
				}

				name := h.Value.Name
				value := ""
				if h.Value.Example != nil {
					value = ""
				}

				if h.Value.In == "header" {
					header.Add(name, value)
				} else if h.Value.In == "cookie" {
					cookies = append(cookies, &http.Cookie{
						Name:  name,
						Value: value,
					})
				}
			}

			operationsSecuritySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
			if o.Security != nil {
				operationsSecuritySchemes = getOperationSecuritySchemes(o.Security, securitySchemes)
			} else if doc.Security != nil {
				operationsSecuritySchemes = getOperationSecuritySchemes(&doc.Security, securitySchemes)
			}
			operationPath, err := getOperationPath(docPath, o.Parameters)
			if err != nil {
				return nil, err
			}

			operationUrl := *baseUrl
			operationUrl.Path = path.Join(operationUrl.Path, operationPath)

			operation, err := request.NewOperation(method, operationUrl.String(), header, cookies, operationsSecuritySchemes)
			if err != nil {
				return nil, err
			}
			operations = append(operations, operation)
		}
	}

	return NewScan(operations, reporter)
}
