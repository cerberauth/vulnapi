package scan

import (
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/openapi"
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
			switch v.Value.Schema.Value.Type {
			case "string":
				value = gofakeit.Word()
			case "number", "integer":
				value = gofakeit.Number(0, 5)
			}
		}

		subs[v.Value.Name] = value
	}

	return stduritemplate.Expand(p, subs)
}

func NewOpenAPIScan(openAPIUrlOrPath string, validToken *string, reporter *report.Reporter) (*Scan, error) {
	doc, err := openapi.LoadOpenAPI(openAPIUrlOrPath)
	if err != nil {
		return nil, err
	}

	baseUrl, err := getBaseUrl(doc)
	if err != nil {
		return nil, err
	}

	securitySchemes := map[string]auth.SecurityScheme{}
	for name, scheme := range doc.Components.SecuritySchemes {
		switch scheme.Value.Type {
		case "http":
			if scheme.Value.Scheme == string(auth.BearerScheme) {
				securitySchemes[name] = auth.NewAuthorizationBearerSecurityScheme(name, validToken)
			}
		}
	}

	operations := request.Operations{}
	for docPath, p := range doc.Paths {
		for method, o := range p.Operations() {
			headers := http.Header{}
			cookies := []http.Cookie{}
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
					headers.Add(name, value)
				} else if h.Value.In == "cookie" {
					cookies = append(cookies, http.Cookie{
						Name:  name,
						Value: value,
					})
				}
			}

			operationsSecuritySchemes := getOperationSecuritySchemes(o.Security, securitySchemes)
			operationPath, err := getOperationPath(docPath, o.Parameters)
			if err != nil {
				return nil, err
			}

			operationUrl := *baseUrl
			operationUrl.Path = path.Join(operationUrl.Path, operationPath)

			operations = append(operations, request.Operation{
				Url:     operationUrl.String(),
				Method:  method,
				Headers: &headers,
				Cookies: cookies,

				SecuritySchemes: operationsSecuritySchemes,
			})
		}
	}

	return NewScan(operations, reporter)
}
