package openapi

import (
	"bytes"
	"net/http"
	"path"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/getkin/kin-openapi/openapi3"
	stduritemplate "github.com/std-uritemplate/std-uritemplate/go"
)

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

func GetOperationPath(p string, params openapi3.Parameters) (string, error) {
	subs := map[string]interface{}{}
	for _, v := range params {
		if v.Value.In != "path" {
			continue
		}

		subs[v.Value.Name] = getSchemaValue(v.Value.Schema.Value)
	}

	return stduritemplate.Expand(p, subs)
}

func (openapi *OpenAPI) Operations(client *request.Client, securitySchemes auth.SecuritySchemesMap) (request.Operations, error) {
	baseUrl := openapi.BaseUrl()

	operations := request.Operations{}
	for docPath, p := range openapi.Doc.Paths.Map() {
		for method, o := range p.Operations() {
			operationPath, err := GetOperationPath(docPath, o.Parameters)
			if err != nil {
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

				if h.Value.In == "header" {
					header.Add(name, value)
				} else if h.Value.In == "cookie" {
					cookies = append(cookies, &http.Cookie{
						Name:  name,
						Value: value,
					})
				}
			}

			var body *bytes.Buffer
			var mediaType string
			if o.RequestBody != nil {
				body, mediaType = getRequestBodyValue(o.RequestBody.Value)
				header.Set("Content-Type", mediaType)
			} else {
				body = bytes.NewBuffer(nil)
			}

			operation, err := request.NewOperation(method, operationUrl.String(), body, client)
			if err != nil {
				return nil, err
			}
			operation.WithOpenapiOperation(docPath, o)
			operation.WithCookies(cookies).WithHeader(header)

			if o.Security != nil {
				operation.SetSecuritySchemes(getOperationSecuritySchemes(o.Security, securitySchemes))
			} else if openapi.Doc.Security != nil {
				operation.SetSecuritySchemes(getOperationSecuritySchemes(&openapi.Doc.Security, securitySchemes))
			}

			operations = append(operations, operation)
		}
	}

	return operations, nil
}
