package openapi_test

import (
	"context"
	"testing"

	"github.com/cerberauth/vulnapi/openapi"
	"github.com/stretchr/testify/assert"
)

func TestGetSchemaValue_WhenNoParameters(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 0)
	assert.Len(t, operations[0].Cookies, 0)
}

func TestGetSchemaValue_WhenHeaderParametersWithExample(t *testing.T) {
	expected := "example"
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [{name: param, in: header, required: true, schema: {type: string, example: example}}], responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 1)
	assert.Equal(t, expected, operations[0].Header.Get("param"))
	assert.Len(t, operations[0].Cookies, 0)
}

func TestGetSchemaValue_WhenHeaderParametersWithoutExample(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [{name: param, in: header, required: true, schema: {type: string}}], responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 1)
	assert.GreaterOrEqual(t, len(operations[0].Header.Get("param")), 1)
	assert.NotEqual(t, "", operations[0].Header.Get("param"))
	assert.Len(t, operations[0].Cookies, 0)
}

func TestGetSchemaValue_WhenHeaderParametersNotRequired(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [{name: param, in: header, schema: {type: string, example: example}}], responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 0)
	assert.Len(t, operations[0].Cookies, 0)
}

func TestGetSchemaValue_WhenCookieParametersWithExample(t *testing.T) {
	expected := "example"
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [{name: param, in: cookie, required: true, schema: {type: string, example: example}}], responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 0)
	assert.Len(t, operations[0].Cookies, 1)
	assert.Equal(t, expected, operations[0].Cookies[0].Value)
}

func TestGetSchemaValue_WhenCookieParametersWithoutExample(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [{name: param, in: cookie, required: true, schema: {type: string}}], responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 0)
	assert.Len(t, operations[0].Cookies, 1)
	assert.GreaterOrEqual(t, len(operations[0].Cookies[0].Value), 1)
	assert.NotEqual(t, "", operations[0].Cookies[0].Value)
}

func TestGetSchemaValue_WhenCookieParametersNotRequired(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [{name: param, in: cookie, schema: {type: string, example: example}}], responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 0)
	assert.Len(t, operations[0].Cookies, 0)
}

func TestGetSchemaValue_WhenPathParametersWithExample(t *testing.T) {
	expected := "/example"
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {'/{param}': {get: {parameters: [{name: param, in: path, required: true, schema: {type: string, example: example}}], responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 0)
	assert.Len(t, operations[0].Cookies, 0)
	assert.Equal(t, expected, operations[0].URL.Path)
}

func TestGetSchemaValue_WhenPathParametersWithoutExample(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {'/{param}': {get: {parameters: [{name: param, in: path, required: true, schema: {type: string}}], responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 0)
	assert.Len(t, operations[0].Cookies, 0)
	assert.GreaterOrEqual(t, len(operations[0].URL.Path), 1)
}

func TestGetSchemaValue_WhenRequestBodyParametersWithExample(t *testing.T) {
	expected := []byte("\"example\"")
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: string, example: example}}}}, responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 1)
	assert.Equal(t, "application/json", operations[0].Header.Get("Content-Type"))
	assert.Len(t, operations[0].Cookies, 0)
	assert.NotNil(t, operations[0].Body)
	assert.Equal(t, expected, operations[0].Body)
}

func TestGetSchemaValue_WhenRequestBodyParametersWithoutExample(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: string}}}}, responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 1)
	assert.Equal(t, "application/json", operations[0].Header.Get("Content-Type"))
	assert.Len(t, operations[0].Cookies, 0)
	assert.NotNil(t, operations[0].Body)
}

func TestGetSchemaValue_WhenRequestBodyParametersNotRequired(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: string, example: example}}}}, responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 1)
	assert.Equal(t, "application/json", operations[0].Header.Get("Content-Type"))
	assert.Len(t, operations[0].Cookies, 0)
	assert.NotNil(t, operations[0].Body)
}

func TestGetSchemaValue_WhenRequestBodyParametersWithArrayExample(t *testing.T) {
	expected := []byte("[\"example\"]")
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: array, items: {type: string, example: example}}}}}, responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 1)
	assert.Equal(t, "application/json", operations[0].Header.Get("Content-Type"))
	assert.Len(t, operations[0].Cookies, 0)
	assert.NotNil(t, operations[0].Body)
	assert.Equal(t, expected, operations[0].Body)
}

func TestGetSchemaValue_WhenRequestBodyParametersWithObjectExample(t *testing.T) {
	expected := []byte("{\"name\":\"example\"}")
	openapiContract, operr := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {name: {type: string, example: example}}}}}}, responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, operr)
	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 1)
	assert.Equal(t, "application/json", operations[0].Header.Get("Content-Type"))
	assert.Len(t, operations[0].Cookies, 0)
	assert.NotNil(t, operations[0].Body)
	assert.Equal(t, expected, operations[0].Body)
}

func TestGetSchemaValue_WhenRequestBodyParametersWithObjectExampleAndArrayExample(t *testing.T) {
	expected := []byte("{\"name\":[\"example\"]}")
	openapiContract, operr := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {name: {type: array, items: {type: string, example: example}}}}}}}, responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, operr)
	assert.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.Len(t, operations[0].Header, 1)
	assert.Equal(t, "application/json", operations[0].Header.Get("Content-Type"))
	assert.Len(t, operations[0].Cookies, 0)
	assert.NotNil(t, operations[0].Body)
	assert.Equal(t, expected, operations[0].Body)
}
