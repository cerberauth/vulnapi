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

func TestGetSchemaValue_WhenRequestBodyParametersWithMultiMediaTypes(t *testing.T) {
	expected := []byte("\"example\"")
	openapiContract, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/xml': {schema: {type: string, example: example}},'application/json': {schema: {type: string, example: example}}}}, responses: {'204': {description: successful operation}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, err)
	assert.Equal(t, "application/json", operations[0].Header.Get("Content-Type"))
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

func TestGetSchemaValue_WhenRequestBodyParametersIsString(t *testing.T) {
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

func TestGetSchemaValue_RequestBodyParameters(t *testing.T) {
	tests := []struct {
		name   string
		schema string
	}{
		{
			name:   "string",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: string}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "number",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {number: {type: number}}}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "double",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {number: {type: number, format: double}}}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "float",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {number: {type: number, format: float}}}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "integer",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {number: {type: number}}}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "int32",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {number: {type: number, format: int32}}}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "int64",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {number: {type: number, format: int64}}}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "boolean",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: boolean}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "array",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: array, items: {type: string}}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "object",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {name: {type: string}}}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "object with array",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {name: {type: array, items: {type: string}}}}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "object with array with 10 depth properties",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {name: {type: array, items: {type: object, properties: {subname: {type: array, items: {type: object, properties: {subsubname: {type: array, items: {type: object, properties: {subsubsubname: {type: array, items: {type: object, properties: {subsubsubsubname: {type: array, items: {type: object, properties: {subsubsubsubsubname: {type: array, items: {type: object, properties: {subsubsubsubsubsubname: {type: array, items: {type: object, properties: {subsubsubsubsubsubsubname: {type: array, items: {type: object, properties: {subsubsubsubsubsubsubsubname: {type: array, items: {type: object, properties: {subsubsubsubsubsubsubsubsubname: {type: array, items: {type: string }}} }}} }}} }}} }}} }}} }}} }}} }}} }}}}}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "object with object",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {name: {type: object, properties: {subname: {type: string}}}}}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "object with missing properties",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "object with 4 depth properties",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {name: {type: object, properties: {subname: {type: object, properties: {subsubname: {type: object, properties: {subsubsubname: {type: string}}}}}}}}}}}}, responses: {'204': {}}}}}}`,
		},
		{
			name:   "object with 10 depth properties",
			schema: `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {name: {type: object, properties: {subname: {type: object, properties: {subsubname: {type: object, properties: {subsubsubname: {type: object, properties: {subsubsubsubname: {type: object, properties: {subsubsubsubsubname: {type: object, properties: {subsubsubsubsubsubname: {type: object, properties: {subsubsubsubsubsubsubname: {type: object, properties: {subsubsubsubsubsubsubsubname: {type: object, properties: {subsubsubsubsubsubsubsubsubname: {type: string }}} }}}}}}}}}}}}}}}}}}}}}}}, responses: {'204': {}}}}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			openapiContract, _ := openapi.LoadFromData(
				context.TODO(),
				[]byte(tt.schema),
			)

			securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
			operations, err := openapiContract.Operations(nil, securitySchemesMap)

			assert.NoError(t, err)
			assert.NotNil(t, operations[0].Body)
		})
	}
}

func TestGetSchemaValue_RequestBodyParametersAndExample(t *testing.T) {
	tests := []struct {
		name     string
		schema   string
		expected []byte
	}{
		{
			name:     "string",
			schema:   `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: string, example: example}}}}, responses: {'204': {}}}}}}`,
			expected: []byte("\"example\""),
		},
		{
			name:     "number",
			schema:   `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {number: {type: number, example: 1.1}}}}}}, responses: {'204': {}}}}}}`,
			expected: []byte("{\"number\":1.1}"),
		},
		{
			name:     "double",
			schema:   `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {number: {type: number, format: double, example: 1.1}}}}}}, responses: {'204': {}}}}}}`,
			expected: []byte("{\"number\":1.1}"),
		},
		{
			name:     "float",
			schema:   `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {number: {type: number, format: float, example: 1.1}}}}}}, responses: {'204': {}}}}}}`,
			expected: []byte("{\"number\":1.1}"),
		},
		{
			name:     "integer",
			schema:   `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {number: {type: number, example: 1}}}}}}, responses: {'204': {}}}}}}`,
			expected: []byte("{\"number\":1}"),
		},
		{
			name:     "int32",
			schema:   `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {number: {type: number, format: int32, example: 1}}}}}}, responses: {'204': {}}}}}}`,
			expected: []byte("{\"number\":1}"),
		},
		{
			name:     "int64",
			schema:   `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {number: {type: number, format: int64, example: 1}}}}}}, responses: {'204': {}}}}}}`,
			expected: []byte("{\"number\":1}"),
		},
		{
			name:     "boolean",
			schema:   `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: boolean, example: true}}}}, responses: {'204': {}}}}}}`,
			expected: []byte("true"),
		},
		{
			name:     "array",
			schema:   `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: array, items: {type: string, example: example}}}}}, responses: {'204': {}}}}}}`,
			expected: []byte("[\"example\"]"),
		},
		{
			name:     "object",
			schema:   `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {name: {type: string, example: example}}}}}}, responses: {'204': {}}}}}}`,
			expected: []byte("{\"name\":\"example\"}"),
		},
		{
			name:     "object with array",
			schema:   `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {name: {type: array, items: {type: string, example: example}}}}}}}, responses: {'204': {}}}}}}`,
			expected: []byte("{\"name\":[\"example\"]}"),
		},
		{
			name:     "object with object",
			schema:   `{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: {'application/json': {schema: {type: object, properties: {name: {type: object, properties: {subname: {type: string, example: example}}}}}}}}, responses: {'204': {}}}}}}`,
			expected: []byte("{\"name\":{\"subname\":\"example\"}}"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			openapiContract, _ := openapi.LoadFromData(
				context.TODO(),
				[]byte(tt.schema),
			)

			securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
			operations, err := openapiContract.Operations(nil, securitySchemesMap)

			assert.NoError(t, err)
			assert.NotNil(t, operations[0].Body)
			assert.Equal(t, tt.expected, operations[0].Body)
		})
	}
}

func TestRecursiveParameters(t *testing.T) {
	openapiContract, operr := openapi.LoadFromData(
		context.Background(),
		[]byte(`{"openapi":"3.0.2","servers":[{"url":"http://localhost:8080"}],"paths":{"/":{"post":{"summary":"Create an item","requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Item"}}}},"responses":{"201":{"description":"Item created","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Item"}}}}}}}},"components":{"schemas":{"Item":{"type":"object","properties":{"details":{"type":"object","properties":{"description":{"type":"string"},"attributes":{"type":"array","items":{"$ref":"#/components/schemas/Attribute"}}}}}},"Attribute":{"type":"object","properties":{"key":{"type":"string"},"value":{"type":"string"},"subAttributes":{"type":"array","items":{"$ref":"#/components/schemas/Attribute"}}}}}}}}`),
	)

	securitySchemesMap, _ := openapiContract.SecuritySchemeMap(openapi.NewEmptySecuritySchemeValues())
	operations, err := openapiContract.Operations(nil, securitySchemesMap)

	assert.NoError(t, operr)
	assert.NoError(t, err)
	assert.NotNil(t, operations[0].Body)
}
