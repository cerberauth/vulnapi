package openapi_test

import (
	"encoding/json"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOperations_NumberAndIntegerParameterExamples(t *testing.T) {
	openapiContract, err := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [
		{name: X-Double, in: header, required: true, schema: {type: number, format: double, example: 1.5}},
		{name: X-Int32, in: header, required: true, schema: {type: integer, format: int32, example: 32}},
		{name: X-Int64, in: header, required: true, schema: {type: integer, format: int64, example: 64}},
		{name: X-Integer, in: header, required: true, schema: {type: integer, example: 7}}
	], responses: {'204': {description: successful operation}}}}}}`))
	require.NoError(t, err)

	operations, err := openapiContract.Operations(t.Context(), nil, nil)

	require.NoError(t, err)
	assert.Equal(t, "1.5", operations[0].Header.Get("X-Double"))
	assert.Equal(t, "32", operations[0].Header.Get("X-Int32"))
	assert.Equal(t, "64", operations[0].Header.Get("X-Int64"))
	assert.Equal(t, "7", operations[0].Header.Get("X-Integer"))
}

func TestOperations_PathParameterIsEncodedOnce(t *testing.T) {
	openapiContract, err := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080/api'}], paths: {'/items/{id}': {get: {parameters: [{name: id, in: path, required: true, schema: {type: string, example: 'a b'}}], responses: {'204': {description: successful operation}}}}}}`))
	require.NoError(t, err)

	operations, err := openapiContract.Operations(t.Context(), nil, nil)

	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/api/items/a%20b", operations[0].URL.String())
	assert.Equal(t, "/api/items/a b", operations[0].URL.Path)
}

func TestOperations_RequiredQueryAndPathItemParameters(t *testing.T) {
	openapiContract, err := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {'/items/{id}': {
		parameters: [{name: id, in: path, required: true, schema: {type: integer, example: 42}}, {name: tenant, in: query, required: true, schema: {type: string, example: acme}}],
		get: {parameters: [{name: limit, in: query, required: true, schema: {type: integer, example: 10}}, {name: tenant, in: query, required: true, schema: {type: string, example: other}}, {name: optional, in: query, schema: {type: string, example: no}}], responses: {'204': {description: successful operation}}}}}}`))
	require.NoError(t, err)

	operations, err := openapiContract.Operations(t.Context(), nil, nil)

	require.NoError(t, err)
	assert.Equal(t, "/items/42", operations[0].URL.Path)
	assert.Equal(t, "limit=10&tenant=other", operations[0].URL.RawQuery)
}

func TestOperations_AreSortedByPathThenMethod(t *testing.T) {
	openapiContract, err := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {
		/b: {post: {responses: {'204': {description: ok}}}, get: {responses: {'204': {description: ok}}}},
		/a: {get: {responses: {'204': {description: ok}}}},
		/c: {delete: {responses: {'204': {description: ok}}}}}}`))
	require.NoError(t, err)

	for range 5 {
		operations, err := openapiContract.Operations(t.Context(), nil, nil)

		require.NoError(t, err)
		var got []string
		for _, op := range operations {
			got = append(got, op.Method+" "+op.URL.Path)
		}
		assert.Equal(t, []string{"GET /a", "GET /b", "POST /b", "DELETE /c"}, got)
	}
}

func TestOperations_AndSecurityRequirementSendsCompanionCredentials(t *testing.T) {
	openapiContract, err := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {responses: {'204': {description: ok}}, security: [{bearer_auth: [], api_key: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer}, api_key: {type: apiKey, in: header, name: X-API-Key}}}}`))
	require.NoError(t, err)
	token := "token"
	apiKey := "key"
	securitySchemes, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewSecuritySchemeValues(map[string]interface{}{
		"bearer_auth": &token,
		"api_key":     &apiKey,
	}))
	require.NoError(t, err)

	operations, err := openapiContract.Operations(t.Context(), nil, securitySchemes)

	require.NoError(t, err)
	// "api_key" sorts first, so it is the scheme under test and the bearer
	// token is sent along with every request
	assert.Equal(t, []*auth.SecurityScheme{securitySchemes["api_key"]}, operations[0].SecuritySchemes)
	assert.Equal(t, "Bearer token", operations[0].Header.Get("Authorization"))
}

func TestOperations_RequestBodies(t *testing.T) {
	tests := []struct {
		name                string
		content             string
		expectedContentType string
		expectedBody        string
	}{
		{
			name:                "example keys missing from properties",
			content:             `{'application/json': {schema: {type: object, properties: {name: {type: string}}, example: {name: john, extra: 1}}}}`,
			expectedContentType: "application/json",
			expectedBody:        `{"extra":1,"name":"john"}`,
		},
		{
			name:                "array without items",
			content:             `{'application/json': {schema: {type: array}}}`,
			expectedContentType: "application/json",
			expectedBody:        `[]`,
		},
		{
			name:                "string is JSON-escaped",
			content:             `{'application/json': {schema: {type: string, example: 'say "hi" <b>'}}}`,
			expectedContentType: "application/json",
			expectedBody:        `"say \"hi\" <b>"`,
		},
		{
			name:                "allOf is merged",
			content:             `{'application/json': {schema: {allOf: [{type: object, properties: {a: {type: string, example: x}}}, {type: object, properties: {b: {type: integer, example: 2}}}]}}}`,
			expectedContentType: "application/json",
			expectedBody:        `{"a":"x","b":2}`,
		},
		{
			name:                "oneOf uses the first schema",
			content:             `{'application/json': {schema: {oneOf: [{type: string, example: first}, {type: integer, example: 2}]}}}`,
			expectedContentType: "application/json",
			expectedBody:        `"first"`,
		},
		{
			name:                "vendor JSON media type",
			content:             `{'application/vnd.api+json': {schema: {type: object, properties: {a: {type: string, example: x}}}}}`,
			expectedContentType: "application/vnd.api+json",
			expectedBody:        `{"a":"x"}`,
		},
		{
			name:                "form urlencoded",
			content:             `{'application/x-www-form-urlencoded': {schema: {type: object, properties: {a: {type: string, example: 'x y'}, b: {type: integer, example: 2}}}}}`,
			expectedContentType: "application/x-www-form-urlencoded",
			expectedBody:        `a=x+y&b=2`,
		},
		{
			name:                "JSON is preferred",
			content:             `{'text/plain': {schema: {type: string, example: text}}, 'application/json': {schema: {type: string, example: json}}}`,
			expectedContentType: "application/json",
			expectedBody:        `"json"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			openapiContract, err := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {post: {requestBody: {content: `+tt.content+`}, responses: {'204': {description: ok}}}}}}`))
			require.NoError(t, err)

			operations, err := openapiContract.Operations(t.Context(), nil, nil)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedContentType, operations[0].Header.Get("Content-Type"))
			assert.Equal(t, tt.expectedBody, string(operations[0].Body))
			if tt.expectedContentType != "application/x-www-form-urlencoded" {
				assert.True(t, json.Valid(operations[0].Body))
			}
		})
	}
}
