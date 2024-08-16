package openapi

import (
	"bytes"
	"strconv"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/getkin/kin-openapi/openapi3"
)

func getParameterValue(param *openapi3.Parameter) string {
	if param.Schema != nil {
		value := getSchemaValue(param.Schema.Value)
		if param.Schema.Value.Type.Is("string") {
			return value.(string)
		} else if param.Schema.Value.Type.Is("number") {
			return strconv.FormatFloat(value.(float64), 'f', -1, 64)
		} else if param.Schema.Value.Type.Is("integer") {
			return strconv.Itoa(value.(int))
		} else if param.Schema.Value.Type.Is("boolean") {
			return strconv.FormatBool(value.(bool))
		}
	}

	return ""
}

func mapRequestBodyFakeValueToJSON(schema *openapi3.Schema, fakeValue interface{}) *bytes.Buffer {
	jsonResponse := []byte("{}")
	if schema.Type.Is("string") {
		jsonResponse = []byte("\"" + fakeValue.(string) + "\"")
	} else if schema.Type.Is("number") {
		jsonResponse = []byte(strconv.FormatFloat(fakeValue.(float64), 'f', -1, 64))
	} else if schema.Type.Is("integer") {
		jsonResponse = []byte(strconv.Itoa(fakeValue.(int)))
	} else if schema.Type.Is("boolean") {
		jsonResponse = []byte(strconv.FormatBool(fakeValue.(bool)))
	} else if schema.Type.Is("array") {
		jsonResponse = []byte("[")
		for i, value := range fakeValue.([]interface{}) {
			if i > 0 {
				jsonResponse = append(jsonResponse, ',')
			}
			jsonResponse = append(jsonResponse, mapRequestBodyFakeValueToJSON(schema.Items.Value, value).Bytes()...)
		}
		jsonResponse = append(jsonResponse, ']')
	} else if schema.Type.Is("object") {
		jsonResponse = []byte("{")
		i := 0
		for key, value := range fakeValue.(map[string]interface{}) {
			if i > 0 {
				jsonResponse = append(jsonResponse, ',')
			}
			jsonResponse = append(jsonResponse, []byte("\""+key+"\":")...)
			jsonResponse = append(jsonResponse, mapRequestBodyFakeValueToJSON(schema.Properties[key].Value, value).Bytes()...)
			i++
		}
		jsonResponse = append(jsonResponse, '}')
	}

	return bytes.NewBuffer(jsonResponse)
}

func getRequestBodyValue(requestBody *openapi3.RequestBody) (*bytes.Buffer, string) {
	if requestBody.Content != nil {
		for mediaType, mediaTypeValue := range requestBody.Content {
			if mediaTypeValue.Schema != nil {
				body := getSchemaValue(mediaTypeValue.Schema.Value)
				switch mediaType {
				case "application/json":
					return mapRequestBodyFakeValueToJSON(mediaTypeValue.Schema.Value, body), "application/json"
				}
			}
		}
	}

	return bytes.NewBuffer(nil), ""
}

func getSchemaValue(schema *openapi3.Schema) interface{} {
	if schema.Example != nil {
		return schema.Example
	} else if len(schema.Enum) > 0 {
		return schema.Enum[gofakeit.Number(0, len(schema.Enum)-1)]
	}

	// if there is no example generate random param
	if schema.Type.Is("number") || schema.Type.Is("integer") {
		return gofakeit.Number(0, 10)
	} else if schema.Type.Is("boolean") {
		return gofakeit.Bool()
	} else if schema.Type.Is("array") {
		return []interface{}{getSchemaValue(schema.Items.Value)}
	} else if schema.Type.Is("object") {
		object := map[string]interface{}{}
		for key, value := range schema.Properties {
			object[key] = getSchemaValue(value.Value)
		}
		return object
	} else if schema.Type.Is("string") {
		switch schema.Format {
		case "date":
			return gofakeit.Date().Format("2006-01-02")
		case "date-time":
			return gofakeit.Date().Format("2006-01-02T15:04:05Z")
		case "password":
			return gofakeit.Password(true, true, true, true, false, 10)
		case "byte":
			return gofakeit.LetterN(10)
		case "binary":
			return gofakeit.LetterN(10)
		case "email":
			return gofakeit.Email()
		case "uuid":
			return gofakeit.UUID()
		case "uri":
			return gofakeit.URL()
		case "hostname":
			return gofakeit.DomainName()
		case "ipv4":
			return gofakeit.IPv4Address()
		case "ipv6":
			return gofakeit.IPv6Address()
		default:
			return gofakeit.Word()
		}
	}

	return ""
}
