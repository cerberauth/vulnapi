package openapi

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/getkin/kin-openapi/openapi3"
)

const maximumDepth = 4

const (
	FloatParamType   = "float"
	DoubleParamType  = "double"
	Int32ParamFormat = "int32"
	Int64ParamFormat = "int64"
)

func NewErrNoSupportedBodyMediaType() error {
	return fmt.Errorf("no supported body media type")
}

func getParameterValue(param *openapi3.Parameter) string {
	if param.Schema != nil {
		value := getSchemaValue(param.Schema.Value, 0)
		switch {
		case param.Schema.Value.Type.Is("string"):
			return value.(string)
		case param.Schema.Value.Type.Is("number"):
			switch param.Schema.Value.Format {
			case FloatParamType:
				return strconv.FormatFloat(value.(float64), 'f', -1, 32)
			case DoubleParamType:
			default:
				return strconv.FormatFloat(value.(float64), 'f', -1, 64)
			}
		case param.Schema.Value.Type.Is("integer"):
			return strconv.FormatInt(value.(int64), 10)
		case param.Schema.Value.Type.Is("boolean"):
			return strconv.FormatBool(value.(bool))
		}
	}
	return ""
}

func mapRequestBodyFakeValueToJSON(schema *openapi3.Schema, fakeValue interface{}) *bytes.Buffer {
	jsonResponse := []byte("{}")
	switch {
	case schema.Type.Is("string"):
		jsonResponse = []byte("\"" + fakeValue.(string) + "\"")
	case schema.Type.Is("number"):
		jsonResponse = []byte(strconv.FormatFloat(fakeValue.(float64), 'f', -1, 64))
	case schema.Type.Is("integer"):
		jsonResponse = []byte(strconv.FormatInt(fakeValue.(int64), 10))
	case schema.Type.Is("boolean"):
		jsonResponse = []byte(strconv.FormatBool(fakeValue.(bool)))
	case schema.Type.Is("array"):
		jsonResponse = []byte("[")
		for i, value := range fakeValue.([]interface{}) {
			if i > 0 {
				jsonResponse = append(jsonResponse, ',')
			}
			jsonResponse = append(jsonResponse, mapRequestBodyFakeValueToJSON(schema.Items.Value, value).Bytes()...)
		}
		jsonResponse = append(jsonResponse, ']')
	case schema.Type.Is("object"):
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

func getRequestBodyValue(requestBody *openapi3.RequestBody) (*bytes.Buffer, string, error) {
	if requestBody == nil || requestBody.Content == nil {
		return nil, "", nil
	}
	for mediaType, mediaTypeValue := range requestBody.Content {
		if mediaTypeValue.Schema != nil {
			body := getSchemaValue(mediaTypeValue.Schema.Value, 0)
			if mediaType == "application/json" {
				return mapRequestBodyFakeValueToJSON(mediaTypeValue.Schema.Value, body), mediaType, nil
			}
		}
	}
	return nil, "", NewErrNoSupportedBodyMediaType()
}

func parseSchemaExample(schema *openapi3.Schema) (interface{}, error) {
	var example interface{}
	if schema.Example != nil {
		example = schema.Example
	} else if len(schema.Enum) > 0 {
		example = schema.Enum[gofakeit.Number(0, len(schema.Enum)-1)]
	}
	if example == nil {
		return nil, nil
	}

	var ok bool
	_, ok = example.(string)
	if ok && !schema.Type.Is("string") {
		switch {
		case schema.Type.Is("number"):
			return strconv.ParseFloat(example.(string), 64)
		case schema.Type.Is("integer"):
			return strconv.ParseInt(example.(string), 10, 64)
		case schema.Type.Is("boolean"):
			return strconv.ParseBool(example.(string))
		}
	}

	switch {
	case schema.Type.Is("string"):
		example, ok = example.(string)
	case schema.Type.Is("number"):
		example, ok = example.(float64)
	case schema.Type.Is("integer"):
		switch schema.Format {
		case Int32ParamFormat:
			example, ok = example.(int32)
		case Int64ParamFormat:
		default:
			example, ok = example.(int64)
		}
	case schema.Type.Is("boolean"):
		example, ok = example.(bool)
	case schema.Type.Is("array"):
		example, ok = example.([]interface{})
	case schema.Type.Is("object"):
		example, ok = example.(map[string]interface{})
	}
	if !ok {
		return nil, fmt.Errorf("invalid example type")
	}
	return example, nil
}

func getSchemaValue(schema *openapi3.Schema, depth int) interface{} {
	example, err := parseSchemaExample(schema)
	if err == nil && example != nil {
		return example
	}

	// if there is no example generate random param
	switch {
	case schema.Type.Is("number"):
		return gofakeit.Float64()
	case schema.Type.Is("integer"):
		return gofakeit.Int64()
	case schema.Type.Is("boolean"):
		return gofakeit.Bool()
	case schema.Type.Is("array"):
		if depth > maximumDepth {
			return []interface{}{}
		}
		return []interface{}{getSchemaValue(schema.Items.Value, depth+1)}
	case schema.Type.Is("object"):
		object := map[string]interface{}{}
		if depth > maximumDepth {
			return object
		}
		for key, value := range schema.Properties {
			object[key] = getSchemaValue(value.Value, depth+1)
		}
		return object
	case schema.Type.Is("string"):
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
