package openapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"mime"
	"net/url"
	"slices"
	"strconv"
	"strings"

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

// formatValue formats a value built by getSchemaValue as a parameter value.
// Arrays are comma-separated (the default "simple" and "form" styles) and
// objects are JSON-encoded.
func formatValue(value interface{}, format string) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		bitSize := 64
		if format == FloatParamType {
			bitSize = 32
		}
		return strconv.FormatFloat(v, 'f', -1, bitSize)
	case int64:
		return strconv.FormatInt(v, 10)
	case bool:
		return strconv.FormatBool(v)
	case []interface{}:
		values := make([]string, len(v))
		for i, item := range v {
			values[i] = formatValue(item, "")
		}
		return strings.Join(values, ",")
	default:
		data, err := marshalJSON(v)
		if err != nil {
			return ""
		}
		return string(data)
	}
}

func getParameterValue(param *openapi3.Parameter) string {
	if param.Schema == nil || param.Schema.Value == nil {
		return ""
	}
	return formatValue(getSchemaValue(param.Schema.Value, 0), param.Schema.Value.Format)
}

func marshalJSON(value interface{}) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func isJSONMediaType(mediaType string) bool {
	return mediaType == "application/json" || (strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json"))
}

// mediaTypePriority orders the request body media types vulnapi can
// generate; unsupported media types return -1.
func mediaTypePriority(mediaType string) int {
	switch {
	case mediaType == "application/json":
		return 0
	case isJSONMediaType(mediaType):
		return 1
	case mediaType == "application/x-www-form-urlencoded":
		return 2
	case mediaType == "text/plain":
		return 3
	default:
		return -1
	}
}

func encodeRequestBody(mediaType string, value interface{}) ([]byte, error) {
	switch {
	case isJSONMediaType(mediaType):
		return marshalJSON(value)
	case mediaType == "application/x-www-form-urlencoded":
		form := url.Values{}
		if object, ok := value.(map[string]interface{}); ok {
			for key, v := range object {
				form.Set(key, formatValue(v, ""))
			}
		}
		return []byte(form.Encode()), nil
	default:
		return []byte(formatValue(value, "")), nil
	}
}

func getRequestBodyValue(requestBody *openapi3.RequestBody) (*bytes.Buffer, string, error) {
	if requestBody == nil || requestBody.Content == nil {
		return nil, "", nil
	}

	var mediaTypes []string
	for contentType, mediaTypeValue := range requestBody.Content {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || mediaTypeValue == nil || mediaTypeValue.Schema == nil || mediaTypeValue.Schema.Value == nil || mediaTypePriority(mediaType) < 0 {
			continue
		}
		mediaTypes = append(mediaTypes, contentType)
	}
	if len(mediaTypes) == 0 {
		return nil, "", NewErrNoSupportedBodyMediaType()
	}
	slices.SortFunc(mediaTypes, func(a, b string) int {
		ma, _, _ := mime.ParseMediaType(a)
		mb, _, _ := mime.ParseMediaType(b)
		if pa, pb := mediaTypePriority(ma), mediaTypePriority(mb); pa != pb {
			return pa - pb
		}
		return strings.Compare(a, b)
	})

	contentType := mediaTypes[0]
	mediaType, _, _ := mime.ParseMediaType(contentType)
	body, err := encodeRequestBody(mediaType, getSchemaValue(requestBody.Content[contentType].Schema.Value, 0))
	if err != nil {
		return nil, "", err
	}
	return bytes.NewBuffer(body), contentType, nil
}

// normalizeNumber converts the numeric types an example can be decoded as
// into float64, or int64 when integer is true. ok is false when value is
// not a number or not an integral number for integer.
func normalizeNumber(value interface{}, integer bool) (interface{}, bool) {
	var f float64
	switch v := value.(type) {
	case float64:
		f = v
	case float32:
		f = float64(v)
	case int:
		f = float64(v)
	case int32:
		f = float64(v)
	case int64:
		if integer {
			return v, true
		}
		f = float64(v)
	case uint64:
		f = float64(v)
	case json.Number:
		if integer {
			i, err := v.Int64()
			return i, err == nil
		}
		parsed, err := v.Float64()
		if err != nil {
			return nil, false
		}
		f = parsed
	case string:
		if integer {
			i, err := strconv.ParseInt(v, 10, 64)
			return i, err == nil
		}
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, false
		}
		f = parsed
	default:
		return nil, false
	}

	if !integer {
		return f, true
	}
	if f != math.Trunc(f) {
		return nil, false
	}
	return int64(f), true
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
	switch {
	case schema.Type.Is("string"):
		_, ok = example.(string)
	case schema.Type.Is("number"):
		example, ok = normalizeNumber(example, false)
	case schema.Type.Is("integer"):
		example, ok = normalizeNumber(example, true)
	case schema.Type.Is("boolean"):
		if s, isString := example.(string); isString {
			parsed, parseErr := strconv.ParseBool(s)
			example, ok = parsed, parseErr == nil
		} else {
			_, ok = example.(bool)
		}
	case schema.Type.Is("array"):
		_, ok = example.([]interface{})
	case schema.Type.Is("object"):
		_, ok = example.(map[string]interface{})
	default:
		ok = true
	}
	if !ok {
		return nil, fmt.Errorf("invalid example type")
	}
	return example, nil
}

func isObjectSchema(schema *openapi3.Schema) bool {
	return schema.Type.Is("object") || (schema.Type == nil && len(schema.Properties) > 0)
}

func getSchemaValue(schema *openapi3.Schema, depth int) interface{} {
	if schema == nil {
		return nil
	}

	example, err := parseSchemaExample(schema)
	if err == nil && example != nil {
		return example
	}

	// allOf merges every subschema; oneOf and anyOf use the first one
	if len(schema.AllOf) > 0 {
		object := map[string]interface{}{}
		var value interface{}
		for _, subSchema := range schema.AllOf {
			if subSchema == nil || depth > maximumDepth {
				continue
			}
			subValue := getSchemaValue(subSchema.Value, depth+1)
			if subObject, ok := subValue.(map[string]interface{}); ok {
				for key, v := range subObject {
					object[key] = v
				}
			} else if value == nil {
				value = subValue
			}
		}
		if isObjectSchema(schema) {
			for key, v := range getObjectValue(schema, depth) {
				object[key] = v
			}
		}
		if len(object) > 0 || value == nil {
			return object
		}
		return value
	}
	for _, alternatives := range []openapi3.SchemaRefs{schema.OneOf, schema.AnyOf} {
		if len(alternatives) > 0 && alternatives[0] != nil && depth <= maximumDepth {
			return getSchemaValue(alternatives[0].Value, depth+1)
		}
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
		if depth > maximumDepth || schema.Items == nil || schema.Items.Value == nil {
			return []interface{}{}
		}
		return []interface{}{getSchemaValue(schema.Items.Value, depth+1)}
	case isObjectSchema(schema):
		return getObjectValue(schema, depth)
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

func getObjectValue(schema *openapi3.Schema, depth int) map[string]interface{} {
	object := map[string]interface{}{}
	if depth > maximumDepth {
		return object
	}
	for key, value := range schema.Properties {
		if value == nil || value.Value == nil {
			continue
		}
		object[key] = getSchemaValue(value.Value, depth+1)
	}
	return object
}
