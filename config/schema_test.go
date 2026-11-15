package config_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cerberauth/vulnapi/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type jsonSchema map[string]interface{}

func (s jsonSchema) resolve(root jsonSchema) jsonSchema {
	ref, ok := s["$ref"].(string)
	if !ok {
		return s
	}
	def := root["$defs"].(map[string]interface{})[strings.TrimPrefix(ref, "#/$defs/")]
	return jsonSchema(def.(map[string]interface{})).resolve(root)
}

func (s jsonSchema) child(key string) jsonSchema {
	if child, ok := s[key].(map[string]interface{}); ok {
		return child
	}
	return nil
}

func yamlFields(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for i := range t.NumField() {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		name, options, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if options == "inline" {
			for k, v := range yamlFields(field.Type) {
				fields[k] = v
			}
			continue
		}
		if name == "" || name == "-" {
			continue
		}
		fields[name] = field.Type
	}
	return fields
}

var (
	valueType = reflect.TypeOf(config.Value{})
	dateType  = reflect.TypeOf(config.Date{})
	nodeType  = reflect.TypeOf(yaml.Node{})
)

func compareSchema(t *testing.T, path string, typ reflect.Type, schema, root jsonSchema) {
	schema = schema.resolve(root)
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch {
	case typ == valueType:
		assert.NotNil(t, schema["oneOf"], path)
		return
	case typ == dateType:
		assert.Equal(t, "date", schema["format"], path)
		return
	case typ == nodeType:
		assert.Equal(t, "object", schema["type"], path)
		return
	}
	switch typ.Kind() {
	case reflect.Map:
		additional := schema.child("additionalProperties")
		require.NotNil(t, additional, path)
		compareSchema(t, path+".*", typ.Elem(), additional, root)
	case reflect.Slice:
		items := schema.child("items")
		require.NotNil(t, items, path)
		compareSchema(t, path+"[]", typ.Elem(), items, root)
	case reflect.Struct:
		assert.Equal(t, false, schema["additionalProperties"], path)
		properties := schema.child("properties")
		fields := yamlFields(typ)
		assert.ElementsMatch(t, slices.Sorted(func(yield func(string) bool) {
			for k := range fields {
				if !yield(k) {
					return
				}
			}
		}), slices.Sorted(func(yield func(string) bool) {
			for k := range properties {
				if !yield(k) {
					return
				}
			}
		}), path)
		for name, fieldType := range fields {
			if property := properties.child(name); property != nil {
				compareSchema(t, path+"."+name, fieldType, property, root)
			}
		}
	case reflect.String:
		if schema["oneOf"] == nil && schema["const"] == nil {
			assert.Equal(t, "string", schema["type"], path)
		}
	case reflect.Bool:
		assert.Equal(t, "boolean", schema["type"], path)
	case reflect.Int:
		assert.NotNil(t, schema["const"], path)
	}
}

func TestSchema_MatchesStructs(t *testing.T) {
	var root jsonSchema
	require.NoError(t, json.Unmarshal(config.Schema, &root))
	assert.Equal(t, config.SchemaURL, root["$id"])
	compareSchema(t, "config", reflect.TypeOf(config.Config{}), root, root)
}
