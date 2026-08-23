package storagejson

import (
	"encoding/base64"
	"fmt"
	"math"
	"reflect"

	"github.com/islishude/webauthn/extension"
)

const (
	valueNull     = "null"
	valueBool     = "bool"
	valueString   = "string"
	valueBytes    = "bytes"
	valueInt      = "int"
	valueUint     = "uint"
	valueFloat    = "float"
	valueArray    = "array"
	valueObject   = "object"
	maxValueDepth = 32
)

type encodedValue struct {
	Type   string                  `json:"type"`
	Bool   *bool                   `json:"bool,omitempty"`
	String *string                 `json:"string,omitempty"`
	Bytes  *string                 `json:"bytes,omitempty"`
	Int    *int64                  `json:"int,omitempty"`
	Uint   *uint64                 `json:"uint,omitempty"`
	Float  *float64                `json:"float,omitempty"`
	Array  []encodedValue          `json:"array"`
	Object map[string]encodedValue `json:"object"`
}

func encodeExtensionValues(values map[string]any) (map[string]encodedValue, error) {
	if values == nil {
		return nil, nil
	}
	out := make(map[string]encodedValue, len(values))
	for id, value := range values {
		if id == "" {
			return nil, fmt.Errorf("%w: empty extension id", ErrUnsupportedExtensionValue)
		}
		encoded, err := encodeValueAt(normalizeBuiltInValue(value), 0)
		if err != nil {
			return nil, fmt.Errorf("%w: extension %s", err, id)
		}
		out[id] = encoded
	}
	return out, nil
}

func decodeExtensionValues(values map[string]encodedValue) (map[string]any, error) {
	if values == nil {
		return nil, nil
	}
	out := make(map[string]any, len(values))
	for id, value := range values {
		if id == "" {
			return nil, fmt.Errorf("%w: empty extension id", ErrInvalidEnvelope)
		}
		decoded, err := decodeValueAt(value, 0)
		if err != nil {
			return nil, fmt.Errorf("%w: extension %s", err, id)
		}
		out[id] = decoded
	}
	return out, nil
}

func normalizeBuiltInValue(value any) any {
	switch typed := value.(type) {
	case extension.PRFInput:
		out := make(map[string]any, 3)
		if typed.Eval != nil {
			out["eval"] = prfValuesObject(*typed.Eval)
		}
		if typed.EvalByCredential != nil {
			entries := make(map[string]any, len(typed.EvalByCredential))
			for id, values := range typed.EvalByCredential {
				entries[id] = prfValuesObject(values)
			}
			out["evalByCredential"] = entries
		}
		if typed.AllowCredentials != nil {
			out["allowCredentials"] = typed.AllowCredentials
		}
		return out
	case extension.PRFValues:
		return prfValuesObject(typed)
	case extension.LargeBlobInput:
		out := make(map[string]any, 3)
		if typed.Support != "" {
			out["support"] = string(typed.Support)
		}
		if typed.Read != nil {
			out["read"] = *typed.Read
		}
		if typed.Write != nil {
			out["write"] = typed.Write
		}
		return out
	default:
		return value
	}
}

func prfValuesObject(values extension.PRFValues) map[string]any {
	out := map[string]any{"first": values.First}
	if values.Second != nil {
		out["second"] = values.Second
	}
	return out
}

func encodeValueAt(value any, depth int) (encodedValue, error) {
	if depth > maxValueDepth {
		return encodedValue{}, fmt.Errorf("%w: nesting too deep", ErrUnsupportedExtensionValue)
	}
	if value == nil {
		return encodedValue{Type: valueNull}, nil
	}
	switch typed := value.(type) {
	case bool:
		return encodedValue{Type: valueBool, Bool: pointer(typed)}, nil
	case string:
		return encodedValue{Type: valueString, String: pointer(typed)}, nil
	case []byte:
		encoded := base64.RawURLEncoding.EncodeToString(typed)
		return encodedValue{Type: valueBytes, Bytes: &encoded}, nil
	case float32:
		return encodeFloat(float64(typed))
	case float64:
		return encodeFloat(typed)
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		integer := reflected.Int()
		return encodedValue{Type: valueInt, Int: &integer}, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		integer := reflected.Uint()
		return encodedValue{Type: valueUint, Uint: &integer}, nil
	case reflect.Slice, reflect.Array:
		array := make([]encodedValue, reflected.Len())
		for i := range reflected.Len() {
			item, err := encodeValueAt(normalizeBuiltInValue(reflected.Index(i).Interface()), depth+1)
			if err != nil {
				return encodedValue{}, err
			}
			array[i] = item
		}
		return encodedValue{Type: valueArray, Array: array}, nil
	case reflect.Map:
		if reflected.Type().Key().Kind() != reflect.String {
			return encodedValue{}, fmt.Errorf("%w: map key type %s", ErrUnsupportedExtensionValue, reflected.Type().Key())
		}
		object := make(map[string]encodedValue, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			item, err := encodeValueAt(normalizeBuiltInValue(iterator.Value().Interface()), depth+1)
			if err != nil {
				return encodedValue{}, err
			}
			object[iterator.Key().String()] = item
		}
		return encodedValue{Type: valueObject, Object: object}, nil
	default:
		return encodedValue{}, fmt.Errorf("%w: type %T", ErrUnsupportedExtensionValue, value)
	}
}

func encodeFloat(value float64) (encodedValue, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return encodedValue{}, fmt.Errorf("%w: non-finite float", ErrUnsupportedExtensionValue)
	}
	return encodedValue{Type: valueFloat, Float: &value}, nil
}

func decodeValueAt(value encodedValue, depth int) (any, error) {
	if depth > maxValueDepth {
		return nil, fmt.Errorf("%w: nesting too deep", ErrInvalidEnvelope)
	}
	if err := validateEncodedValue(value); err != nil {
		return nil, err
	}
	switch value.Type {
	case valueNull:
		return nil, nil
	case valueBool:
		return *value.Bool, nil
	case valueString:
		return *value.String, nil
	case valueBytes:
		decoded, err := base64.RawURLEncoding.DecodeString(*value.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid extension bytes", ErrInvalidEnvelope)
		}
		return decoded, nil
	case valueInt:
		return *value.Int, nil
	case valueUint:
		return *value.Uint, nil
	case valueFloat:
		if math.IsNaN(*value.Float) || math.IsInf(*value.Float, 0) {
			return nil, fmt.Errorf("%w: non-finite float", ErrInvalidEnvelope)
		}
		return *value.Float, nil
	case valueArray:
		out := make([]any, len(value.Array))
		for i, item := range value.Array {
			decoded, err := decodeValueAt(item, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = decoded
		}
		return out, nil
	case valueObject:
		out := make(map[string]any, len(value.Object))
		for key, item := range value.Object {
			decoded, err := decodeValueAt(item, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = decoded
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: unknown value type", ErrInvalidEnvelope)
	}
}

func validateEncodedValue(value encodedValue) error {
	fields := 0
	for _, present := range []bool{
		value.Bool != nil,
		value.String != nil,
		value.Bytes != nil,
		value.Int != nil,
		value.Uint != nil,
		value.Float != nil,
		value.Array != nil,
		value.Object != nil,
	} {
		if present {
			fields++
		}
	}
	valid := false
	switch value.Type {
	case valueNull:
		valid = fields == 0
	case valueBool:
		valid = fields == 1 && value.Bool != nil
	case valueString:
		valid = fields == 1 && value.String != nil
	case valueBytes:
		valid = fields == 1 && value.Bytes != nil
	case valueInt:
		valid = fields == 1 && value.Int != nil
	case valueUint:
		valid = fields == 1 && value.Uint != nil
	case valueFloat:
		valid = fields == 1 && value.Float != nil
	case valueArray:
		valid = fields == 1 && value.Array != nil
	case valueObject:
		valid = fields == 1 && value.Object != nil
	}
	if !valid {
		return fmt.Errorf("%w: value fields do not match type", ErrInvalidEnvelope)
	}
	return nil
}

func pointer[T any](value T) *T {
	return &value
}
