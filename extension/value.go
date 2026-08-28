package extension

import (
	"fmt"
	"reflect"
	"slices"
)

const maxCloneDepth = 32

// CloneValue returns a recursive defensive copy of supported extension input
// and output values. Unsupported application-specific structs fail explicitly.
func CloneValue(value any) (any, error) {
	return cloneValueAt(value, 0)
}

func cloneValueAt(value any, depth int) (any, error) {
	if depth > maxCloneDepth {
		return nil, fmt.Errorf("%w: extension value nesting too deep", ErrInvalidRequest)
	}
	if value == nil {
		return nil, nil
	}
	switch typed := value.(type) {
	case bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return typed, nil
	case []byte:
		return slices.Clone(typed), nil
	case PRFInput:
		return clonePRFInput(typed), nil
	case PRFValues:
		return clonePRFValues(typed), nil
	case PRFResult:
		return clonePRFResult(typed), nil
	case LargeBlobInput:
		return cloneLargeBlobInput(typed), nil
	case LargeBlobResult:
		return cloneLargeBlobResult(typed), nil
	case CredentialPropertiesResult:
		return CredentialPropertiesResult{ResidentKey: cloneBoolPtr(typed.ResidentKey)}, nil
	case UVMResult:
		return UVMResult{Entries: cloneUVMEntries(typed.Entries)}, nil
	case []UVMEntry:
		return cloneUVMEntries(typed), nil
	case AppIDResult, AppIDExcludeResult:
		return typed, nil
	case RemoteClientDataJSONResult:
		return typed, nil
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Slice, reflect.Array:
		out := make([]any, reflected.Len())
		for i := range reflected.Len() {
			item, err := cloneValueAt(reflected.Index(i).Interface(), depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = item
		}
		return out, nil
	case reflect.Map:
		if reflected.Type().Key().Kind() == reflect.String {
			out := make(map[string]any, reflected.Len())
			iterator := reflected.MapRange()
			for iterator.Next() {
				item, err := cloneValueAt(iterator.Value().Interface(), depth+1)
				if err != nil {
					return nil, err
				}
				out[iterator.Key().String()] = item
			}
			return out, nil
		}

		out := make(map[any]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			key, err := cloneMapKey(iterator.Key())
			if err != nil {
				return nil, err
			}
			item, err := cloneValueAt(iterator.Value().Interface(), depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = item
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: extension value type %T", ErrInvalidRequest, value)
	}
}

func cloneMapKey(value reflect.Value) (any, error) {
	for value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil, nil
		}
		value = value.Elem()
	}
	if !immutableMapKeyType(value.Type()) {
		return nil, fmt.Errorf("%w: extension map key type %s", ErrInvalidRequest, value.Type())
	}
	return value.Interface(), nil
}

func immutableMapKeyType(value reflect.Type) bool {
	switch value.Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.String:
		return true
	case reflect.Array:
		return immutableMapKeyType(value.Elem())
	case reflect.Struct:
		for i := range value.NumField() {
			if !immutableMapKeyType(value.Field(i).Type) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// CloneResult returns a defensive copy of an extension result.
func CloneResult(result Result) (Result, error) {
	outputs, err := CloneValue(result.Outputs)
	if err != nil {
		return Result{}, err
	}
	clonedOutputs, _ := outputs.(map[string]any)
	return Result{
		ID:         result.ID,
		Accepted:   result.Accepted,
		Deprecated: result.Deprecated,
		Outputs:    clonedOutputs,
		Warnings:   slices.Clone(result.Warnings),
	}, nil
}
