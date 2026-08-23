package extension

import (
	"fmt"
	"reflect"
	"slices"
)

// CloneValue returns a recursive defensive copy of supported extension input
// and output values. Unsupported application-specific structs fail explicitly.
func CloneValue(value any) (any, error) {
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
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Slice, reflect.Array:
		out := make([]any, reflected.Len())
		for i := range reflected.Len() {
			item, err := CloneValue(reflected.Index(i).Interface())
			if err != nil {
				return nil, err
			}
			out[i] = item
		}
		return out, nil
	case reflect.Map:
		if reflected.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("%w: extension map key type %s", ErrInvalidRequest, reflected.Type().Key())
		}
		out := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			item, err := CloneValue(iterator.Value().Interface())
			if err != nil {
				return nil, err
			}
			out[iterator.Key().String()] = item
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: extension value type %T", ErrInvalidRequest, value)
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
