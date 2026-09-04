package extension

import (
	"fmt"
	"reflect"
	"slices"
)

const (
	// DefaultMaxCloneDepth bounds recursive extension value nesting.
	DefaultMaxCloneDepth = 32
	// DefaultMaxCloneNodes bounds aggregate container and scalar work.
	DefaultMaxCloneNodes = 4096
	// DefaultMaxCloneBytes bounds aggregate string and byte-slice data.
	DefaultMaxCloneBytes = 1 << 20
)

// CloneLimits bounds recursive defensive-copy work.
type CloneLimits struct {
	MaxDepth int
	MaxNodes int
	MaxBytes int
}

type cloneBudget struct {
	limits CloneLimits
	nodes  int
	bytes  int
}

// CloneValue returns a recursive defensive copy of supported extension input
// and output values. Application-specific types may provide Clone() T;
// unsupported structs fail explicitly.
func CloneValue(value any) (any, error) {
	return CloneValueWithLimits(value, CloneLimits{})
}

// CloneValueWithLimits returns a recursive defensive copy using limits. Zero
// fields select the package defaults.
func CloneValueWithLimits(value any, limits CloneLimits) (any, error) {
	if limits.MaxDepth < 0 || limits.MaxNodes < 0 || limits.MaxBytes < 0 {
		return nil, fmt.Errorf("%w: clone limits must not be negative", ErrInvalidRequest)
	}
	limits = normalizeCloneLimits(limits)
	budget := &cloneBudget{limits: limits}
	return cloneValueAt(value, 0, budget)
}

func normalizeCloneLimits(limits CloneLimits) CloneLimits {
	if limits.MaxDepth == 0 {
		limits.MaxDepth = DefaultMaxCloneDepth
	}
	if limits.MaxNodes == 0 {
		limits.MaxNodes = DefaultMaxCloneNodes
	}
	if limits.MaxBytes == 0 {
		limits.MaxBytes = DefaultMaxCloneBytes
	}
	return limits
}

func (budget *cloneBudget) consume(nodes int, bytes int) error {
	if nodes < 0 || bytes < 0 || budget.nodes > budget.limits.MaxNodes-nodes || budget.bytes > budget.limits.MaxBytes-bytes {
		return fmt.Errorf("%w: extension value exceeds clone budget", ErrInvalidRequest)
	}
	budget.nodes += nodes
	budget.bytes += bytes
	return nil
}

func cloneValueAt(value any, depth int, budget *cloneBudget) (any, error) {
	if depth > budget.limits.MaxDepth {
		return nil, fmt.Errorf("%w: extension value nesting too deep", ErrInvalidRequest)
	}
	nodes, byteCount := directCloneCost(value)
	if err := budget.consume(nodes, byteCount); err != nil {
		return nil, err
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
	if cloned, ok, err := cloneWithMethod(value); ok {
		return cloned, err
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Slice, reflect.Array:
		out := reflect.New(reflected.Type()).Elem()
		if reflected.Kind() == reflect.Slice {
			out = reflect.MakeSlice(reflected.Type(), reflected.Len(), reflected.Len())
		}
		for i := range reflected.Len() {
			item, err := cloneValueAt(reflected.Index(i).Interface(), depth+1, budget)
			if err != nil {
				return nil, err
			}
			if err := setClonedValue(out.Index(i), item); err != nil {
				return nil, err
			}
		}
		return out.Interface(), nil
	case reflect.Map:
		out := reflect.MakeMapWithSize(reflected.Type(), reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			if err := budget.consume(1, mapKeyByteSize(iterator.Key())); err != nil {
				return nil, err
			}
			key, err := cloneMapKey(iterator.Key())
			if err != nil {
				return nil, err
			}
			item, err := cloneValueAt(iterator.Value().Interface(), depth+1, budget)
			if err != nil {
				return nil, err
			}
			keyValue := reflect.ValueOf(key)
			if key == nil {
				keyValue = reflect.Zero(reflected.Type().Key())
			}
			valueTarget := reflect.New(reflected.Type().Elem()).Elem()
			if err := setClonedValue(valueTarget, item); err != nil {
				return nil, err
			}
			out.SetMapIndex(keyValue, valueTarget)
		}
		return out.Interface(), nil
	default:
		return nil, fmt.Errorf("%w: extension value type %T", ErrInvalidRequest, value)
	}
}

func directCloneCost(value any) (int, int) {
	switch typed := value.(type) {
	case nil:
		return 1, 0
	case string:
		return 1, len(typed)
	case []byte:
		return 1, len(typed)
	case PRFValues:
		return 3, len(typed.First) + len(typed.Second)
	case PRFInput:
		nodes, bytes := 1+len(typed.AllowCredentials)+len(typed.EvalByCredential), 0
		if typed.Eval != nil {
			nodes += 2
			bytes += len(typed.Eval.First) + len(typed.Eval.Second)
		}
		for _, credential := range typed.AllowCredentials {
			bytes += len(credential)
		}
		for id, values := range typed.EvalByCredential {
			nodes += 2
			bytes += len(id) + len(values.First) + len(values.Second)
		}
		return nodes, bytes
	case PRFResult:
		nodes, bytes := directCloneCost(PRFInput{Eval: typed.Eval, EvalByCredential: typed.EvalByCredential})
		if typed.Results != nil {
			nodes += 2
			bytes += len(typed.Results.First) + len(typed.Results.Second)
		}
		return nodes, bytes
	case LargeBlobInput:
		return 3, len(typed.Write)
	case LargeBlobResult:
		return 6, len(typed.Write) + len(typed.Blob)
	case UVMResult:
		return 1 + len(typed.Entries), 0
	case []UVMEntry:
		return 1 + len(typed), 0
	default:
		return 1, 0
	}
}

func mapKeyByteSize(value reflect.Value) int {
	for value.Kind() == reflect.Interface && !value.IsNil() {
		value = value.Elem()
	}
	if value.IsValid() && value.Kind() == reflect.String {
		return value.Len()
	}
	return 0
}

func cloneWithMethod(value any) (cloned any, ok bool, err error) {
	reflected := reflect.ValueOf(value)
	if nilLike(value) {
		return nil, false, nil
	}
	method := reflected.MethodByName("Clone")
	if !method.IsValid() {
		return nil, false, nil
	}
	methodType := method.Type()
	if methodType.NumIn() != 0 || methodType.NumOut() != 1 || methodType.Out(0) != reflected.Type() {
		return nil, false, nil
	}
	result := method.Call(nil)
	return result[0].Interface(), true, nil
}

func setClonedValue(target reflect.Value, value any) error {
	if value == nil {
		switch target.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			target.SetZero()
			return nil
		default:
			return fmt.Errorf("%w: nil cannot populate %s", ErrInvalidRequest, target.Type())
		}
	}
	reflected := reflect.ValueOf(value)
	if !reflected.Type().AssignableTo(target.Type()) {
		return fmt.Errorf("%w: cloned type %s cannot populate %s", ErrInvalidRequest, reflected.Type(), target.Type())
	}
	target.Set(reflected)
	return nil
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
