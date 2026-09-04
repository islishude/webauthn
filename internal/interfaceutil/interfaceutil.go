// Package interfaceutil contains small helpers for safely validating injected
// interface implementations at public configuration boundaries.
package interfaceutil

import "reflect"

// IsNil reports whether value is nil or contains a typed nil value.
func IsNil(value any) bool {
	if value == nil {
		return true
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
