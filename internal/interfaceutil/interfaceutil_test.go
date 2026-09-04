package interfaceutil

import "testing"

func TestIsNil(t *testing.T) {
	t.Parallel()

	var pointer *int
	var function func()
	var slice []byte
	for _, test := range []struct {
		name  string
		value any
		want  bool
	}{
		{name: "nil", want: true},
		{name: "typed nil pointer", value: pointer, want: true},
		{name: "typed nil function", value: function, want: true},
		{name: "typed nil slice", value: slice, want: true},
		{name: "integer", value: 0},
		{name: "non-nil pointer", value: new(int)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := IsNil(test.value); got != test.want {
				t.Fatalf("IsNil(%T) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}
