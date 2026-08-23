package protocolidentifier

import "testing"

func TestValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "one octet", value: "a", want: true},
		{name: "maximum", value: "01234567890123456789012345678901", want: true},
		{name: "case sensitive content", value: "Example.Extension", want: true},
		{name: "empty", value: "", want: false},
		{name: "too long", value: "012345678901234567890123456789012", want: false},
		{name: "space", value: "not valid", want: false},
		{name: "double quote", value: "not\"valid", want: false},
		{name: "backslash", value: "not\\valid", want: false},
		{name: "delete", value: "not\x7fvalid", want: false},
		{name: "non ascii", value: "扩展", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := Valid(test.value); got != test.want {
				t.Fatalf("Valid(%q) = %v, want %v", test.value, got, test.want)
			}
		})
	}
}
