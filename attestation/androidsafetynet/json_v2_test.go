package androidsafetynet

import (
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"
)

func TestPayloadJSONStrictDecoding(t *testing.T) {
	valid := string(safetyNetPayload(t, "expected", true, jsontext.Value("1700000000000")))
	for _, tt := range []struct {
		name, data string
		reject     bool
	}{
		{"valid", valid, false},
		{"unknown", strings.Replace(valid, "{", `{"future":{},`, 1), false},
		{"duplicate", strings.Replace(valid, "{", `{"nonce":"expected",`, 1), true},
		{"nested duplicate", strings.Replace(valid, "{", `{"future":{"x":1,"x":2},`, 1), true},
		{"invalid UTF-8", strings.Replace(valid, "{", "{\"future\":\"\xff\",", 1), true},
		{"case variant", strings.Replace(valid, `"nonce"`, `"Nonce"`, 1), true},
		{"trailing", valid + ` {}`, true},
		{"null", strings.Replace(valid, `"nonce":"expected"`, `"nonce":null`, 1), true},
		{"missing", strings.Replace(valid, `"nonce"`, `"unused"`, 1), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validatePayload([]byte(tt.data), "expected", "1.0", validPolicy())
			if (err != nil) != tt.reject {
				t.Fatalf("error = %v, reject = %v", err, tt.reject)
			}
			if tt.reject && !errors.Is(err, ErrInvalidPayload) {
				t.Fatalf("classification: %v", err)
			}
		})
	}
}
