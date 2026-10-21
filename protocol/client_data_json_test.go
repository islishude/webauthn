package protocol_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/islishude/webauthn/protocol"
)

func TestClientDataJSONStrictDecoding(t *testing.T) {
	const valid = `{"type":"webauthn.get","challenge":"MDEyMzQ1Njc4OWFiY2RlZg","origin":"https://example.com"}`
	for _, tt := range []struct {
		name, data string
		reject     bool
	}{
		{"valid", valid, false},
		{"token binding", strings.Replace(valid, "{", `{"tokenBinding":{"status":"present","id":"binding"},`, 1), false},
		{"unknown", strings.Replace(valid, "{", `{"future":{},`, 1), false},
		{"absent optional", valid, false},
		{"explicit false", strings.Replace(valid, "{", `{"crossOrigin":false,`, 1), false},
		{"duplicate", strings.Replace(valid, "{", `{"type":"webauthn.get",`, 1), true},
		{"nested duplicate", strings.Replace(valid, "{", `{"future":{"x":1,"x":2},`, 1), true},
		{"invalid UTF-8", strings.Replace(valid, "example", "exam\xffple", 1), true},
		{"case variant", strings.Replace(valid, `"type"`, `"Type"`, 1), true},
		{"trailing", valid + ` {}`, true},
		{"null", strings.Replace(valid, "{", `{"crossOrigin":null,`, 1), true},
		{"missing required", strings.Replace(valid, `"type":"webauthn.get",`, "", 1), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := protocol.NewClientDataJSON([]byte(tt.data))
			if err != nil {
				t.Fatal(err)
			}
			got, err := protocol.ParseCollectedClientData(raw)
			if (err != nil) != tt.reject {
				t.Fatalf("error = %v, reject = %v", err, tt.reject)
			}
			if err == nil && !bytes.Equal(got.Raw.Bytes(), []byte(tt.data)) {
				t.Fatal("original signed bytes changed")
			}
			if tt.name == "token binding" && (got.TokenBinding == nil || got.TokenBinding.Status != protocol.TokenBindingPresent || got.TokenBinding.ID != "binding") {
				t.Fatalf("token binding lost: %+v", got.TokenBinding)
			}
			if tt.name == "explicit false" && (got.CrossOrigin == nil || *got.CrossOrigin) {
				t.Fatal("explicit false lost")
			}
		})
	}
}
