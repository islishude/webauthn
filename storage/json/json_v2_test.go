package storagejson_test

import (
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	storagejson "github.com/islishude/webauthn/storage/json"
)

func TestEnvelopeJSONStrictDecoding(t *testing.T) {
	raw, err := storagejson.MarshalRegistrationState(registrationStateFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	valid := string(raw)
	for _, tt := range []struct{ name, data string }{
		{"duplicate", strings.Replace(valid, "{", `{"version":1,`, 1)},
		{"nested duplicate", strings.Replace(valid, `"registrationState":{`, `"registrationState":{"rpId":"example.com",`, 1)},
		{"invalid UTF-8", strings.Replace(valid, "example.com", "exam\xffple.com", 1)},
		{"case variant", strings.Replace(valid, `"version"`, `"Version"`, 1)},
		{"unknown", strings.Replace(valid, "{", `{"future":true,`, 1)},
		{"trailing", valid + ` {}`},
		{"null", strings.Replace(valid, `"version":1`, `"version":null`, 1)},
		{"missing", strings.Replace(valid, `"version":1,`, "", 1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.data == valid {
				t.Fatal("fixture mutation had no effect")
			}
			_, err := storagejson.UnmarshalRegistrationState([]byte(tt.data))
			if !errors.Is(err, storagejson.ErrInvalidEnvelope) && !errors.Is(err, storagejson.ErrUnsupportedVersion) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDirectChallengeJSONRejected(t *testing.T) {
	if _, err := json.Marshal(mustChallenge(t)); err == nil {
		t.Fatal("private challenge bytes must use storage encoding")
	}
}
