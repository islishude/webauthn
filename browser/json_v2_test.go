package browser_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/islishude/webauthn/browser"
)

func TestResponseJSONStrictDecoding(t *testing.T) {
	const valid = `{"id":"Y3JlZGVudGlhbC0x","rawId":"Y3JlZGVudGlhbC0x","type":"public-key","clientExtensionResults":{},"response":{"clientDataJSON":"e30","authenticatorData":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","signature":"c2ln"}}`
	for _, tt := range []struct {
		name, data        string
		reject, malformed bool
	}{
		{"valid", valid, false, false},
		{"unknown", strings.Replace(valid, "{", `{"future":{},`, 1), false, false},
		{"duplicate", strings.Replace(valid, "{", `{"type":"public-key",`, 1), true, true},
		{"nested duplicate", strings.Replace(valid, `"clientExtensionResults":{}`, `"clientExtensionResults":{"future":{"x":1,"x":2}}`, 1), true, true},
		{"invalid UTF-8", strings.Replace(valid, "{", "{\"future\":\"\xff\",", 1), true, true},
		{"case variant", strings.Replace(valid, `"rawId"`, `"RawId"`, 1), true, false},
		{"trailing", valid + ` {}`, true, true},
		{"null", strings.Replace(valid, `"clientExtensionResults":{}`, `"clientExtensionResults":null`, 1), true, false},
		{"missing", strings.Replace(valid, `"clientExtensionResults":{},`, "", 1), true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := browser.AuthenticationResponseFromJSON([]byte(tt.data))
			if (err != nil) != tt.reject {
				t.Fatalf("error = %v, reject = %v", err, tt.reject)
			}
			if tt.malformed && !errors.Is(err, browser.ErrMalformedJSON) {
				t.Fatalf("classification: %v", err)
			}
		})
	}
}

func TestOptionalJSONFieldPresence(t *testing.T) {
	empty := ""
	emptyMap := map[string]browser.PRFValuesJSON{}
	raw, err := json.Marshal(browser.PRFInputJSON{EvalByCredential: &emptyMap})
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]jsontext.Value
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	if string(members["evalByCredential"]) != "{}" {
		t.Fatalf("empty object lost: %s", raw)
	}
	raw, err = json.Marshal(browser.AssertionResponseJSON{UserHandle: &empty})
	if err != nil {
		t.Fatal(err)
	}
	members = nil
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	if string(members["userHandle"]) != `""` {
		t.Fatalf("empty string lost: %s", raw)
	}
	raw, err = json.Marshal(browser.CredentialRequestOptionsJSON{})
	if err != nil {
		t.Fatal(err)
	}
	members = nil
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	if _, ok := members["timeout"]; ok {
		t.Fatalf("zero timeout not omitted: %s", raw)
	}
}
