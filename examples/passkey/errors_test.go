package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/islishude/webauthn/internal/testceremony"
	"github.com/islishude/webauthn/preset"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/browser"
	"github.com/islishude/webauthn/protocol"
	storagejson "github.com/islishude/webauthn/storage/json"
)

// classifyFailure is for internal control flow, not a public error response.
func classifyFailure(err error) string {
	var length protocol.ByteLengthError
	var value protocol.ValueError
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "cancelled"
	case errors.Is(err, webauthn.ErrInvalidConfiguration):
		return "configuration"
	case errors.Is(err, webauthn.ErrInvalidCredentialUpdate):
		return "configuration"
	case errors.Is(err, webauthn.ErrCredentialUpdateConflict):
		return "restart ceremony"
	case errors.Is(err, webauthn.ErrInvalidCeremonyState), errors.Is(err, webauthn.ErrInvalidCredentialRecord), errors.Is(err, storagejson.ErrInvalidEnvelope), errors.Is(err, storagejson.ErrUnsupportedVersion):
		return "stored state"
	case errors.Is(err, webauthn.ErrCeremonyExpired):
		return "restart ceremony"
	case errors.Is(err, webauthn.ErrRejectedAttestationPolicy), errors.Is(err, webauthn.ErrExtensionPolicy), errors.Is(err, webauthn.ErrCloneRisk):
		return "policy"
	case errors.Is(err, webauthn.ErrMalformedResponse), errors.Is(err, browser.ErrMalformedJSON), errors.Is(err, browser.ErrInvalidBase64URL), errors.Is(err, browser.ErrInvalidProtocolValue), errors.As(err, &length), errors.As(err, &value):
		return "input"
	default:
		return "verification or application dependency"
	}
}

func Example_errorClassification() {
	fmt.Println(classifyFailure(fmt.Errorf("finish: %w", webauthn.ErrCeremonyExpired)))
	fmt.Println(classifyFailure(protocol.ByteLengthError{Field: "user handle", Length: 0, Min: 1}))
	fmt.Println(classifyFailure(webauthn.ErrRejectedAttestationPolicy))
	// Output:
	// restart ceremony
	// input
	// policy
}

func TestClassificationFromAPI(t *testing.T) {
	ctx := context.Background()
	user, err := protocol.NewUserHandle([]byte("account"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := preset.PasskeyConfig(protocol.RPEntity{ID: "example.com", Name: "Example"}, webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	config.Now = func() time.Time { return now }
	rp, err := webauthn.New(config)
	if err != nil {
		t.Fatal(err)
	}
	f := testceremony.New(t, "example.com", user)
	start, err := rp.StartAuthentication(ctx, webauthn.AuthenticationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := browser.AuthenticationResponseFromJSON(f.AuthenticationJSON(t, start.State))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, want string }{
		{"success", "success"}, {"record", "stored state"}, {"expiry", "restart ceremony"}, {"response", "input"}, {"signature", "verification or application dependency"}, {"owner", "verification or application dependency"}, {"cancel", "cancelled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := webauthn.AuthenticationVerification{State: start.State, Response: response, Credential: f.Record}
			callCtx := ctx
			switch tc.name {
			case "record":
				request.Credential = webauthn.CredentialRecord{}
			case "expiry":
				request.State.ExpiresAt = now
			case "response":
				request.Response = webauthn.AuthenticationResponse{}
			case "signature":
				raw := request.Response.Signature.Bytes()
				raw[0] ^= 1
				request.Response.Signature, err = protocol.NewSignature(raw)
				if err != nil {
					t.Fatal(err)
				}
			case "owner":
				request.Response.UserHandle, err = protocol.NewUserHandle([]byte("other"))
				if err != nil {
					t.Fatal(err)
				}
			case "cancel":
				var cancel context.CancelFunc
				callCtx, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, err := rp.FinishAuthentication(callCtx, request)
			if got := classifyFailure(err); got != tc.want {
				t.Fatalf("classification %s: %v", got, err)
			}
		})
	}
	config.PubKeyCredParams = []protocol.CredentialParameter{{Type: protocol.CredentialTypePublicKey, Algorithm: protocol.AlgorithmES256}}
	restricted, err := webauthn.New(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = restricted.FinishAuthentication(ctx, webauthn.AuthenticationVerification{State: start.State, Response: response, Credential: f.Record})
	if !errors.Is(err, webauthn.ErrUnsupportedAlgorithm) || errors.Is(err, webauthn.ErrInvalidCredentialRecord) {
		t.Fatal(err)
	}
	config.RP.ID = ""
	_, err = webauthn.New(config)
	if classifyFailure(err) != "configuration" {
		t.Fatal(err)
	}
}
