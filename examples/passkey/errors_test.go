package main

import (
	"context"
	"errors"
	"fmt"

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
