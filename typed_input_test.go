package webauthn_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

// testInput adapts deliberately wire-shaped fixtures at the raw input boundary.
func testInput(value any) protocol.ExtensionInput {
	input, err := extension.NormalizeInput(value)
	if err != nil {
		panic(err)
	}
	return input
}

func testClientOutputs(values map[string]any) extension.ClientOutputs {
	out := make(extension.ClientOutputs, len(values))
	for id, value := range values {
		raw, err := extension.NewRawValue(value)
		if err != nil {
			panic(err)
		}
		out[id] = raw
	}
	return out
}

func TestAuthenticationRejectsAbsentClientOutputEntry(t *testing.T) {
	fixture := newAuthenticationFixture(t, true)
	options := fixture.finishOptions()
	options.Response.ClientExtensionResults = extension.ClientOutputs{"future": {}}
	if _, err := webauthn.FinishAuthentication(context.Background(), options); !errors.Is(err, webauthn.ErrExtensionPolicy) {
		t.Fatalf("FinishAuthentication: %v", err)
	}
}

func TestCeremonyStartRejectsOversizedUnknownStringInput(t *testing.T) {
	t.Parallel()
	registry := mustLevel3Registry(t)
	for _, size := range []int{extension.DefaultMaxCloneBytes, extension.DefaultMaxCloneBytes + 1} {
		inputs := protocol.ExtensionInputs{"future": protocol.StringInput(strings.Repeat("x", size))}
		registration, registrationErr := webauthn.StartRegistration(context.Background(), webauthn.RegistrationStartOptions{
			RP:           protocol.RPEntity{ID: "example.com", Name: "Example"},
			User:         protocol.UserEntity{ID: mustUserHandle(t, []byte("user")), Name: "user"},
			OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
			Extensions:   inputs, ExtensionRegistry: registry,
		})
		authentication, authenticationErr := webauthn.StartAuthentication(context.Background(), webauthn.AuthenticationStartOptions{
			RPID: "example.com", OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
			Extensions: inputs, ExtensionRegistry: registry,
		})
		if size > extension.DefaultMaxCloneBytes {
			if !errors.Is(registrationErr, extension.ErrInvalidRequest) || !errors.Is(authenticationErr, extension.ErrInvalidRequest) {
				t.Fatalf("oversized input accepted: registration=%v authentication=%v", registrationErr, authenticationErr)
			}
			continue
		}
		if registrationErr != nil || authenticationErr != nil {
			t.Fatalf("boundary rejected: registration=%v authentication=%v", registrationErr, authenticationErr)
		}
		if registration.State.RequestedExtensions["future"] != inputs["future"] || authentication.State.RequestedExtensions["future"] != inputs["future"] {
			t.Fatal("typed string was changed in ceremony state")
		}
	}
}
