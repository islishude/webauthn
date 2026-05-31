package webauthn_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	fxcbor "github.com/fxamacker/cbor/v2"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	attnone "github.com/islishude/webauthn/attestation/none"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

func TestRegistrationWithNoneAttestation(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)

	result, err := webauthn.FinishRegistration(context.Background(), fixture.finishOptions())
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if !bytes.Equal(result.Credential.ID.Bytes(), fixture.credentialID) {
		t.Fatalf("credential ID = %x, want %x", result.Credential.ID.Bytes(), fixture.credentialID)
	}
	if result.Credential.RPID != "example.com" {
		t.Fatalf("RPID = %q, want example.com", result.Credential.RPID)
	}
	if result.Credential.SignCount != 7 {
		t.Fatalf("SignCount = %d, want 7", result.Credential.SignCount)
	}
	if result.Attestation.Type != attestation.TypeNone || !result.AttestationTrust.Accepted {
		t.Fatalf("attestation result = %+v trust = %+v", result.Attestation, result.AttestationTrust)
	}
}

func TestRegistrationStartGeneratesDefaultChallenge(t *testing.T) {
	t.Parallel()

	userID, err := protocol.NewUserHandle([]byte("user-1"))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}

	result, err := webauthn.StartRegistration(context.Background(), webauthn.RegistrationStartOptions{
		RP:             protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:           protocol.UserEntity{ID: userID, Name: "user@example.com", DisplayName: "Example User"},
		AllowedOrigins: []string{"https://example.com"},
		PubKeyCredParams: []protocol.CredentialParameter{
			{Type: protocol.CredentialTypePublicKey, Algorithm: -7},
		},
	})
	if err != nil {
		t.Fatalf("StartRegistration() error = %v", err)
	}
	if result.State.Challenge.Len() != protocol.RecommendedChallengeLength {
		t.Fatalf("challenge length = %d, want %d", result.State.Challenge.Len(), protocol.RecommendedChallengeLength)
	}
	if result.Options.Attestation != protocol.AttestationNone {
		t.Fatalf("Attestation = %q, want none", result.Options.Attestation)
	}
}

func TestRegistrationFinishRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*testing.T, *registrationFixture, *webauthn.RegistrationFinishOptions)
		wantErr error
	}{
		{
			name: "malformed client data",
			mutate: func(t *testing.T, f *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.Response.ClientDataJSON = mustClientDataJSON(t, []byte(`{`))
				_ = f
			},
			wantErr: webauthn.ErrMalformedResponse,
		},
		{
			name: "challenge mismatch",
			mutate: func(t *testing.T, _ *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.Response.ClientDataJSON = mustClientDataJSON(t, registrationClientData(t, bytes.Repeat([]byte{0x09}, protocol.RecommendedChallengeLength), "https://example.com", false))
			},
			wantErr: webauthn.ErrChallengeMismatch,
		},
		{
			name: "origin mismatch",
			mutate: func(t *testing.T, f *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.Response.ClientDataJSON = mustClientDataJSON(t, registrationClientData(t, f.challenge.Bytes(), "https://evil.example", false))
			},
			wantErr: webauthn.ErrOriginMismatch,
		},
		{
			name: "cross origin rejected",
			mutate: func(t *testing.T, f *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.Response.ClientDataJSON = mustClientDataJSON(t, registrationClientData(t, f.challenge.Bytes(), "https://example.com", true))
			},
			wantErr: webauthn.ErrOriginMismatch,
		},
		{
			name: "token binding mismatch",
			mutate: func(t *testing.T, f *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.State.TokenBindingID = "expected-binding"
				options.Response.ClientDataJSON = mustClientDataJSON(t, registrationClientDataWithTokenBinding(t, f.challenge.Bytes(), "actual-binding"))
			},
			wantErr: webauthn.ErrMalformedResponse,
		},
		{
			name: "rp id hash mismatch",
			mutate: func(t *testing.T, f *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.Response.AttestationObject = f.attestationObject(t, "none", "other.example", registrationFlagUP|registrationFlagAT, nil, map[string]any{})
			},
			wantErr: webauthn.ErrRPIDHashMismatch,
		},
		{
			name: "missing user presence",
			mutate: func(t *testing.T, f *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.Response.AttestationObject = f.attestationObject(t, "none", "example.com", registrationFlagAT, nil, map[string]any{})
			},
			wantErr: webauthn.ErrUserPresenceRequired,
		},
		{
			name: "missing required user verification",
			mutate: func(t *testing.T, f *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.State.RequestedUserVerification = protocol.UserVerificationRequired
				options.Response.AttestationObject = f.attestationObject(t, "none", "example.com", registrationFlagUP|registrationFlagAT, nil, map[string]any{})
			},
			wantErr: webauthn.ErrUserVerificationRequired,
		},
		{
			name: "unsupported algorithm",
			mutate: func(t *testing.T, _ *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.State.AllowedAlgorithms = []protocol.COSEAlgorithmIdentifier{-257}
			},
			wantErr: webauthn.ErrUnsupportedAlgorithm,
		},
		{
			name: "unsupported attestation format",
			mutate: func(t *testing.T, f *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.Response.AttestationObject = f.attestationObject(t, "packed", "example.com", registrationFlagUP|registrationFlagAT, nil, map[string]any{})
			},
			wantErr: webauthn.ErrUnsupportedAttestationFormat,
		},
		{
			name: "none attestation rejected",
			mutate: func(t *testing.T, _ *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.AttestationPolicy.AllowNone = false
			},
			wantErr: webauthn.ErrRejectedAttestationPolicy,
		},
		{
			name: "truncated authenticator data",
			mutate: func(t *testing.T, _ *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.Response.AttestationObject = attestationObjectFromAuthData(t, bytes.Repeat([]byte{0x01}, protocol.MinAuthenticatorDataLength-1), "none", map[string]any{})
			},
			wantErr: webauthn.ErrMalformedResponse,
		},
		{
			name: "missing attested credential data",
			mutate: func(t *testing.T, _ *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.Response.AttestationObject = attestationObjectFromAuthData(t, authenticatorDataWithoutAttestation(t), "none", map[string]any{})
			},
			wantErr: webauthn.ErrMalformedResponse,
		},
		{
			name: "duplicate credential",
			mutate: func(t *testing.T, _ *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.CredentialAlreadyRegistered = true
			},
			wantErr: webauthn.ErrDuplicateCredential,
		},
		{
			name: "expired ceremony",
			mutate: func(t *testing.T, _ *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.State.ExpiresAt = time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
				options.Now = func() time.Time { return time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC) }
			},
			wantErr: webauthn.ErrCeremonyExpired,
		},
		{
			name: "unsolicited extension rejected",
			mutate: func(t *testing.T, _ *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.Response.ClientExtensionResults = map[string]any{"credProps": true}
				options.ExtensionPolicy.RejectUnrequested = true
			},
			wantErr: webauthn.ErrExtensionPolicy,
		},
		{
			name: "unsolicited authenticator extension rejected",
			mutate: func(t *testing.T, f *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.Response.AttestationObject = f.attestationObject(t, "none", "example.com", registrationFlagUP|registrationFlagAT|registrationFlagED, map[string]any{"credProps": true}, map[string]any{})
				options.ExtensionPolicy.RejectUnrequested = true
			},
			wantErr: webauthn.ErrExtensionPolicy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fixture := newRegistrationFixture(t)
			options := fixture.finishOptions()
			tt.mutate(t, fixture, &options)

			_, err := webauthn.FinishRegistration(context.Background(), options)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("FinishRegistration() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestRegistrationExtensionPolicyAllowsAbsentAndIgnoredUnrequestedExtensions(t *testing.T) {
	t.Parallel()

	requested := newRegistrationFixture(t)
	requested.start.State.RequestedExtensions = protocol.ExtensionInputs{"credProps": true}
	if _, err := webauthn.FinishRegistration(context.Background(), requested.finishOptions()); err != nil {
		t.Fatalf("FinishRegistration() with absent requested extension error = %v", err)
	}

	ignored := newRegistrationFixture(t)
	options := ignored.finishOptions()
	options.Response.ClientExtensionResults = map[string]any{"credProps": true}
	if _, err := webauthn.FinishRegistration(context.Background(), options); err != nil {
		t.Fatalf("FinishRegistration() with ignored unrequested extension error = %v", err)
	}
}

func TestRegistrationLevel2CredPropsExtension(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.State.RequestedExtensions = protocol.ExtensionInputs{extension.IDCredProps: true}
	options.Response.ClientExtensionResults = map[string]any{
		extension.IDCredProps: map[string]any{"rk": true},
	}
	options.ExtensionRegistry = mustLevel2Registry(t)

	result, err := webauthn.FinishRegistration(context.Background(), options)
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}

	extensionResult := mustExtensionResult(t, result.Extensions, extension.IDCredProps)
	output, ok := extensionResult.Outputs[extension.IDCredProps].(extension.CredentialPropertiesResult)
	if !ok {
		t.Fatalf("credProps output = %T, want CredentialPropertiesResult", extensionResult.Outputs[extension.IDCredProps])
	}
	if !extensionResult.Accepted || output.ResidentKey == nil || !*output.ResidentKey {
		t.Fatalf("extension result = %+v output = %+v", extensionResult, output)
	}
}

func TestRegistrationUnknownExtensionPolicy(t *testing.T) {
	t.Parallel()

	t.Run("preserved by default", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := fixture.finishOptions()
		options.Response.ClientExtensionResults = map[string]any{"future": true}

		result, err := webauthn.FinishRegistration(context.Background(), options)
		if err != nil {
			t.Fatalf("FinishRegistration() error = %v", err)
		}
		extensionResult := mustExtensionResult(t, result.Extensions, "future")
		if extensionResult.Accepted || extensionResult.Outputs["clientOutput"] != true {
			t.Fatalf("extension result = %+v, want untrusted raw output", extensionResult)
		}
	})

	t.Run("preserves explicit nil output", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := fixture.finishOptions()
		options.Response.ClientExtensionResults = map[string]any{"future": nil}

		result, err := webauthn.FinishRegistration(context.Background(), options)
		if err != nil {
			t.Fatalf("FinishRegistration() error = %v", err)
		}
		extensionResult := mustExtensionResult(t, result.Extensions, "future")
		clientOutput, ok := extensionResult.Outputs["clientOutput"]
		if !ok || clientOutput != nil {
			t.Fatalf("extension result = %+v, want explicit nil client output", extensionResult)
		}
	})

	t.Run("rejected by policy", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := fixture.finishOptions()
		options.Response.ClientExtensionResults = map[string]any{"future": true}
		options.ExtensionPolicy.RejectUnknown = true

		_, err := webauthn.FinishRegistration(context.Background(), options)
		if !errors.Is(err, webauthn.ErrExtensionPolicy) {
			t.Fatalf("FinishRegistration() error = %v, want ErrExtensionPolicy", err)
		}
	})
}

func TestRegistrationUnrequestedKnownExtensionOutputIsUntrusted(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.Response.ClientExtensionResults = map[string]any{
		extension.IDCredProps: map[string]any{"rk": true},
	}
	options.ExtensionRegistry = mustLevel2Registry(t)

	result, err := webauthn.FinishRegistration(context.Background(), options)
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}

	extensionResult := mustExtensionResult(t, result.Extensions, extension.IDCredProps)
	if extensionResult.Accepted {
		t.Fatalf("Accepted = true, want unrequested output to remain untrusted")
	}
	if _, ok := extensionResult.Outputs[extension.IDCredProps]; ok {
		t.Fatalf("Outputs[%s] unexpectedly contains typed trusted output: %+v", extension.IDCredProps, extensionResult.Outputs)
	}
	if _, ok := extensionResult.Outputs["clientOutput"]; !ok {
		t.Fatalf("extension result = %+v, want raw client output", extensionResult)
	}
}

func TestRegistrationAttestationTrustPolicyAcceptsNonNoneAttestation(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.Response.AttestationObject = fixture.attestationObject(t, "packed", "example.com", registrationFlagUP|registrationFlagAT, nil, map[string]any{})

	registry, err := attestation.NewRegistry(fakeRegistrationAttestationVerifier{
		format: "packed",
		result: attestation.VerificationResult{
			Type:                   attestation.TypeSelf,
			TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathNone},
			CryptographicallyValid: true,
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	options.AttestationRegistry = registry
	options.AttestationTrustPolicy = attestation.TrustPolicyFunc(func(_ context.Context, request attestation.TrustRequest) (attestation.TrustResult, error) {
		if request.Format != "packed" || request.Result.Type != attestation.TypeSelf {
			t.Fatalf("trust request = %+v, want packed self attestation", request)
		}

		return attestation.TrustResult{Accepted: true, Reason: "test policy accepted self attestation"}, nil
	})

	result, err := webauthn.FinishRegistration(context.Background(), options)
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if !result.AttestationTrust.Accepted || result.Credential.AttestationType != attestation.TypeSelf {
		t.Fatalf("result attestation = %+v trust = %+v", result.Attestation, result.AttestationTrust)
	}
}

func TestRegistrationAttestationTrustPolicyRejectsNonNoneAttestation(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.Response.AttestationObject = fixture.attestationObject(t, "packed", "example.com", registrationFlagUP|registrationFlagAT, nil, map[string]any{})

	registry, err := attestation.NewRegistry(fakeRegistrationAttestationVerifier{
		format: "packed",
		result: attestation.VerificationResult{
			Type:                   attestation.TypeSelf,
			CryptographicallyValid: true,
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	options.AttestationRegistry = registry
	options.AttestationTrustPolicy = attestation.TrustPolicyFunc(func(context.Context, attestation.TrustRequest) (attestation.TrustResult, error) {
		return attestation.TrustResult{Accepted: false, Reason: "test policy rejected self attestation"}, nil
	})

	_, err = webauthn.FinishRegistration(context.Background(), options)
	if !errors.Is(err, webauthn.ErrRejectedAttestationPolicy) {
		t.Fatalf("FinishRegistration() error = %v, want ErrRejectedAttestationPolicy", err)
	}
}

func TestRegistrationRejectsNonNoneAttestationWithoutTrustPolicy(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.Response.AttestationObject = fixture.attestationObject(t, "packed", "example.com", registrationFlagUP|registrationFlagAT, nil, map[string]any{})

	registry, err := attestation.NewRegistry(fakeRegistrationAttestationVerifier{
		format: "packed",
		result: attestation.VerificationResult{
			Type:                   attestation.TypeSelf,
			CryptographicallyValid: true,
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	options.AttestationRegistry = registry

	_, err = webauthn.FinishRegistration(context.Background(), options)
	if !errors.Is(err, webauthn.ErrRejectedAttestationPolicy) {
		t.Fatalf("FinishRegistration() error = %v, want ErrRejectedAttestationPolicy", err)
	}
}

type registrationFixture struct {
	challenge    protocol.Challenge
	credentialID []byte
	start        webauthn.RegistrationStartResult
	response     webauthn.RegistrationResponse
	decoder      *codeccbor.Decoder
	registry     *attestation.Registry
}

func newRegistrationFixture(t *testing.T) *registrationFixture {
	t.Helper()

	challenge, err := protocol.NewChallenge(bytes.Repeat([]byte{0x01}, protocol.RecommendedChallengeLength))
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}
	userHandle, err := protocol.NewUserHandle([]byte("user-1"))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}
	start, err := webauthn.StartRegistration(context.Background(), webauthn.RegistrationStartOptions{
		RP:               protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:             protocol.UserEntity{ID: userHandle, Name: "user@example.com", DisplayName: "Example User"},
		AllowedOrigins:   []string{"https://example.com"},
		Challenge:        challenge,
		UserVerification: protocol.UserVerificationPreferred,
		PubKeyCredParams: []protocol.CredentialParameter{
			{Type: protocol.CredentialTypePublicKey, Algorithm: -7},
		},
	})
	if err != nil {
		t.Fatalf("StartRegistration() error = %v", err)
	}

	registry, err := attestation.NewRegistry(attnone.New())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	fixture := &registrationFixture{
		challenge:    challenge,
		credentialID: []byte("credential-id"),
		start:        start,
		decoder:      codeccbor.MustNewDecoder(),
		registry:     registry,
	}
	fixture.response = webauthn.RegistrationResponse{
		Type:              protocol.CredentialTypePublicKey,
		RawID:             mustRawID(t, fixture.credentialID),
		ClientDataJSON:    mustClientDataJSON(t, registrationClientData(t, challenge.Bytes(), "https://example.com", false)),
		AttestationObject: fixture.attestationObject(t, "none", "example.com", registrationFlagUP|registrationFlagAT, nil, map[string]any{}),
		Transports:        []protocol.AuthenticatorTransport{protocol.TransportInternal},
	}

	return fixture
}

func (f *registrationFixture) finishOptions() webauthn.RegistrationFinishOptions {
	return webauthn.RegistrationFinishOptions{
		State:               f.start.State,
		Response:            f.response,
		Decoders:            f.decoder,
		AttestationRegistry: f.registry,
		AttestationPolicy:   webauthn.RegistrationAttestationPolicy{AllowNone: true},
	}
}

func (f *registrationFixture) attestationObject(t *testing.T, format string, rpID string, flags byte, extensions map[string]any, statement map[string]any) protocol.AttestationObject {
	t.Helper()

	return attestationObjectFromAuthData(t, f.authenticatorData(t, rpID, flags, extensions), format, statement)
}

func (f *registrationFixture) authenticatorData(t *testing.T, rpID string, flags byte, extensions map[string]any) []byte {
	t.Helper()

	rpIDHash := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, rpIDHash[:]...)
	out = append(out, flags)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 7)
	out = append(out, counter...)
	out = append(out, bytes.Repeat([]byte{0x02}, protocol.AAGUIDLength)...)
	credentialIDLength := make([]byte, 2)
	binary.BigEndian.PutUint16(credentialIDLength, checkedUint16Length(t, len(f.credentialID)))
	out = append(out, credentialIDLength...)
	out = append(out, f.credentialID...)
	out = append(out, coseKeyCBOR(t)...)
	if flags&registrationFlagED != 0 {
		out = append(out, mustCBOR(t, extensions)...)
	}

	return out
}

const (
	registrationFlagUP = byte(0x01)
	registrationFlagUV = byte(0x04)
	registrationFlagAT = byte(0x40)
	registrationFlagED = byte(0x80)
)

func registrationClientData(t *testing.T, challenge []byte, origin string, crossOrigin bool) []byte {
	t.Helper()

	if crossOrigin {
		return []byte(`{"type":"webauthn.create","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `","origin":"` + origin + `","crossOrigin":true}`)
	}

	return []byte(`{"type":"webauthn.create","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `","origin":"` + origin + `"}`)
}

func registrationClientDataWithTokenBinding(t *testing.T, challenge []byte, tokenBindingID string) []byte {
	t.Helper()

	return []byte(`{"type":"webauthn.create","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `","origin":"https://example.com","tokenBinding":{"status":"present","id":"` + tokenBindingID + `"}}`)
}

func authenticatorDataWithoutAttestation(t *testing.T) []byte {
	t.Helper()

	rpIDHash := sha256.Sum256([]byte("example.com"))
	out := append([]byte{}, rpIDHash[:]...)
	out = append(out, registrationFlagUP)
	out = append(out, 0x00, 0x00, 0x00, 0x07)
	return out
}

func attestationObjectFromAuthData(t *testing.T, authData []byte, format string, statement map[string]any) protocol.AttestationObject {
	t.Helper()

	raw, err := protocol.NewAttestationObject(mustCBOR(t, map[string]any{
		"fmt":      format,
		"authData": authData,
		"attStmt":  statement,
	}))
	if err != nil {
		t.Fatalf("NewAttestationObject() error = %v", err)
	}

	return raw
}

func mustRawID(t *testing.T, value []byte) protocol.RawID {
	t.Helper()

	rawID, err := protocol.NewRawID(value)
	if err != nil {
		t.Fatalf("NewRawID() error = %v", err)
	}

	return rawID
}

func mustClientDataJSON(t *testing.T, value []byte) protocol.ClientDataJSON {
	t.Helper()

	clientData, err := protocol.NewClientDataJSON(value)
	if err != nil {
		t.Fatalf("NewClientDataJSON() error = %v", err)
	}

	return clientData
}

func coseKeyCBOR(t *testing.T) []byte {
	t.Helper()

	return mustCBOR(t, map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: []byte("01234567890123456789012345678901"),
		-3: []byte("abcdefghijklmnopqrstuvwxyzabcdef"),
	})
}

func mustCBOR(t *testing.T, value any) []byte {
	t.Helper()

	encoded, err := fxcbor.Marshal(value)
	if err != nil {
		t.Fatalf("cbor.Marshal() error = %v", err)
	}

	return encoded
}

func checkedUint16Length(t *testing.T, length int) uint16 {
	t.Helper()

	if length < 0 || length > protocol.MaxCredentialIDLength {
		t.Fatalf("length %d is outside uint16 range", length)
	}

	return uint16(length) //nolint:gosec // length is bounded by MaxCredentialIDLength before conversion.
}

type fakeRegistrationAttestationVerifier struct {
	format string
	result attestation.VerificationResult
}

func (v fakeRegistrationAttestationVerifier) Format() string {
	return v.format
}

func (v fakeRegistrationAttestationVerifier) VerifyAttestation(context.Context, attestation.VerificationRequest) (attestation.VerificationResult, error) {
	return v.result, nil
}

var _ attestation.Verifier = fakeRegistrationAttestationVerifier{}

func mustLevel2Registry(t *testing.T) *extension.Registry {
	t.Helper()

	registry, err := extension.NewLevel2Registry()
	if err != nil {
		t.Fatalf("NewLevel2Registry() error = %v", err)
	}

	return registry
}

func mustExtensionResult(t *testing.T, results []extension.Result, id string) extension.Result {
	t.Helper()

	for _, result := range results {
		if result.ID == id {
			return result
		}
	}

	t.Fatalf("extension result %q missing from %+v", id, results)
	return extension.Result{}
}
