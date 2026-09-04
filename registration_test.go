package webauthn_test

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	fxcbor "github.com/fxamacker/cbor/v2"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	attnone "github.com/islishude/webauthn/attestation/none"
	"github.com/islishude/webauthn/codec"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	webcrypto "github.com/islishude/webauthn/crypto"
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
	if result.Credential.Type != protocol.CredentialTypePublicKey {
		t.Fatalf("credential type = %q, want public-key", result.Credential.Type)
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

func TestRegistrationRejectsCredentialDecoderSourceMismatchAndTypedNil(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.CredentialPublicKeyDecoder = mismatchedSourceKeyDecoder{}
	if _, err := webauthn.FinishRegistration(context.Background(), options); !errors.Is(err, webauthn.ErrMalformedResponse) {
		t.Fatalf("source mismatch error = %v, want ErrMalformedResponse", err)
	}

	options = fixture.finishOptions()
	options.CredentialPublicKeyDecoder = invalidAlgorithmKeyDecoder{}
	if _, err := webauthn.FinishRegistration(context.Background(), options); !errors.Is(err, webauthn.ErrMalformedResponse) {
		t.Fatalf("invalid decoded key error = %v, want ErrMalformedResponse", err)
	}

	var typedNil *mismatchedSourceKeyDecoder
	options.CredentialPublicKeyDecoder = typedNil
	if _, err := webauthn.FinishRegistration(context.Background(), options); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
		t.Fatalf("typed-nil decoder error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestRegistrationRejectsAttestationDecoderSourceMismatch(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.AttestationObjectDecoder = mismatchedAttestationObjectDecoder{inner: fixture.decoder}
	if _, err := webauthn.FinishRegistration(context.Background(), options); !errors.Is(err, webauthn.ErrMalformedResponse) {
		t.Fatalf("source mismatch error = %v, want ErrMalformedResponse", err)
	}
}

func TestRegistrationTreatsUnknownAuthenticatorAttachmentAsAbsent(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.Response.AuthenticatorAttachment = protocol.AuthenticatorAttachment("future-attachment")
	result, err := webauthn.FinishRegistration(context.Background(), options)
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if result.Credential.AuthenticatorAttachment != "" {
		t.Fatalf("AuthenticatorAttachment = %q, want absent", result.Credential.AuthenticatorAttachment)
	}
}

func TestRegistrationCapturesUVInitialization(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.Response.AttestationObject = fixture.attestationObject(t, "none", "example.com", registrationFlagUP|registrationFlagUV|registrationFlagAT, nil, map[string]any{})
	result, err := webauthn.FinishRegistration(context.Background(), options)
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if !result.Credential.UVInitialized {
		t.Fatal("UVInitialized = false, want true")
	}
}

func TestConditionalRegistrationDoesNotRequireUserPresence(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.State.ConditionalMediation = true
	options.Response.AttestationObject = fixture.attestationObject(t, "none", "example.com", registrationFlagAT, nil, map[string]any{})

	if _, err := webauthn.FinishRegistration(context.Background(), options); err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
}

func TestRegistrationStartGeneratesDefaultChallenge(t *testing.T) {
	t.Parallel()

	userID, err := protocol.NewUserHandle([]byte("user-1"))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)

	result, err := webauthn.StartRegistration(context.Background(), webauthn.RegistrationStartOptions{
		RP:                   protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:                 protocol.UserEntity{ID: userID, Name: "user@example.com", DisplayName: "Example User"},
		OriginPolicy:         webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		ConditionalMediation: true,
		PubKeyCredParams: []protocol.CredentialParameter{
			{Type: protocol.CredentialTypePublicKey, Algorithm: -7},
		},
		Hints:              []protocol.PublicKeyCredentialHint{protocol.HintClientDevice},
		AttestationFormats: []string{"packed", "none"},
		Timeout:            1500 * time.Millisecond,
		StateTTL:           2 * time.Second,
		Now:                func() time.Time { return now },
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
	if len(result.Options.Hints) != 1 || result.Options.Hints[0] != protocol.HintClientDevice {
		t.Fatalf("Hints = %#v", result.Options.Hints)
	}
	if len(result.Options.AttestationFormats) != 2 || result.Options.AttestationFormats[0] != "packed" {
		t.Fatalf("AttestationFormats = %#v", result.Options.AttestationFormats)
	}
	if result.Options.TimeoutMilliseconds != 1500 {
		t.Fatalf("TimeoutMilliseconds = %v, want 1500", result.Options.TimeoutMilliseconds)
	}
	if !result.State.ExpiresAt.Equal(now.Add(2 * time.Second)) {
		t.Fatalf("ExpiresAt = %v, want %v", result.State.ExpiresAt, now.Add(2*time.Second))
	}
	if !result.State.ConditionalMediation {
		t.Fatal("ConditionalMediation = false, want true")
	}
}

func TestRegistrationStartUsesSafeTimeoutDefault(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	userHandle := mustUserHandle(t, []byte("user-1"))
	result, err := webauthn.StartRegistration(context.Background(), webauthn.RegistrationStartOptions{
		RP:               protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:             protocol.UserEntity{ID: userHandle, Name: "user@example.com", DisplayName: "Example User"},
		OriginPolicy:     webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		PubKeyCredParams: protocol.RecommendedLevel3CredentialParameters(),
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("StartRegistration() error = %v", err)
	}
	if int64(result.Options.TimeoutMilliseconds) != webauthn.DefaultBrowserTimeout.Milliseconds() {
		t.Fatalf("TimeoutMilliseconds = %d", result.Options.TimeoutMilliseconds)
	}
	if !result.State.ExpiresAt.Equal(now.Add(webauthn.DefaultChallengeTTL)) {
		t.Fatalf("ExpiresAt = %v", result.State.ExpiresAt)
	}
	if !result.State.UserHandle.Equal(userHandle) {
		t.Fatal("state user handle mismatch")
	}
}

func TestRegistrationStartRejectsInvalidTimeAndChallengeConfiguration(t *testing.T) {
	t.Parallel()

	userHandle := mustUserHandle(t, []byte("user-1"))
	base := webauthn.RegistrationStartOptions{
		RP:               protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:             protocol.UserEntity{ID: userHandle, Name: "user@example.com", DisplayName: "Example User"},
		OriginPolicy:     webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		PubKeyCredParams: protocol.RecommendedLevel3CredentialParameters(),
	}

	negativeTimeout := base
	negativeTimeout.Timeout = -time.Second
	if _, err := webauthn.StartRegistration(context.Background(), negativeTimeout); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
		t.Fatalf("negative timeout error = %v, want ErrInvalidConfiguration", err)
	}
	negativeStateTTL := base
	negativeStateTTL.StateTTL = -time.Second
	if _, err := webauthn.StartRegistration(context.Background(), negativeStateTTL); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
		t.Fatalf("negative state ttl error = %v, want ErrInvalidConfiguration", err)
	}
	shortStateTTL := base
	shortStateTTL.Timeout = 2 * time.Minute
	shortStateTTL.StateTTL = time.Minute
	if _, err := webauthn.StartRegistration(context.Background(), shortStateTTL); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
		t.Fatalf("short state ttl error = %v, want ErrInvalidConfiguration", err)
	}

	shortChallenge := base
	shortChallenge.ChallengeGenerator = webauthn.RandomChallengeGenerator{Length: -1}
	if _, err := webauthn.StartRegistration(context.Background(), shortChallenge); err == nil {
		t.Fatal("negative challenge length accepted")
	}
	var typedNil *pointerChallengeGenerator
	typedNilGenerator := base
	typedNilGenerator.ChallengeGenerator = typedNil
	if _, err := webauthn.StartRegistration(context.Background(), typedNilGenerator); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
		t.Fatalf("typed-nil challenge generator error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestRegistrationStartUsesSpecificationAlgorithmDefaults(t *testing.T) {
	t.Parallel()

	result, err := webauthn.StartRegistration(context.Background(), webauthn.RegistrationStartOptions{
		RP:           protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:         protocol.UserEntity{ID: mustUserHandle(t, []byte("user-1")), Name: "user", DisplayName: "User"},
		OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
	})
	if err != nil {
		t.Fatalf("StartRegistration() error = %v", err)
	}
	want := []protocol.COSEAlgorithmIdentifier{protocol.AlgorithmES256, protocol.AlgorithmRS256}
	if !slices.Equal(result.State.AllowedAlgorithms, want) {
		t.Fatalf("AllowedAlgorithms = %v, want %v", result.State.AllowedAlgorithms, want)
	}
}

func TestRegistrationStartIgnoresUnsupportedCredentialTypes(t *testing.T) {
	t.Parallel()

	base := webauthn.RegistrationStartOptions{
		RP:           protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:         protocol.UserEntity{ID: mustUserHandle(t, []byte("user-1")), Name: "user", DisplayName: "User"},
		OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		PubKeyCredParams: []protocol.CredentialParameter{
			{Type: protocol.PublicKeyCredentialType("future-type"), Algorithm: 123},
			{Type: protocol.CredentialTypePublicKey, Algorithm: protocol.AlgorithmES256},
		},
	}
	result, err := webauthn.StartRegistration(context.Background(), base)
	if err != nil {
		t.Fatalf("StartRegistration() error = %v", err)
	}
	if len(result.Options.PubKeyCredParams) != 1 || result.Options.PubKeyCredParams[0].Type != protocol.CredentialTypePublicKey {
		t.Fatalf("PubKeyCredParams = %#v", result.Options.PubKeyCredParams)
	}
	base.PubKeyCredParams = base.PubKeyCredParams[:1]
	if _, err := webauthn.StartRegistration(context.Background(), base); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
		t.Fatalf("only unsupported types error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestRegistrationStartValidatesAndCopiesExtensionInputs(t *testing.T) {
	t.Parallel()

	userHandle := mustUserHandle(t, []byte("user-1"))
	base := webauthn.RegistrationStartOptions{
		RP:               protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:             protocol.UserEntity{ID: userHandle, Name: "user@example.com", DisplayName: "Example User"},
		OriginPolicy:     webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		PubKeyCredParams: protocol.RecommendedLevel3CredentialParameters(),
	}

	missingRegistry := base
	missingRegistry.Extensions = protocol.ExtensionInputs{extension.IDCredProps: true}
	if _, err := webauthn.StartRegistration(context.Background(), missingRegistry); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
		t.Fatalf("missing registry error = %v, want ErrInvalidConfiguration", err)
	}

	invalidKnown := missingRegistry
	invalidKnown.Extensions = protocol.ExtensionInputs{extension.IDCredProps: false}
	invalidKnown.ExtensionRegistry = mustLevel3Registry(t)
	if _, err := webauthn.StartRegistration(context.Background(), invalidKnown); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
		t.Fatalf("invalid known extension error = %v, want ErrInvalidConfiguration", err)
	}

	emptyRegistry, err := extension.NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	reservedUnknown := missingRegistry
	reservedUnknown.ExtensionRegistry = emptyRegistry
	if _, err := webauthn.StartRegistration(context.Background(), reservedUnknown); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
		t.Fatalf("unregistered built-in error = %v, want ErrInvalidConfiguration", err)
	}

	tooMany := base
	tooMany.Extensions = make(protocol.ExtensionInputs, extension.MaxEntries+1)
	for i := range extension.MaxEntries + 1 {
		tooMany.Extensions[fmt.Sprintf("x%02d", i)] = true
	}
	tooMany.ExtensionRegistry = emptyRegistry
	if _, err := webauthn.StartRegistration(context.Background(), tooMany); !errors.Is(err, extension.ErrTooManyEntries) {
		t.Fatalf("too many extensions error = %v, want ErrTooManyEntries", err)
	}
	nested := map[string]any{"bytes": []byte{0x01}}
	unknown := base
	unknown.Extensions = protocol.ExtensionInputs{"future": nested}
	unknown.ExtensionRegistry = emptyRegistry
	result, err := webauthn.StartRegistration(context.Background(), unknown)
	if err != nil {
		t.Fatalf("StartRegistration() error = %v", err)
	}
	nested["bytes"].([]byte)[0] = 0xff
	stateValue := result.State.RequestedExtensions["future"].(map[string]any)["bytes"].([]byte)
	optionValue := result.Options.Extensions["future"].(map[string]any)["bytes"].([]byte)
	if stateValue[0] != 0x01 || optionValue[0] != 0x01 {
		t.Fatal("extension input aliases caller memory")
	}
	stateValue[0] = 0xee
	if optionValue[0] != 0x01 {
		t.Fatal("state and browser options share extension memory")
	}

	unknown.ExtensionInputPolicy.RejectUnknown = true
	if _, err := webauthn.StartRegistration(context.Background(), unknown); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
		t.Fatalf("unknown input policy error = %v, want ErrInvalidConfiguration", err)
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
			name: "backup state without eligibility",
			mutate: func(t *testing.T, f *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.Response.AttestationObject = f.attestationObject(t, "none", "example.com", registrationFlagUP|registrationFlagBS|registrationFlagAT, nil, map[string]any{})
			},
			wantErr: webauthn.ErrInvalidBackupState,
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
				options.AttestationTrustPolicy = nil
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
			name: "missing ceremony expiry",
			mutate: func(t *testing.T, _ *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.State.ExpiresAt = time.Time{}
			},
			wantErr: webauthn.ErrInvalidCeremonyState,
		},
		{
			name: "missing ceremony user verification policy",
			mutate: func(t *testing.T, _ *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				options.State.RequestedUserVerification = ""
			},
			wantErr: webauthn.ErrInvalidCeremonyState,
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
			name: "ceremony expires at exact deadline",
			mutate: func(t *testing.T, _ *registrationFixture, options *webauthn.RegistrationFinishOptions) {
				t.Helper()
				deadline := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
				options.State.ExpiresAt = deadline
				options.Now = func() time.Time { return deadline }
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

func TestCeremonyErrorsUseOperationNeutralText(t *testing.T) {
	t.Parallel()

	if got := webauthn.ErrMalformedResponse.Error(); got != "webauthn: malformed response" {
		t.Fatalf("ErrMalformedResponse = %q", got)
	}
	if got := webauthn.ErrCeremonyExpired.Error(); got != "webauthn: ceremony expired" {
		t.Fatalf("ErrCeremonyExpired = %q", got)
	}
}

func TestRegistrationIgnoresReservedTokenBinding(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.Response.ClientDataJSON = mustClientDataJSON(t, registrationClientDataWithTokenBinding(t, fixture.challenge.Bytes(), "reserved-binding"))

	if _, err := webauthn.FinishRegistration(context.Background(), options); err != nil {
		t.Fatalf("FinishRegistration() error = %v, want tokenBinding ignored", err)
	}
}

func TestRegistrationTopOriginPolicy(t *testing.T) {
	t.Parallel()

	t.Run("accepts allowed top origin", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := fixture.finishOptions()
		options.State.OriginPolicy = webauthn.OriginPolicy{
			AllowedOrigins:      []string{"https://frame.example"},
			AllowedTopOrigins:   []string{"https://top.example"},
			AllowRelatedOrigins: true,
		}
		options.Response.ClientDataJSON = mustClientDataJSON(t, registrationClientDataWithTopOrigin(
			t,
			fixture.challenge.Bytes(),
			"https://frame.example",
			true,
			"https://top.example",
		))

		if _, err := webauthn.FinishRegistration(context.Background(), options); err != nil {
			t.Fatalf("FinishRegistration() error = %v", err)
		}
	})

	t.Run("rejects unlisted top origin", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := fixture.finishOptions()
		options.State.OriginPolicy = webauthn.OriginPolicy{
			AllowedOrigins:      []string{"https://frame.example"},
			AllowedTopOrigins:   []string{"https://top.example"},
			AllowRelatedOrigins: true,
		}
		options.Response.ClientDataJSON = mustClientDataJSON(t, registrationClientDataWithTopOrigin(
			t,
			fixture.challenge.Bytes(),
			"https://frame.example",
			true,
			"https://evil.example",
		))

		_, err := webauthn.FinishRegistration(context.Background(), options)
		if !errors.Is(err, webauthn.ErrOriginMismatch) {
			t.Fatalf("FinishRegistration() error = %v, want ErrOriginMismatch", err)
		}
	})

	t.Run("rejects top origin without cross origin", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := fixture.finishOptions()
		options.State.OriginPolicy = webauthn.OriginPolicy{
			AllowedOrigins:      []string{"https://frame.example"},
			AllowedTopOrigins:   []string{"https://top.example"},
			AllowRelatedOrigins: true,
		}
		options.Response.ClientDataJSON = mustClientDataJSON(t, registrationClientDataWithTopOrigin(
			t,
			fixture.challenge.Bytes(),
			"https://frame.example",
			false,
			"https://top.example",
		))

		_, err := webauthn.FinishRegistration(context.Background(), options)
		if !errors.Is(err, webauthn.ErrOriginMismatch) {
			t.Fatalf("FinishRegistration() error = %v, want ErrOriginMismatch", err)
		}
	})
}

func TestRegistrationExtensionPolicyAllowsAbsentAndIgnoredUnrequestedExtensions(t *testing.T) {
	t.Parallel()

	requested := newRegistrationFixture(t)
	requested.start.State.RequestedExtensions = protocol.ExtensionInputs{"future": true}
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

func TestRegistrationRejectsUnboundBuiltInAndExcessOutputs(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.State.RequestedExtensions = protocol.ExtensionInputs{extension.IDCredProps: true}
	options.ExtensionRegistry = mustLevel3Registry(t)
	if _, err := webauthn.FinishRegistration(context.Background(), options); !errors.Is(err, webauthn.ErrInvalidCeremonyState) {
		t.Fatalf("unbound built-in error = %v, want ErrInvalidCeremonyState", err)
	}

	options = fixture.finishOptions()
	options.Response.ClientExtensionResults = make(map[string]any, extension.MaxEntries+1)
	for i := range extension.MaxEntries + 1 {
		options.Response.ClientExtensionResults[fmt.Sprintf("x%02d", i)] = true
	}
	if _, err := webauthn.FinishRegistration(context.Background(), options); !errors.Is(err, extension.ErrTooManyEntries) {
		t.Fatalf("too many outputs error = %v, want ErrTooManyEntries", err)
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
	options.State.ExtensionBindings = mustExtensionBindings(t, options.ExtensionRegistry, extension.IDCredProps)

	result, err := webauthn.FinishRegistration(context.Background(), options)
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}

	typed, ok := extension.Find(result.Extensions, extension.CredPropsHandler{})
	if !ok || !typed.Accepted || typed.Output.ResidentKey == nil || !*typed.Output.ResidentKey {
		t.Fatalf("extension result = %+v", typed)
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
		raw, ok := extension.FindRaw(result.Extensions, "future")
		clientOutput, outputOK := extension.As[bool](raw.Output.ClientOutput)
		if !ok || raw.Accepted || !outputOK || !clientOutput {
			t.Fatalf("extension result = %+v, want untrusted raw output", raw)
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
		raw, ok := extension.FindRaw(result.Extensions, "future")
		if !ok || !raw.Output.ClientOutput.Present() || !raw.Output.ClientOutput.Null() {
			t.Fatalf("extension result = %+v, want explicit nil client output", raw)
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

func TestRegistrationRejectUnknownAllowsRequestedExtensionWithoutOutput(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.State.RequestedExtensions = protocol.ExtensionInputs{"future": true}
	options.ExtensionPolicy.RejectUnknown = true
	if _, err := webauthn.FinishRegistration(context.Background(), options); err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
}

func TestRegistrationExtensionResultsAreSorted(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.Response.ClientExtensionResults = map[string]any{"zeta": true, "alpha": true}
	result, err := webauthn.FinishRegistration(context.Background(), options)
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if len(result.Extensions) != 2 || result.Extensions[0].ID != "alpha" || result.Extensions[1].ID != "zeta" {
		t.Fatalf("extensions = %+v, want alpha then zeta", result.Extensions)
	}
}

func TestRegistrationExtensionOutputRunsAfterAttestationVerification(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	called := false
	handler := trackingExtensionHandler{id: "track", called: &called}
	registry, err := extension.NewRegistry(extension.Register(handler))
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	attesters, err := attestation.NewRegistry(fakeRegistrationAttestationVerifier{
		format: "none",
		result: attestation.VerificationResult{Type: attestation.TypeNone},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	options := fixture.finishOptions()
	options.State.RequestedExtensions = protocol.ExtensionInputs{"track": true}
	options.State.ExtensionBindings = mustExtensionBindings(t, registry, "track")
	options.Response.ClientExtensionResults = map[string]any{"track": true}
	options.ExtensionRegistry = registry
	options.AttestationRegistry = attesters
	if _, err := webauthn.FinishRegistration(context.Background(), options); !errors.Is(err, webauthn.ErrInvalidAttestation) {
		t.Fatalf("FinishRegistration() error = %v, want ErrInvalidAttestation", err)
	}
	if called {
		t.Fatal("extension output handler ran before attestation verification")
	}
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

	raw, ok := extension.FindRaw(result.Extensions, extension.IDCredProps)
	if !ok {
		t.Fatal("raw credProps result missing")
	}
	if raw.Accepted {
		t.Fatalf("Accepted = true, want unrequested output to remain untrusted")
	}
	if !raw.Output.ClientOutput.Present() {
		t.Fatalf("extension result = %+v, want raw client output", raw)
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

func TestRegistrationRejectsUnknownAttestationTypeFromVerifier(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.AttestationRegistry = mustRegistrationRegistry(t, fakeRegistrationAttestationVerifier{
		format: "none",
		result: attestation.VerificationResult{
			CryptographicallyValid: true,
		},
	})
	if _, err := webauthn.FinishRegistration(context.Background(), options); !errors.Is(err, webauthn.ErrInvalidAttestation) {
		t.Fatalf("FinishRegistration() error = %v, want ErrInvalidAttestation", err)
	}
}

func TestRegistrationRejectsUnknownAttestationTrustPathFromVerifier(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.AttestationRegistry = mustRegistrationRegistry(t, fakeRegistrationAttestationVerifier{
		format: "none",
		result: attestation.VerificationResult{
			Type:                   attestation.TypeNone,
			TrustPath:              attestation.TrustPath{Kind: "future"},
			CryptographicallyValid: true,
		},
	})
	if _, err := webauthn.FinishRegistration(context.Background(), options); !errors.Is(err, webauthn.ErrInvalidAttestation) {
		t.Fatalf("FinishRegistration() error = %v, want ErrInvalidAttestation", err)
	}
}

func TestRegistrationAttestationTrustPolicyRejectsNonNoneAttestation(t *testing.T) {
	t.Parallel()

	fixture := newRegistrationFixture(t)
	options := fixture.finishOptions()
	options.Response.AttestationObject = fixture.attestationObject(t, "packed", "example.com", registrationFlagUP|registrationFlagAT, nil, map[string]any{})
	options.AttestationTrustPolicy = nil

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
			TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathNone},
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

func TestRegistrationBuiltInAttestationTrustPolicies(t *testing.T) {
	t.Parallel()

	t.Run("accept none trust policy accepts valid none attestation", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := fixture.finishOptions()
		options.AttestationTrustPolicy = attestation.AcceptNone()

		result, err := webauthn.FinishRegistration(context.Background(), options)
		if err != nil {
			t.Fatalf("FinishRegistration() error = %v", err)
		}
		if !result.AttestationTrust.Accepted || result.Attestation.Type != attestation.TypeNone {
			t.Fatalf("attestation = %+v trust = %+v, want accepted none", result.Attestation, result.AttestationTrust)
		}
	})

	t.Run("reject none trust policy rejects valid none attestation", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := fixture.finishOptions()
		options.AttestationTrustPolicy = attestation.RejectNone()

		_, err := webauthn.FinishRegistration(context.Background(), options)
		if !errors.Is(err, webauthn.ErrRejectedAttestationPolicy) {
			t.Fatalf("FinishRegistration() error = %v, want ErrRejectedAttestationPolicy", err)
		}
	})

	t.Run("accept self trust policy accepts valid self attestation", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := fixture.finishOptions()
		options.Response.AttestationObject = fixture.attestationObject(t, "packed", "example.com", registrationFlagUP|registrationFlagAT, nil, map[string]any{})
		options.AttestationRegistry = mustRegistrationRegistry(t, fakeRegistrationAttestationVerifier{
			format: "packed",
			result: attestation.VerificationResult{
				Type:                   attestation.TypeSelf,
				TrustPath:              attestation.TrustPath{Kind: attestation.TrustPathNone},
				CryptographicallyValid: true,
			},
		})
		options.AttestationTrustPolicy = attestation.AcceptSelf()

		result, err := webauthn.FinishRegistration(context.Background(), options)
		if err != nil {
			t.Fatalf("FinishRegistration() error = %v", err)
		}
		if result.Credential.AttestationType != attestation.TypeSelf {
			t.Fatalf("AttestationType = %q, want self", result.Credential.AttestationType)
		}
	})

	t.Run("trust root policy accepts trusted x5c path", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := x5cRegistrationOptions(t, fixture)
		options.AttestationTrustPolicy = attestation.RequireTrustedRoots(
			&registrationCertificateVerifier{result: webcrypto.CertificateVerification{Trusted: true}},
			webcrypto.CertificateVerificationContext{DNSName: "attestation.example"},
		)

		result, err := webauthn.FinishRegistration(context.Background(), options)
		if err != nil {
			t.Fatalf("FinishRegistration() error = %v", err)
		}
		if !result.AttestationTrust.Accepted || result.Attestation.TrustPath.Kind != attestation.TrustPathX509 {
			t.Fatalf("attestation = %+v trust = %+v, want trusted x5c", result.Attestation, result.AttestationTrust)
		}
	})

	t.Run("trust root policy rejects untrusted x5c path", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := x5cRegistrationOptions(t, fixture)
		options.AttestationTrustPolicy = attestation.RequireTrustedRoots(
			&registrationCertificateVerifier{result: webcrypto.CertificateVerification{Trusted: false}},
			webcrypto.CertificateVerificationContext{},
		)

		_, err := webauthn.FinishRegistration(context.Background(), options)
		if !errors.Is(err, webauthn.ErrRejectedAttestationPolicy) {
			t.Fatalf("FinishRegistration() error = %v, want ErrRejectedAttestationPolicy", err)
		}
	})

	t.Run("metadata policy accepts trusted metadata", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := x5cRegistrationOptions(t, fixture)
		options.AttestationTrustPolicy = attestation.RequireTrustedMetadata(&registrationMetadataProvider{
			result: attestation.MetadataResult{Found: true, Trusted: true},
		})

		result, err := webauthn.FinishRegistration(context.Background(), options)
		if err != nil {
			t.Fatalf("FinishRegistration() error = %v", err)
		}
		if !result.AttestationTrust.Accepted {
			t.Fatalf("AttestationTrust = %+v, want accepted", result.AttestationTrust)
		}
	})

	t.Run("aaguid policy accepts matching authenticator", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := fixture.finishOptions()
		options.AttestationTrustPolicy = attestation.RequireAAGUID(registrationFixtureAAGUID())

		result, err := webauthn.FinishRegistration(context.Background(), options)
		if err != nil {
			t.Fatalf("FinishRegistration() error = %v", err)
		}
		if !result.AttestationTrust.Accepted {
			t.Fatalf("AttestationTrust = %+v, want accepted", result.AttestationTrust)
		}
	})

	t.Run("certificate status policy rejects revoked x5c path", func(t *testing.T) {
		t.Parallel()

		fixture := newRegistrationFixture(t)
		options := x5cRegistrationOptions(t, fixture)
		options.AttestationTrustPolicy = attestation.RequireCertificateStatus(&registrationCertificateStatusProvider{
			result: attestation.CertificateStatusResult{Status: attestation.CertificateStatusRevoked},
		})

		_, err := webauthn.FinishRegistration(context.Background(), options)
		if !errors.Is(err, webauthn.ErrRejectedAttestationPolicy) {
			t.Fatalf("FinishRegistration() error = %v, want ErrRejectedAttestationPolicy", err)
		}
	})
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
		RP:           protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:         protocol.UserEntity{ID: userHandle, Name: "user@example.com", DisplayName: "Example User"},
		OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		Challenge:    challenge,
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
		State:                      f.start.State,
		Response:                   f.response,
		AttestationObjectDecoder:   f.decoder,
		CredentialPublicKeyDecoder: f.decoder,
		ExtensionMapDecoder:        f.decoder,
		AttestationRegistry:        f.registry,
		AttestationTrustPolicy:     attestation.AcceptNone(),
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
	registrationFlagBE = byte(0x08)
	registrationFlagBS = byte(0x10)
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

func registrationClientDataWithTopOrigin(t *testing.T, challenge []byte, origin string, crossOrigin bool, topOrigin string) []byte {
	t.Helper()

	return []byte(`{"type":"webauthn.create","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `","origin":"` + origin + `","crossOrigin":` + boolJSON(crossOrigin) + `,"topOrigin":"` + topOrigin + `"}`)
}

func registrationClientDataWithTokenBinding(t *testing.T, challenge []byte, tokenBindingID string) []byte {
	t.Helper()

	return []byte(`{"type":"webauthn.create","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `","origin":"https://example.com","tokenBinding":{"status":"present","id":"` + tokenBindingID + `"}}`)
}

func boolJSON(value bool) string {
	if value {
		return "true"
	}

	return "false"
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
	curve := elliptic.P256().Params()

	return mustCBOR(t, map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: curve.Gx.FillBytes(make([]byte, 32)),
		-3: curve.Gy.FillBytes(make([]byte, 32)),
	})
}

func mustCBOR(t *testing.T, value any) []byte {
	t.Helper()

	mode, err := fxcbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("CTAP2 EncMode() error = %v", err)
	}
	encoded, err := mode.Marshal(value)
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

func x5cRegistrationOptions(t *testing.T, fixture *registrationFixture) webauthn.RegistrationFinishOptions {
	t.Helper()

	options := fixture.finishOptions()
	options.Response.AttestationObject = fixture.attestationObject(t, "packed", "example.com", registrationFlagUP|registrationFlagAT, nil, map[string]any{})
	options.AttestationRegistry = mustRegistrationRegistry(t, fakeRegistrationAttestationVerifier{
		format: "packed",
		result: attestation.VerificationResult{
			Type:                   attestation.TypeBasic,
			TrustPath:              registrationX5CTrustPath(),
			CryptographicallyValid: true,
		},
	})

	return options
}

func registrationX5CTrustPath() attestation.TrustPath {
	return attestation.TrustPath{
		Kind:         attestation.TrustPathX509,
		Certificates: webcrypto.CertificateChain{webcrypto.NewCertificate([]byte("leaf"))},
	}
}

func registrationFixtureAAGUID() protocol.AAGUID {
	var aaguid protocol.AAGUID
	for i := range aaguid {
		aaguid[i] = 0x02
	}

	return aaguid
}

func mustRegistrationRegistry(t *testing.T, verifiers ...attestation.Verifier) *attestation.Registry {
	t.Helper()

	registry, err := attestation.NewRegistry(verifiers...)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	return registry
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

type trackingExtensionHandler struct {
	id       string
	revision string
	called   *bool
}

func (h trackingExtensionHandler) ID() string {
	return h.id
}

func (h trackingExtensionHandler) Revision() string {
	if h.revision != "" {
		return h.revision
	}
	return "test-v1"
}

func (h trackingExtensionHandler) ValidateInput(request extension.InputRequest) (bool, error) {
	value, ok := extension.As[bool](request.Input)
	if !ok {
		return false, extension.ErrInvalidRequest
	}
	return value, nil
}

func (h trackingExtensionHandler) VerifyOutput(_ context.Context, request extension.OutputRequest[bool]) (extension.Verification[map[string]any], error) {
	if h.called != nil {
		*h.called = true
	}
	value, err := request.ClientOutput.Clone()
	if err != nil {
		return extension.Verification[map[string]any]{}, err
	}
	return extension.Verification[map[string]any]{Accepted: true, Output: map[string]any{"value": value}}, nil
}

var _ extension.Handler[bool, map[string]any] = trackingExtensionHandler{}

type mismatchedSourceKeyDecoder struct{}

func (mismatchedSourceKeyDecoder) DecodeCredentialPublicKey(raw []byte) (codec.CredentialPublicKey, error) {
	changed := bytes.Clone(raw)
	if len(changed) != 0 {
		changed[0] ^= 0xff
	}
	return codec.NewCredentialPublicKey(protocol.AlgorithmES256, changed, codec.CredentialPublicKeyMaterial{}), nil
}

type invalidAlgorithmKeyDecoder struct{}

func (invalidAlgorithmKeyDecoder) DecodeCredentialPublicKey(raw []byte) (codec.CredentialPublicKey, error) {
	return codec.NewCredentialPublicKey(0, raw, codec.CredentialPublicKeyMaterial{}), nil
}

type mismatchedAttestationObjectDecoder struct {
	inner codec.AttestationObjectDecoder
}

func (decoder mismatchedAttestationObjectDecoder) DecodeAttestationObject(raw protocol.AttestationObject) (codec.DecodedAttestationObject, error) {
	decoded, err := decoder.inner.DecodeAttestationObject(raw)
	if err != nil {
		return codec.DecodedAttestationObject{}, err
	}
	changed := decoded.Raw.Bytes()
	changed[0] ^= 0xff
	decoded.Raw, err = protocol.NewAttestationObject(changed)
	return decoded, err
}

type pointerChallengeGenerator struct{}

func (*pointerChallengeGenerator) GenerateChallenge(context.Context) (protocol.Challenge, error) {
	return protocol.Challenge{}, nil
}

type registrationCertificateVerifier struct {
	result webcrypto.CertificateVerification
	err    error
}

func (v *registrationCertificateVerifier) VerifyCertificateChain(context.Context, webcrypto.CertificateChain, webcrypto.CertificateVerificationContext) (webcrypto.CertificateVerification, error) {
	if v.err != nil {
		return webcrypto.CertificateVerification{}, v.err
	}

	return v.result, nil
}

type registrationMetadataProvider struct {
	result attestation.MetadataResult
	err    error
}

func (p *registrationMetadataProvider) LookupAttestationMetadata(context.Context, attestation.MetadataRequest) (attestation.MetadataResult, error) {
	if p.err != nil {
		return attestation.MetadataResult{}, p.err
	}

	return p.result, nil
}

type registrationCertificateStatusProvider struct {
	result attestation.CertificateStatusResult
	err    error
}

func (p *registrationCertificateStatusProvider) CheckCertificateStatus(context.Context, attestation.CertificateStatusRequest) (attestation.CertificateStatusResult, error) {
	if p.err != nil {
		return attestation.CertificateStatusResult{}, p.err
	}

	return p.result, nil
}

func mustLevel2Registry(t *testing.T) *extension.Registry {
	t.Helper()

	registry, err := extension.NewLevel2Registry()
	if err != nil {
		t.Fatalf("NewLevel2Registry() error = %v", err)
	}

	return registry
}

func mustLevel3Registry(t *testing.T) *extension.Registry {
	t.Helper()

	registry, err := extension.NewLevel3RegistryWithDeprecated()
	if err != nil {
		t.Fatalf("NewLevel3RegistryWithDeprecated() error = %v", err)
	}

	return registry
}
