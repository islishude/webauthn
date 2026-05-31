package webauthn_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/codec"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

func TestAuthenticationUsernameFirst(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t, true)

	result, err := webauthn.FinishAuthentication(context.Background(), fixture.finishOptions())
	if err != nil {
		t.Fatalf("FinishAuthentication() error = %v", err)
	}
	if !bytes.Equal(result.AuthenticatedAs.Bytes(), fixture.userHandle.Bytes()) {
		t.Fatalf("AuthenticatedAs = %x, want %x", result.AuthenticatedAs.Bytes(), fixture.userHandle.Bytes())
	}
	if result.Counter.Status != webauthn.CounterStatusIncremented || result.Update.SignCount != 8 {
		t.Fatalf("counter = %+v update = %+v", result.Counter, result.Update)
	}
}

func TestAuthenticationDiscoverable(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t, false)

	result, err := webauthn.FinishAuthentication(context.Background(), fixture.finishOptions())
	if err != nil {
		t.Fatalf("FinishAuthentication() error = %v", err)
	}
	if !bytes.Equal(result.AuthenticatedAs.Bytes(), fixture.userHandle.Bytes()) {
		t.Fatalf("AuthenticatedAs = %x, want %x", result.AuthenticatedAs.Bytes(), fixture.userHandle.Bytes())
	}
}

func TestAuthenticationStartGeneratesDefaultChallenge(t *testing.T) {
	t.Parallel()

	result, err := webauthn.StartAuthentication(context.Background(), webauthn.AuthenticationStartOptions{
		RPID:             "example.com",
		AllowedOrigins:   []string{"https://example.com"},
		UserVerification: protocol.UserVerificationPreferred,
	})
	if err != nil {
		t.Fatalf("StartAuthentication() error = %v", err)
	}
	if result.State.Challenge.Len() != protocol.RecommendedChallengeLength {
		t.Fatalf("challenge length = %d, want %d", result.State.Challenge.Len(), protocol.RecommendedChallengeLength)
	}
}

func TestAuthenticationRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*testing.T, *authenticationFixture, *webauthn.AuthenticationFinishOptions)
		wantErr error
	}{
		{
			name: "missing discoverable user handle",
			mutate: func(t *testing.T, _ *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.Response.UserHandle = protocol.UserHandle{}
			},
			wantErr: webauthn.ErrUserHandleRequired,
		},
		{
			name: "username first user handle mismatch",
			mutate: func(t *testing.T, _ *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.State.ExpectedUserHandle = options.Credential.UserHandle
				options.Response.UserHandle = mustUserHandle(t, []byte("other-user"))
			},
			wantErr: webauthn.ErrCredentialOwnershipMismatch,
		},
		{
			name: "allow credentials mismatch",
			mutate: func(t *testing.T, _ *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.State.AllowCredentials = []protocol.CredentialDescriptor{{
					Type: protocol.CredentialTypePublicKey,
					ID:   mustCredentialID(t, []byte("other-credential")),
				}}
			},
			wantErr: webauthn.ErrCredentialNotAllowed,
		},
		{
			name: "challenge mismatch",
			mutate: func(t *testing.T, _ *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.Response.ClientDataJSON = mustClientDataJSON(t, authenticationClientData(t, bytes.Repeat([]byte{0x09}, protocol.RecommendedChallengeLength), "https://example.com", false))
			},
			wantErr: webauthn.ErrChallengeMismatch,
		},
		{
			name: "origin mismatch",
			mutate: func(t *testing.T, f *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.Response.ClientDataJSON = mustClientDataJSON(t, authenticationClientData(t, f.challenge.Bytes(), "https://evil.example", false))
			},
			wantErr: webauthn.ErrOriginMismatch,
		},
		{
			name: "rp id hash mismatch",
			mutate: func(t *testing.T, _ *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.Response.AuthenticatorData = mustAuthenticatorData(t, authenticationAuthenticatorData(t, "other.example", authenticationFlagUP, 8, nil))
			},
			wantErr: webauthn.ErrRPIDHashMismatch,
		},
		{
			name: "missing user presence",
			mutate: func(t *testing.T, _ *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.Response.AuthenticatorData = mustAuthenticatorData(t, authenticationAuthenticatorData(t, "example.com", 0, 8, nil))
			},
			wantErr: webauthn.ErrUserPresenceRequired,
		},
		{
			name: "missing required user verification",
			mutate: func(t *testing.T, _ *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.State.RequestedUserVerification = protocol.UserVerificationRequired
			},
			wantErr: webauthn.ErrUserVerificationRequired,
		},
		{
			name: "invalid signature",
			mutate: func(t *testing.T, _ *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.SignatureVerifier = failingSignatureVerifier{}
			},
			wantErr: webauthn.ErrInvalidSignature,
		},
		{
			name: "unsupported algorithm",
			mutate: func(t *testing.T, _ *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.AlgorithmPolicy = algorithmPolicyFunc(func(protocol.COSEAlgorithmIdentifier) bool { return false })
			},
			wantErr: webauthn.ErrUnsupportedAlgorithm,
		},
		{
			name: "counter rollback rejected",
			mutate: func(t *testing.T, _ *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.Response.AuthenticatorData = mustAuthenticatorData(t, authenticationAuthenticatorData(t, "example.com", authenticationFlagUP, 7, nil))
				options.CounterPolicy.RejectCloneRisk = true
			},
			wantErr: webauthn.ErrCloneRisk,
		},
		{
			name: "unsolicited extension rejected",
			mutate: func(t *testing.T, _ *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.Response.ClientExtensionResults = map[string]any{"credProps": true}
				options.ExtensionPolicy.RejectUnrequested = true
			},
			wantErr: webauthn.ErrExtensionPolicy,
		},
		{
			name: "unsolicited authenticator extension rejected",
			mutate: func(t *testing.T, _ *authenticationFixture, options *webauthn.AuthenticationFinishOptions) {
				t.Helper()
				options.Response.AuthenticatorData = mustAuthenticatorData(t, authenticationAuthenticatorData(t, "example.com", authenticationFlagUP|authenticationFlagED, 8, map[string]any{"credProps": true}))
				options.Decoders = codeccbor.MustNewDecoder()
				options.ExtensionPolicy.RejectUnrequested = true
			},
			wantErr: webauthn.ErrExtensionPolicy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fixture := newAuthenticationFixture(t, false)
			options := fixture.finishOptions()
			tt.mutate(t, fixture, &options)

			_, err := webauthn.FinishAuthentication(context.Background(), options)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("FinishAuthentication() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthenticationAppIDHashAcceptedWithPolicyAndOutput(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t, true)
	options := fixture.finishOptions()
	appID := "https://legacy.example/appid"
	options.State.RequestedExtensions = protocol.ExtensionInputs{"appid": appID}
	options.ExtensionPolicy.AppID = appID
	options.Response.ClientExtensionResults = map[string]any{"appid": true}
	options.Response.AuthenticatorData = mustAuthenticatorData(t, authenticationAuthenticatorData(t, appID, authenticationFlagUP, 8, nil))

	if _, err := webauthn.FinishAuthentication(context.Background(), options); err != nil {
		t.Fatalf("FinishAuthentication() error = %v", err)
	}
}

func TestAuthenticationCounterPolicy(t *testing.T) {
	t.Parallel()

	t.Run("zero zero", func(t *testing.T) {
		t.Parallel()

		fixture := newAuthenticationFixture(t, true)
		options := fixture.finishOptions()
		options.Credential.SignCount = 0
		options.Response.AuthenticatorData = mustAuthenticatorData(t, authenticationAuthenticatorData(t, "example.com", authenticationFlagUP, 0, nil))

		result, err := webauthn.FinishAuthentication(context.Background(), options)
		if err != nil {
			t.Fatalf("FinishAuthentication() error = %v", err)
		}
		if result.Counter.Status != webauthn.CounterStatusUnsupported || result.Counter.CloneRisk {
			t.Fatalf("counter = %+v, want unsupported without clone risk", result.Counter)
		}
	})

	t.Run("rollback warning", func(t *testing.T) {
		t.Parallel()

		fixture := newAuthenticationFixture(t, true)
		options := fixture.finishOptions()
		options.Response.AuthenticatorData = mustAuthenticatorData(t, authenticationAuthenticatorData(t, "example.com", authenticationFlagUP, 7, nil))

		result, err := webauthn.FinishAuthentication(context.Background(), options)
		if err != nil {
			t.Fatalf("FinishAuthentication() error = %v", err)
		}
		if !result.Counter.CloneRisk || len(result.Warnings) == 0 {
			t.Fatalf("counter = %+v warnings = %v, want clone risk warning", result.Counter, result.Warnings)
		}
	})
}

func TestAuthenticationExtensionPolicyAllowsAbsentAndIgnoredUnrequestedExtensions(t *testing.T) {
	t.Parallel()

	requested := newAuthenticationFixture(t, true)
	requested.start.State.RequestedExtensions = protocol.ExtensionInputs{"credProps": true}
	if _, err := webauthn.FinishAuthentication(context.Background(), requested.finishOptions()); err != nil {
		t.Fatalf("FinishAuthentication() with absent requested extension error = %v", err)
	}

	ignored := newAuthenticationFixture(t, true)
	options := ignored.finishOptions()
	options.Response.ClientExtensionResults = map[string]any{"credProps": true}
	if _, err := webauthn.FinishAuthentication(context.Background(), options); err != nil {
		t.Fatalf("FinishAuthentication() with ignored unrequested extension error = %v", err)
	}
}

type authenticationFixture struct {
	challenge    protocol.Challenge
	credentialID []byte
	userHandle   protocol.UserHandle
	start        webauthn.AuthenticationStartResult
	response     webauthn.AuthenticationResponse
	credential   webauthn.CredentialRecord
}

func newAuthenticationFixture(t *testing.T, usernameFirst bool) *authenticationFixture {
	t.Helper()

	challenge, err := protocol.NewChallenge(bytes.Repeat([]byte{0x03}, protocol.RecommendedChallengeLength))
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}
	credentialID := []byte("credential-id")
	userHandle := mustUserHandle(t, []byte("user-1"))

	startOptions := webauthn.AuthenticationStartOptions{
		RPID:             "example.com",
		AllowedOrigins:   []string{"https://example.com"},
		Challenge:        challenge,
		UserVerification: protocol.UserVerificationPreferred,
	}
	if usernameFirst {
		startOptions.ExpectedUserHandle = userHandle
		startOptions.AllowCredentials = []protocol.CredentialDescriptor{{
			Type: protocol.CredentialTypePublicKey,
			ID:   mustCredentialID(t, credentialID),
		}}
	}
	start, err := webauthn.StartAuthentication(context.Background(), startOptions)
	if err != nil {
		t.Fatalf("StartAuthentication() error = %v", err)
	}

	credential := webauthn.CredentialRecord{
		ID:         mustCredentialID(t, credentialID),
		PublicKey:  codec.NewCredentialPublicKey(-7, "public-key", []byte("raw-key")),
		UserHandle: userHandle,
		RPID:       "example.com",
		SignCount:  7,
	}
	response := webauthn.AuthenticationResponse{
		Type:              protocol.CredentialTypePublicKey,
		RawID:             mustRawID(t, credentialID),
		ClientDataJSON:    mustClientDataJSON(t, authenticationClientData(t, challenge.Bytes(), "https://example.com", false)),
		AuthenticatorData: mustAuthenticatorData(t, authenticationAuthenticatorData(t, "example.com", authenticationFlagUP, 8, nil)),
		Signature:         mustSignature(t, []byte("signature")),
		UserHandle:        userHandle,
	}
	if usernameFirst {
		response.UserHandle = protocol.UserHandle{}
	}

	return &authenticationFixture{
		challenge:    challenge,
		credentialID: credentialID,
		userHandle:   userHandle,
		start:        start,
		response:     response,
		credential:   credential,
	}
}

func (f *authenticationFixture) finishOptions() webauthn.AuthenticationFinishOptions {
	return webauthn.AuthenticationFinishOptions{
		State:             f.start.State,
		Response:          f.response,
		Credential:        f.credential,
		SignatureVerifier: acceptingSignatureVerifier{},
		AlgorithmPolicy:   algorithmPolicyFunc(func(algorithm protocol.COSEAlgorithmIdentifier) bool { return algorithm == -7 }),
	}
}

const (
	authenticationFlagUP = byte(0x01)
	authenticationFlagUV = byte(0x04)
	authenticationFlagED = byte(0x80)
)

func authenticationClientData(t *testing.T, challenge []byte, origin string, crossOrigin bool) []byte {
	t.Helper()

	if crossOrigin {
		return []byte(`{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `","origin":"` + origin + `","crossOrigin":true}`)
	}

	return []byte(`{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `","origin":"` + origin + `"}`)
}

func authenticationAuthenticatorData(t *testing.T, rpID string, flags byte, counter uint32, extensions map[string]any) []byte {
	t.Helper()

	rpIDHash := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, rpIDHash[:]...)
	out = append(out, flags)
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, counter)
	out = append(out, counterBytes...)
	if flags&authenticationFlagED != 0 {
		out = append(out, mustCBOR(t, extensions)...)
	}

	return out
}

func mustAuthenticatorData(t *testing.T, value []byte) protocol.AuthenticatorData {
	t.Helper()

	authData, err := protocol.NewAuthenticatorData(value)
	if err != nil {
		t.Fatalf("NewAuthenticatorData() error = %v", err)
	}

	return authData
}

func mustCredentialID(t *testing.T, value []byte) protocol.CredentialID {
	t.Helper()

	credentialID, err := protocol.NewCredentialID(value)
	if err != nil {
		t.Fatalf("NewCredentialID() error = %v", err)
	}

	return credentialID
}

func mustUserHandle(t *testing.T, value []byte) protocol.UserHandle {
	t.Helper()

	userHandle, err := protocol.NewUserHandle(value)
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}

	return userHandle
}

func mustSignature(t *testing.T, value []byte) protocol.Signature {
	t.Helper()

	signature, err := protocol.NewSignature(value)
	if err != nil {
		t.Fatalf("NewSignature() error = %v", err)
	}

	return signature
}

type acceptingSignatureVerifier struct{}

func (acceptingSignatureVerifier) VerifySignature(context.Context, webcrypto.SignatureInput) error {
	return nil
}

type failingSignatureVerifier struct{}

func (failingSignatureVerifier) VerifySignature(context.Context, webcrypto.SignatureInput) error {
	return errors.New("signature rejected")
}

type algorithmPolicyFunc func(protocol.COSEAlgorithmIdentifier) bool

func (f algorithmPolicyFunc) AcceptsAlgorithm(algorithm protocol.COSEAlgorithmIdentifier) bool {
	return f(algorithm)
}
