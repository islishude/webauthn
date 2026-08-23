package storagejson_test

import (
	"bytes"
	"crypto/elliptic"
	stdjson "encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	fxcbor "github.com/fxamacker/cbor/v2"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
	storagejson "github.com/islishude/webauthn/storage/json"
)

func TestRegistrationStateRoundTrip(t *testing.T) {
	t.Parallel()

	state := registrationStateFixture(t)
	encoded, err := storagejson.MarshalRegistrationState(state)
	if err != nil {
		t.Fatalf("MarshalRegistrationState() error = %v", err)
	}
	decoded, err := storagejson.UnmarshalRegistrationState(encoded)
	if err != nil {
		t.Fatalf("UnmarshalRegistrationState() error = %v", err)
	}
	if !decoded.Challenge.Equal(state.Challenge) || decoded.RPID != state.RPID || !decoded.UserHandle.Equal(state.UserHandle) || !decoded.ExpiresAt.Equal(state.ExpiresAt) {
		t.Fatalf("decoded state = %+v", decoded)
	}
	assertExtensionTree(t, decoded.RequestedExtensions["future"])
}

func TestAuthenticationStateRoundTrip(t *testing.T) {
	t.Parallel()

	state := authenticationStateFixture(t)
	encoded, err := storagejson.MarshalAuthenticationState(state)
	if err != nil {
		t.Fatalf("MarshalAuthenticationState() error = %v", err)
	}
	decoded, err := storagejson.UnmarshalAuthenticationState(encoded)
	if err != nil {
		t.Fatalf("UnmarshalAuthenticationState() error = %v", err)
	}
	if !decoded.Challenge.Equal(state.Challenge) || decoded.RPID != state.RPID || !decoded.ExpectedUserHandle.Equal(state.ExpectedUserHandle) || len(decoded.AllowCredentials) != 1 || !decoded.AllowCredentials[0].ID.Equal(state.AllowCredentials[0].ID) {
		t.Fatalf("decoded state = %+v", decoded)
	}
	assertExtensionTree(t, decoded.RequestedExtensions["future"])
	if _, err := (extension.PRFHandler{}).ValidateInput(extension.InputRequest{Operation: extension.OperationAuthentication, ID: extension.IDPRF, Input: decoded.RequestedExtensions[extension.IDPRF]}); err != nil {
		t.Fatalf("restored PRF input validation error = %v", err)
	}
}

func TestCredentialRecordRoundTrip(t *testing.T) {
	t.Parallel()

	decoder := codeccbor.MustNewDecoder()
	record := credentialRecordFixture(t, decoder)
	encoded, err := storagejson.MarshalCredentialRecord(record)
	if err != nil {
		t.Fatalf("MarshalCredentialRecord() error = %v", err)
	}
	decoded, err := storagejson.UnmarshalCredentialRecord(encoded, decoder)
	if err != nil {
		t.Fatalf("UnmarshalCredentialRecord() error = %v", err)
	}
	if !decoded.ID.Equal(record.ID) || !decoded.UserHandle.Equal(record.UserHandle) || decoded.RPID != record.RPID || decoded.SignCount != record.SignCount || !decoded.BackupEligible || !decoded.BackupState || !decoded.UVInitialized || !bytes.Equal(decoded.PublicKey.Raw(), record.PublicKey.Raw()) || !reflect.DeepEqual(decoded.PublicKey.PublicKeyMaterial(), record.PublicKey.PublicKeyMaterial()) {
		t.Fatalf("decoded credential = %+v", decoded)
	}
}

func TestStorageJSONRejectsInvalidEnvelopes(t *testing.T) {
	t.Parallel()

	registration, err := storagejson.MarshalRegistrationState(registrationStateFixture(t))
	if err != nil {
		t.Fatalf("MarshalRegistrationState() error = %v", err)
	}
	credential, err := storagejson.MarshalCredentialRecord(credentialRecordFixture(t, codeccbor.MustNewDecoder()))
	if err != nil {
		t.Fatalf("MarshalCredentialRecord() error = %v", err)
	}

	tests := []struct {
		name    string
		data    []byte
		decode  func([]byte) error
		wantErr error
	}{
		{
			name:    "unknown version",
			data:    bytes.Replace(registration, []byte(`"version":1`), []byte(`"version":2`), 1),
			decode:  decodeRegistration,
			wantErr: storagejson.ErrUnsupportedVersion,
		},
		{
			name:    "trailing data",
			data:    append(append([]byte{}, registration...), []byte(` {}`)...),
			decode:  decodeRegistration,
			wantErr: storagejson.ErrInvalidEnvelope,
		},
		{
			name:    "unknown field",
			data:    bytes.Replace(registration, []byte(`"kind":`), []byte(`"unknown":true,"kind":`), 1),
			decode:  decodeRegistration,
			wantErr: storagejson.ErrInvalidEnvelope,
		},
		{
			name:    "invalid challenge base64url",
			data:    replaceNestedString(t, registration, "registrationState", "challenge", "%%%"),
			decode:  decodeRegistration,
			wantErr: storagejson.ErrInvalidEnvelope,
		},
		{
			name:    "damaged cose key",
			data:    replaceNestedString(t, credential, "credentialRecord", "publicKeyCose", "oA"),
			decode:  decodeCredential,
			wantErr: storagejson.ErrInvalidEnvelope,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.decode(tt.data); !errors.Is(err, tt.wantErr) {
				t.Fatalf("decode error = %v, want %v", err, tt.wantErr)
			}
		})
	}

	if err := decodeRegistration(bytes.Repeat([]byte{' '}, storagejson.MaxEnvelopeBytes+1)); !errors.Is(err, storagejson.ErrInvalidEnvelope) {
		t.Fatalf("oversized envelope error = %v", err)
	}
	if _, err := storagejson.UnmarshalCredentialRecord(credential, nil); !errors.Is(err, storagejson.ErrInvalidEnvelope) {
		t.Fatalf("nil decoder error = %v", err)
	}
}

func TestStorageJSONRejectsInvalidStateAndUnsupportedExtensionValue(t *testing.T) {
	t.Parallel()

	state := registrationStateFixture(t)
	state.RequestedExtensions["unsupported"] = make(chan struct{})
	if _, err := storagejson.MarshalRegistrationState(state); !errors.Is(err, storagejson.ErrUnsupportedExtensionValue) {
		t.Fatalf("unsupported extension error = %v", err)
	}

	record := credentialRecordFixture(t, codeccbor.MustNewDecoder())
	record.BackupEligible = false
	if _, err := storagejson.MarshalCredentialRecord(record); !errors.Is(err, storagejson.ErrInvalidEnvelope) {
		t.Fatalf("invalid backup state error = %v", err)
	}
}

func FuzzUnmarshalRegistrationState(f *testing.F) {
	seed, err := storagejson.MarshalRegistrationState(registrationStateFixture(f))
	if err != nil {
		f.Fatalf("MarshalRegistrationState() error = %v", err)
	}
	f.Add(seed)
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = storagejson.UnmarshalRegistrationState(data)
	})
}

func FuzzUnmarshalAuthenticationState(f *testing.F) {
	seed, err := storagejson.MarshalAuthenticationState(authenticationStateFixture(f))
	if err != nil {
		f.Fatalf("MarshalAuthenticationState() error = %v", err)
	}
	f.Add(seed)
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = storagejson.UnmarshalAuthenticationState(data)
	})
}

func FuzzUnmarshalCredentialRecord(f *testing.F) {
	decoder := codeccbor.MustNewDecoder()
	seed, err := storagejson.MarshalCredentialRecord(credentialRecordFixture(f, decoder))
	if err != nil {
		f.Fatalf("MarshalCredentialRecord() error = %v", err)
	}
	f.Add(seed)
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = storagejson.UnmarshalCredentialRecord(data, decoder)
	})
}

func registrationStateFixture(t testing.TB) webauthn.RegistrationState {
	t.Helper()
	return webauthn.RegistrationState{
		Challenge:                 mustChallenge(t),
		RPID:                      "example.com",
		OriginPolicy:              webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}, AllowedTopOrigins: []string{"https://top.example"}},
		UserHandle:                mustUserHandle(t),
		RequestedUserVerification: protocol.UserVerificationRequired,
		RequestedExtensions:       extensionTree(),
		AllowedAlgorithms:         []protocol.COSEAlgorithmIdentifier{protocol.AlgorithmES256},
		Attestation:               protocol.AttestationNone,
		ExpiresAt:                 time.Date(2026, 8, 23, 12, 5, 0, 123, time.UTC),
	}
}

func authenticationStateFixture(t testing.TB) webauthn.AuthenticationState {
	t.Helper()
	credentialID, err := protocol.NewCredentialID([]byte("credential-id"))
	if err != nil {
		t.Fatalf("NewCredentialID() error = %v", err)
	}
	return webauthn.AuthenticationState{
		Challenge:                 mustChallenge(t),
		RPID:                      "example.com",
		OriginPolicy:              webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}},
		RequestedUserVerification: protocol.UserVerificationPreferred,
		RequestedExtensions:       authenticationExtensionTree(),
		AllowCredentials: []protocol.CredentialDescriptor{{
			Type:       protocol.CredentialTypePublicKey,
			ID:         credentialID,
			Transports: []protocol.AuthenticatorTransport{protocol.TransportInternal},
		}},
		ExpectedUserHandle: mustUserHandle(t),
		ExpiresAt:          time.Date(2026, 8, 23, 12, 5, 0, 123, time.UTC),
	}
}

func credentialRecordFixture(t testing.TB, decoder *codeccbor.Decoder) webauthn.CredentialRecord {
	t.Helper()
	credentialID, err := protocol.NewCredentialID([]byte("credential-id"))
	if err != nil {
		t.Fatalf("NewCredentialID() error = %v", err)
	}
	publicKey, err := decoder.DecodeCredentialPublicKey(validCOSEKey(t))
	if err != nil {
		t.Fatalf("DecodeCredentialPublicKey() error = %v", err)
	}
	var aaguid protocol.AAGUID
	copy(aaguid[:], []byte("0123456789abcdef"))
	return webauthn.CredentialRecord{
		ID:                      credentialID,
		PublicKey:               publicKey,
		UserHandle:              mustUserHandle(t),
		RPID:                    "example.com",
		AAGUID:                  aaguid,
		SignCount:               7,
		Transports:              []protocol.AuthenticatorTransport{protocol.TransportInternal, protocol.TransportHybrid},
		BackupEligible:          true,
		BackupState:             true,
		UVInitialized:           true,
		AuthenticatorAttachment: protocol.AuthenticatorAttachmentPlatform,
		AttestationType:         attestation.TypeNone,
	}
}

func extensionTree() protocol.ExtensionInputs {
	return protocol.ExtensionInputs{
		"future": map[string]any{
			"bytes":       []byte{0x00, 0xff},
			"signed":      int(-2),
			"unsigned":    uint64(9),
			"array":       []any{true, "value"},
			"emptyArray":  []any{},
			"emptyObject": map[string]any{},
		},
		"largeBlob": extension.LargeBlobInput{Support: extension.LargeBlobSupportPreferred},
	}
}

func authenticationExtensionTree() protocol.ExtensionInputs {
	out := extensionTree()
	delete(out, extension.IDLargeBlob)
	out[extension.IDPRF] = extension.PRFInput{Eval: &extension.PRFValues{First: []byte("salt")}}
	return out
}

func assertExtensionTree(t *testing.T, value any) {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("extension value type = %T", value)
	}
	if !bytes.Equal(object["bytes"].([]byte), []byte{0x00, 0xff}) || object["signed"] != int64(-2) || object["unsigned"] != uint64(9) {
		t.Fatalf("extension object = %#v", object)
	}
	if len(object["emptyArray"].([]any)) != 0 || len(object["emptyObject"].(map[string]any)) != 0 {
		t.Fatalf("empty extension containers = %#v", object)
	}
}

func mustChallenge(t testing.TB) protocol.Challenge {
	t.Helper()
	challenge, err := protocol.NewChallenge(bytes.Repeat([]byte{0x01}, protocol.RecommendedChallengeLength))
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}
	return challenge
}

func mustUserHandle(t testing.TB) protocol.UserHandle {
	t.Helper()
	handle, err := protocol.NewUserHandle([]byte("user-handle"))
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}
	return handle
}

func validCOSEKey(t testing.TB) []byte {
	t.Helper()
	curve := elliptic.P256().Params()
	mode, err := fxcbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("CTAP2 EncMode() error = %v", err)
	}
	encoded, err := mode.Marshal(map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: curve.Gx.FillBytes(make([]byte, 32)),
		-3: curve.Gy.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("cbor.Marshal() error = %v", err)
	}
	return encoded
}

func replaceNestedString(t *testing.T, data []byte, object string, field string, value string) []byte {
	t.Helper()
	var decoded map[string]any
	if err := stdjson.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	nested := decoded[object].(map[string]any)
	nested[field] = value
	out, err := stdjson.Marshal(decoded)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return out
}

func decodeRegistration(data []byte) error {
	_, err := storagejson.UnmarshalRegistrationState(data)
	return err
}

func decodeCredential(data []byte) error {
	_, err := storagejson.UnmarshalCredentialRecord(data, codeccbor.MustNewDecoder())
	return err
}
