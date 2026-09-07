// Package testceremony provides independently generated ceremony inputs for
// example tests. It uses standard-library signing and the project's CBOR adapter.
// It must never be used to accept assertions in an application.
package testceremony

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	fxcbor "github.com/fxamacker/cbor/v2"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/browser"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/protocol"
)

// Fixture owns an ephemeral test key, never persisted or logged.
type Fixture struct {
	private ed25519.PrivateKey
	Record  webauthn.CredentialRecord
}

// New generates a credential for the provided account and RP.
func New(t *testing.T, rp string, user protocol.UserHandle) Fixture {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := protocol.NewCredentialID(pub)
	if err != nil {
		t.Fatal(err)
	}
	raw := encodeCBOR(t, map[int]any{1: 1, 3: -8, -1: 6, -2: []byte(pub)})
	key, err := codeccbor.MustNewDecoder().DecodeCredentialPublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return Fixture{private: private, Record: webauthn.CredentialRecord{Type: protocol.CredentialTypePublicKey, ID: id, PublicKey: key, UserHandle: user, RPID: rp, AttestationType: attestation.TypeNone, UVInitialized: true}}
}

func encodeCBOR(t *testing.T, v any) []byte {
	t.Helper()
	mode, err := fxcbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mode.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func encodeJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func authData(rp string, flags byte) []byte {
	sum := sha256.Sum256([]byte(rp))
	return append(sum[:], flags, 0, 0, 0, 0)
}
func clientData(t *testing.T, kind string, challenge protocol.Challenge, origin string) []byte {
	return encodeJSON(t, map[string]any{"type": kind, "challenge": b64(challenge.Bytes()), "origin": origin})
}

// RegistrationJSON creates a UV/UP registration response using none attestation.
func (f Fixture) RegistrationJSON(t *testing.T, state webauthn.RegistrationState) []byte {
	t.Helper()
	auth := authData(state.RPID, 0x45)
	auth = append(auth, make([]byte, 16)...)
	length := f.Record.ID.Len()
	if length < 1 || length > protocol.MaxCredentialIDLength {
		t.Fatal("invalid fixture credential length")
		return nil
	}
	auth = binary.BigEndian.AppendUint16(auth, uint16(length))
	auth = f.Record.ID.AppendTo(auth)
	auth = append(auth, f.Record.PublicKey.Raw()...)
	object := encodeCBOR(t, map[string]any{"fmt": "none", "authData": auth, "attStmt": map[string]any{}})
	return encodeJSON(t, browser.RegistrationCredentialJSON{ID: b64(f.Record.ID.Bytes()), RawID: b64(f.Record.ID.Bytes()), Type: protocol.CredentialTypePublicKey, ClientExtensionResults: map[string]any{}, Response: browser.AttestationResponseJSON{ClientDataJSON: b64(clientData(t, "webauthn.create", state.Challenge, state.OriginPolicy.AllowedOrigins[0])), AuthenticatorData: b64(auth), Transports: []protocol.AuthenticatorTransport{}, PublicKeyAlgorithm: protocol.AlgorithmEdDSA, AttestationObject: b64(object)}})
}

// AuthenticationJSON includes an unknown signed authenticator extension. The
// default policy accepts it only after decoding and signature verification.
func (f Fixture) AuthenticationJSON(t *testing.T, state webauthn.AuthenticationState) []byte {
	t.Helper()
	auth := append(authData(state.RPID, 0x85), encodeCBOR(t, map[string]any{"test-extension": true})...)
	client := clientData(t, "webauthn.get", state.Challenge, state.OriginPolicy.AllowedOrigins[0])
	hash := sha256.Sum256(client)
	signed := append(append([]byte{}, auth...), hash[:]...)
	user := b64(f.Record.UserHandle.Bytes())
	return encodeJSON(t, browser.AuthenticationCredentialJSON{ID: b64(f.Record.ID.Bytes()), RawID: b64(f.Record.ID.Bytes()), Type: protocol.CredentialTypePublicKey, ClientExtensionResults: map[string]any{}, Response: browser.AssertionResponseJSON{ClientDataJSON: b64(client), AuthenticatorData: b64(auth), Signature: b64(ed25519.Sign(f.private, signed)), UserHandle: &user}})
}
