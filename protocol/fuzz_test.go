package protocol_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/islishude/webauthn/protocol"
)

func FuzzParseAuthenticatorData(f *testing.F) {
	f.Add(make([]byte, protocol.MinAuthenticatorDataLength))
	f.Add(fuzzAuthenticatorData(0x01, nil, nil))
	f.Add(fuzzAuthenticatorData(0x01|0x40, []byte("credential-id"), []byte{0xa0}))
	f.Add(fuzzAuthenticatorData(0x01|0x80, nil, []byte{0xa0}))

	f.Fuzz(func(t *testing.T, data []byte) {
		raw, err := protocol.NewAuthenticatorData(data)
		if err != nil {
			return
		}

		parsed, err := protocol.ParseAuthenticatorData(raw)
		if err != nil {
			return
		}
		if len(parsed.RPIDHash) != protocol.RPIDHashLength {
			t.Fatalf("RPIDHash length = %d, want %d", len(parsed.RPIDHash), protocol.RPIDHashLength)
		}
		if parsed.Flags.HasAttestedCredentialData() && parsed.AttestedCredentialData == nil {
			t.Fatalf("AT flag set without attested credential data")
		}
		if !parsed.Flags.HasExtensionData() && parsed.ExtensionData != nil {
			t.Fatalf("extension data present without ED flag")
		}
	})
}

func FuzzParseCollectedClientData(f *testing.F) {
	challenge := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	f.Add([]byte(`{"type":"webauthn.create","challenge":"` + challenge + `","origin":"https://example.com"}`))
	f.Add([]byte(`{"origin":"https://example.com","challenge":"` + challenge + `","type":"webauthn.get","unknown":true}`))
	f.Add([]byte(`{"type":"webauthn.get","challenge":"` + challenge + `","origin":"https://example.com","tokenBinding":{"status":"supported"}}`))
	f.Add([]byte(`{"type":"webauthn.create"}`))
	f.Add([]byte{0xff, 0xfe, 0xfd})

	f.Fuzz(func(t *testing.T, data []byte) {
		raw, err := protocol.NewClientDataJSON(data)
		if err != nil {
			return
		}

		clientData, err := protocol.ParseCollectedClientData(raw)
		if err != nil {
			return
		}
		if _, err := clientData.ChallengeBytes(); err != nil {
			return
		}
	})
}

func fuzzAuthenticatorData(flags byte, credentialID []byte, suffix []byte) []byte {
	rpIDHash := sha256.Sum256([]byte("example.com"))
	out := append([]byte{}, rpIDHash[:]...)
	out = append(out, flags)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 7)
	out = append(out, counter...)

	if flags&0x40 != 0 {
		out = append(out, make([]byte, protocol.AAGUIDLength)...)
		credentialIDLength := make([]byte, 2)
		binary.BigEndian.PutUint16(credentialIDLength, uint16(len(credentialID))) //nolint:gosec // fixed fuzz seed length.
		out = append(out, credentialIDLength...)
		out = append(out, credentialID...)
	}

	out = append(out, suffix...)
	return out
}
