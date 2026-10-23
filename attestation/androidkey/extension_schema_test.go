package androidkey

import (
	"context"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/islishude/webauthn/attestation"
)

// These schema mutations are independently derived from WebAuthn Level 3
// section 8.4.1 and the Android KeyDescription/AuthorizationList ASN.1 schema.
func TestVerifierRejectsMalformedAndroidKeyDescription(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, []asn1.RawValue) []asn1.RawValue
	}{
		{name: "attestation version is not an integer", mutate: replaceDescriptionField(0, []byte{3})},
		{name: "keymaster version is not an integer", mutate: replaceDescriptionField(2, []byte{4})},
		{name: "unique ID is not an octet string", mutate: replaceDescriptionField(5, 0)},
		{name: "unknown attestation security level", mutate: replaceDescriptionField(1, asn1.Enumerated(3))},
		{name: "unknown keymaster security level", mutate: replaceDescriptionField(3, asn1.Enumerated(3))},
		{name: "negative attestation security level", mutate: replaceDescriptionField(1, asn1.Enumerated(-1))},
		{name: "duplicate software purpose", mutate: duplicateAuthorizationField(6, androidTagPurpose)},
		{name: "duplicate hardware origin", mutate: duplicateAuthorizationField(7, androidTagOrigin)},
		{name: "untagged authorization", mutate: appendAuthorizationField(6, func(t *testing.T) asn1.RawValue {
			return rawValue(t, mustMarshal(t, 1))
		})},
		{name: "implicit authorization", mutate: appendAuthorizationField(6, func(t *testing.T) asn1.RawValue {
			return rawValue(t, mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte{3}}))
		})},
		{name: "empty explicit authorization", mutate: appendAuthorizationField(6, func(t *testing.T) asn1.RawValue {
			return explicitValue(t, 2, nil)
		})},
		{name: "multiple explicit authorization values", mutate: appendAuthorizationField(6, func(t *testing.T) asn1.RawValue {
			return explicitValue(t, 2, append(mustMarshal(t, 3), mustMarshal(t, 3)...))
		})},
		{name: "truncated explicit authorization value", mutate: appendAuthorizationField(6, func(t *testing.T) asn1.RawValue {
			return explicitValue(t, 2, []byte{0x02, 0x01})
		})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := newEC2Fixture(t, extensionOptions{descriptionFields: tt.mutate})
			_, err := New(signatureVerifier{t: t}).VerifyAttestation(context.Background(), attestation.VerificationRequest{
				Format:              "android-key",
				AuthenticatorData:   fixture.authenticatorData,
				ClientDataHash:      fixture.clientDataHash,
				Statement:           fixture.statement,
				CredentialPublicKey: fixture.credentialPublicKey,
			})
			if !errors.Is(err, ErrInvalidExtension) {
				t.Fatalf("VerifyAttestation() error = %v, want ErrInvalidExtension", err)
			}
		})
	}
}

func TestVerifierAcceptsAndroidKeyDescriptionOptionalData(t *testing.T) {
	t.Parallel()

	for _, level := range []asn1.Enumerated{androidSecurityLevelSoftware, androidSecurityLevelTEE, androidSecurityLevelStrongBox} {
		fixture := newEC2Fixture(t, extensionOptions{descriptionFields: func(t *testing.T, fields []asn1.RawValue) []asn1.RawValue {
			fields = replaceDescriptionField(1, level)(t, fields)
			fields = replaceDescriptionField(3, level)(t, fields)
			fields = replaceDescriptionField(5, []byte("unique-id"))(t, fields)
			// Algorithm is a schema-defined explicit field not used by the WebAuthn
			// authorization checks; its presence does not change those checks.
			return appendAuthorizationField(6, func(t *testing.T) asn1.RawValue {
				return explicitValue(t, 2, mustMarshal(t, 3))
			})(t, fields)
		}})
		_, err := New(signatureVerifier{t: t}).VerifyAttestation(context.Background(), attestation.VerificationRequest{
			Format:              "android-key",
			AuthenticatorData:   fixture.authenticatorData,
			ClientDataHash:      fixture.clientDataHash,
			Statement:           fixture.statement,
			CredentialPublicKey: fixture.credentialPublicKey,
		})
		if err != nil {
			t.Fatalf("VerifyAttestation() security level %d error = %v", level, err)
		}
	}
}

func replaceDescriptionField(index int, value any) func(*testing.T, []asn1.RawValue) []asn1.RawValue {
	return func(t *testing.T, fields []asn1.RawValue) []asn1.RawValue {
		t.Helper()
		fields[index] = rawValue(t, mustMarshal(t, value))
		return fields
	}
}

func duplicateAuthorizationField(index int, tag int) func(*testing.T, []asn1.RawValue) []asn1.RawValue {
	return func(t *testing.T, fields []asn1.RawValue) []asn1.RawValue {
		t.Helper()
		items := authorizationItems(t, fields[index])
		for _, item := range items {
			if item.Tag == tag {
				items = append(items, item)
				fields[index] = rawValue(t, mustMarshal(t, items))
				return fields
			}
		}
		t.Fatalf("authorization tag %d missing from fixture", tag)
		return nil
	}
}

func appendAuthorizationField(index int, value func(*testing.T) asn1.RawValue) func(*testing.T, []asn1.RawValue) []asn1.RawValue {
	return func(t *testing.T, fields []asn1.RawValue) []asn1.RawValue {
		t.Helper()
		items := append(authorizationItems(t, fields[index]), value(t))
		fields[index] = rawValue(t, mustMarshal(t, items))
		return fields
	}
}

func authorizationItems(t *testing.T, raw asn1.RawValue) []asn1.RawValue {
	t.Helper()
	var items []asn1.RawValue
	rest, err := asn1.Unmarshal(raw.FullBytes, &items)
	if err != nil || len(rest) != 0 {
		t.Fatalf("Unmarshal() error = %v, rest = %x", err, rest)
	}
	return items
}
