// Package codec defines narrow WebAuthn codec adapter contracts.
package codec

import (
	"slices"

	"github.com/islishude/webauthn/protocol"
)

// AttestationStatement is the decoded attestation statement map for a format.
type AttestationStatement map[string]any

// ExtensionMap is the decoded authenticator extension output map.
type ExtensionMap map[string]any

// CredentialPublicKey is adapter-owned decoded COSE public-key material.
type CredentialPublicKey struct {
	Algorithm protocol.COSEAlgorithmIdentifier
	Key       any
	raw       []byte
}

// NewCredentialPublicKey stores decoded key material and a defensive copy of
// the raw COSE key bytes.
func NewCredentialPublicKey(algorithm protocol.COSEAlgorithmIdentifier, key any, raw []byte) CredentialPublicKey {
	return CredentialPublicKey{
		Algorithm: algorithm,
		Key:       key,
		raw:       slices.Clone(raw),
	}
}

// Raw returns a defensive copy of the source COSE key bytes when available.
func (k CredentialPublicKey) Raw() []byte {
	return slices.Clone(k.raw)
}

// DecodedAttestationObject is the WebAuthn shape expected after CBOR decoding.
type DecodedAttestationObject struct {
	Format            string
	AuthenticatorData protocol.AuthenticatorData
	Statement         AttestationStatement
	Raw               protocol.AttestationObject
}

// AttestationObjectDecoder decodes a raw CBOR attestation object.
type AttestationObjectDecoder interface {
	DecodeAttestationObject(protocol.AttestationObject) (DecodedAttestationObject, error)
}

// COSEKeyDecoder decodes credential public key bytes into adapter-owned key
// material suitable for crypto verification.
type COSEKeyDecoder interface {
	DecodeCredentialPublicKey([]byte) (CredentialPublicKey, error)
}

// ExtensionMapDecoder decodes authenticator extension output bytes.
type ExtensionMapDecoder interface {
	DecodeExtensionMap([]byte) (ExtensionMap, error)
}

// Decoders groups the codec contracts needed by ceremony verifiers.
type Decoders interface {
	AttestationObjectDecoder
	COSEKeyDecoder
	ExtensionMapDecoder
}
