// Package codec defines narrow WebAuthn codec adapter contracts.
package codec

import (
	"slices"

	"github.com/islishude/webauthn/protocol"
)

// AttestationStatement is the decoded attestation statement map for a format.
type AttestationStatement map[string]any

const (
	// CompoundSubStatementsKey is the normalized key used by decoders for the
	// WebAuthn Level 3 compound attestation statement array.
	CompoundSubStatementsKey = "statements"
)

// CompoundSubStatement is one normalized sub-statement in a compound attestation.
type CompoundSubStatement struct {
	Format    string
	Statement AttestationStatement
}

// ExtensionMap is the decoded authenticator extension output map.
type ExtensionMap map[string]any

// CredentialPublicKey is adapter-owned decoded COSE public-key material.
type CredentialPublicKey struct {
	Algorithm protocol.COSEAlgorithmIdentifier
	Key       any
	raw       []byte
	u2fRaw    []byte
	material  CredentialPublicKeyMaterial
}

// NewCredentialPublicKey stores decoded key material and a defensive copy of
// the raw COSE key bytes.
func NewCredentialPublicKey(algorithm protocol.COSEAlgorithmIdentifier, key any, raw []byte) CredentialPublicKey {
	return NewCredentialPublicKeyWithMaterial(algorithm, key, raw, nil, CredentialPublicKeyMaterial{})
}

// NewCredentialPublicKeyWithU2F stores decoded key material, the raw COSE key
// bytes, and an optional raw U2F public key representation.
func NewCredentialPublicKeyWithU2F(algorithm protocol.COSEAlgorithmIdentifier, key any, raw []byte, u2fRaw []byte) CredentialPublicKey {
	return NewCredentialPublicKeyWithMaterial(algorithm, key, raw, u2fRaw, CredentialPublicKeyMaterial{})
}

// NewCredentialPublicKeyWithMaterial stores decoded key material, raw COSE key
// bytes, an optional raw U2F public key representation, and public key material
// needed by attestation format verifiers.
func NewCredentialPublicKeyWithMaterial(algorithm protocol.COSEAlgorithmIdentifier, key any, raw []byte, u2fRaw []byte, material CredentialPublicKeyMaterial) CredentialPublicKey {
	return CredentialPublicKey{
		Algorithm: algorithm,
		Key:       key,
		raw:       slices.Clone(raw),
		u2fRaw:    slices.Clone(u2fRaw),
		material:  material.clone(),
	}
}

// Raw returns a defensive copy of the source COSE key bytes when available.
func (k CredentialPublicKey) Raw() []byte {
	return slices.Clone(k.raw)
}

// U2FPublicKey returns the raw U2F public key representation 0x04 || x || y
// when the selected codec can derive it from the COSE key.
func (k CredentialPublicKey) U2FPublicKey() []byte {
	return slices.Clone(k.u2fRaw)
}

// PublicKeyMaterial returns codec-derived public key material for attestation
// format binding checks.
func (k CredentialPublicKey) PublicKeyMaterial() CredentialPublicKeyMaterial {
	return k.material.clone()
}

// CredentialPublicKeyMaterial contains codec-derived public key values for
// protocol-specific attestation checks.
type CredentialPublicKeyMaterial struct {
	EC2 *EC2PublicKeyMaterial
	RSA *RSAPublicKeyMaterial
	OKP *OKPPublicKeyMaterial
}

func (m CredentialPublicKeyMaterial) clone() CredentialPublicKeyMaterial {
	var out CredentialPublicKeyMaterial
	if m.EC2 != nil {
		out.EC2 = &EC2PublicKeyMaterial{
			Curve: m.EC2.Curve,
			X:     slices.Clone(m.EC2.X),
			Y:     slices.Clone(m.EC2.Y),
		}
	}
	if m.RSA != nil {
		out.RSA = &RSAPublicKeyMaterial{
			Modulus:  slices.Clone(m.RSA.Modulus),
			Exponent: m.RSA.Exponent,
		}
	}
	if m.OKP != nil {
		out.OKP = &OKPPublicKeyMaterial{
			Curve: m.OKP.Curve,
			X:     slices.Clone(m.OKP.X),
		}
	}

	return out
}

// EC2PublicKeyMaterial contains public coordinates for a COSE EC2 key.
type EC2PublicKeyMaterial struct {
	Curve string
	X     []byte
	Y     []byte
}

const (
	// EC2CurveP256 identifies the NIST P-256 curve.
	EC2CurveP256 = "P-256"
	// EC2CurveP384 identifies the NIST P-384 curve.
	EC2CurveP384 = "P-384"
	// EC2CurveP521 identifies the NIST P-521 curve.
	EC2CurveP521 = "P-521"
)

// RSAPublicKeyMaterial contains public values for a COSE RSA key.
type RSAPublicKeyMaterial struct {
	Modulus  []byte
	Exponent uint32
}

// OKPPublicKeyMaterial contains public values for a COSE OKP key.
type OKPPublicKeyMaterial struct {
	Curve string
	X     []byte
}

const (
	// OKPCurveEd25519 identifies Ed25519.
	OKPCurveEd25519 = "Ed25519"
	// OKPCurveEd448 identifies Ed448.
	OKPCurveEd448 = "Ed448"
)

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
