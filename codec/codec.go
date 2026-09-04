// Package codec defines narrow WebAuthn codec adapter contracts.
package codec

import (
	"errors"
	"math/bits"
	"slices"

	"github.com/islishude/webauthn/protocol"
)

const (
	// MaxCredentialPublicKeyBytes bounds raw COSE credential keys accepted from
	// caller-owned storage and codec adapters.
	MaxCredentialPublicKeyBytes = 64 << 10
)

var (
	// ErrInvalidCredentialPublicKey reports an incomplete or internally
	// inconsistent decoded credential public key.
	ErrInvalidCredentialPublicKey = errors.New("invalid credential public key")
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
	raw       []byte
	material  CredentialPublicKeyMaterial
}

// NewCredentialPublicKey stores a defensive copy of the raw COSE key and typed
// public key material. Adapter-specific decoded key handles are deliberately not
// retained in the public API.
func NewCredentialPublicKey(algorithm protocol.COSEAlgorithmIdentifier, raw []byte, material CredentialPublicKeyMaterial) CredentialPublicKey {
	return CredentialPublicKey{
		Algorithm: algorithm,
		raw:       slices.Clone(raw),
		material:  material.clone(),
	}
}

// NewCredentialPublicKeyWithU2F stores a raw U2F uncompressed P-256 key as
// typed EC2 material. Malformed input produces empty material so verification
// fails closed.
func NewCredentialPublicKeyWithU2F(algorithm protocol.COSEAlgorithmIdentifier, raw []byte, u2fRaw []byte) CredentialPublicKey {
	var material CredentialPublicKeyMaterial
	if len(u2fRaw) == 65 && u2fRaw[0] == 0x04 {
		material.EC2 = &EC2PublicKeyMaterial{
			Curve: EC2CurveP256,
			X:     slices.Clone(u2fRaw[1:33]),
			Y:     slices.Clone(u2fRaw[33:]),
		}
	}
	return NewCredentialPublicKey(algorithm, raw, material)
}

// Raw returns a defensive copy of the source COSE key bytes when available.
func (k CredentialPublicKey) Raw() []byte {
	return slices.Clone(k.raw)
}

// U2FPublicKey returns the raw U2F public key representation 0x04 || x || y
// when the selected codec can derive it from the COSE key.
func (k CredentialPublicKey) U2FPublicKey() []byte {
	material := k.material.EC2
	if k.Algorithm != protocol.AlgorithmES256 || material == nil || material.Curve != EC2CurveP256 || len(material.X) != 32 || len(material.Y) != 32 {
		return nil
	}

	out := make([]byte, 1, 65)
	out[0] = 0x04
	out = append(out, material.X...)
	out = append(out, material.Y...)
	return out
}

// PublicKeyMaterial returns codec-derived public key material for attestation
// format binding checks.
func (k CredentialPublicKey) PublicKeyMaterial() CredentialPublicKeyMaterial {
	return k.material.clone()
}

// Validate checks the algorithm and raw COSE representation required at
// ceremony and storage boundaries.
func (k CredentialPublicKey) Validate() error {
	if k.Algorithm == 0 || len(k.raw) == 0 || len(k.raw) > MaxCredentialPublicKeyBytes {
		return ErrInvalidCredentialPublicKey
	}
	if err := k.Algorithm.Validate(); err != nil {
		return err
	}
	return nil
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

const (
	// MinRSAModulusBits is the RFC 8230 minimum RSA modulus size.
	MinRSAModulusBits = 2048
	// MaxRSAModulusBits bounds RSA verification work while retaining RFC 8230's
	// recommended interoperability range.
	MaxRSAModulusBits = 16384
)

// Valid reports whether the RSA material is minimally encoded and within the
// supported RFC 8230 key-size range.
func (m *RSAPublicKeyMaterial) Valid() bool {
	if m == nil || len(m.Modulus) == 0 || m.Modulus[0] == 0 || m.Modulus[len(m.Modulus)-1]%2 == 0 || m.Exponent < 3 || m.Exponent%2 == 0 {
		return false
	}
	modulusBits := (len(m.Modulus)-1)*8 + bits.Len8(m.Modulus[0])
	return modulusBits >= MinRSAModulusBits && modulusBits <= MaxRSAModulusBits
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
