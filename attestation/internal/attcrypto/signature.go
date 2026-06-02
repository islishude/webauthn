// Package attcrypto contains shared attestation cryptographic adapter helpers.
package attcrypto

import (
	"context"
	"fmt"
	"slices"

	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

// SignedData returns authenticatorData || clientDataHash.
func SignedData(authenticatorData protocol.AuthenticatorData, clientDataHash []byte) []byte {
	out := authenticatorData.AppendTo(make([]byte, 0, authenticatorData.Len()+len(clientDataHash)))
	return append(out, clientDataHash...)
}

// VerifySignature validates the raw signature wrapper, then delegates signature
// verification through verifier while preserving caller-selected sentinel errors.
func VerifySignature(ctx context.Context, verifier webcrypto.SignatureVerifier, algorithm protocol.COSEAlgorithmIdentifier, publicKey any, signed []byte, signature []byte, malformedSignature error, invalidSignature error) error {
	protocolSignature, err := protocol.NewSignature(signature)
	if err != nil {
		return fmt.Errorf("%w: %w", malformedSignature, err)
	}

	if err := verifier.VerifySignature(ctx, webcrypto.SignatureInput{
		Algorithm: algorithm,
		PublicKey: publicKey,
		Signed:    slices.Clone(signed),
		Signature: protocolSignature,
	}); err != nil {
		return fmt.Errorf("%w: %w", invalidSignature, err)
	}

	return nil
}
