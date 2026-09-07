// Package preset assembles explicitly selected, optional WebAuthn configurations.
package preset

import (
	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/attestation/none"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/crypto/standard"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

// PasskeyConfig selects discoverable credentials, required user verification,
// and explicitly accepted none attestation. It does not request extensions or
// constrain authenticator attachment. Call webauthn.New after any customization.
func PasskeyConfig(rp protocol.RPEntity, origins webauthn.OriginPolicy) (webauthn.Config, error) {
	decoder, err := codeccbor.NewDecoder()
	if err != nil {
		return webauthn.Config{}, err
	}
	parameters := protocol.RecommendedLevel3CredentialParameters()
	algorithms := make([]protocol.COSEAlgorithmIdentifier, len(parameters))
	for i, p := range parameters {
		algorithms[i] = p.Algorithm
	}
	verifier, err := standard.NewVerifier(algorithms...)
	if err != nil {
		return webauthn.Config{}, err
	}
	attesters, err := attestation.NewRegistry(none.New())
	if err != nil {
		return webauthn.Config{}, err
	}
	extensions, err := extension.NewLevel3Registry()
	if err != nil {
		return webauthn.Config{}, err
	}
	return webauthn.Config{
		RP: rp, OriginPolicy: origins, PubKeyCredParams: parameters,
		AttestationObjectDecoder: decoder, CredentialPublicKeyDecoder: decoder, ExtensionMapDecoder: decoder,
		SignatureVerifier: verifier, AlgorithmPolicy: verifier,
		AttestationRegistry: attesters, AttestationTrustPolicy: attestation.AcceptNone(), ExtensionRegistry: extensions,
		Registration: webauthn.RegistrationConfig{Attestation: protocol.AttestationNone,
			AuthenticatorSelection: &protocol.AuthenticatorSelectionCriteria{ResidentKey: protocol.ResidentKeyRequired, UserVerification: protocol.UserVerificationRequired}},
		Authentication: webauthn.AuthenticationConfig{UserVerification: protocol.UserVerificationRequired},
	}, nil
}
