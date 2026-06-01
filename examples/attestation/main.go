package main

import (
	"github.com/islishude/webauthn/attestation"
	attnone "github.com/islishude/webauthn/attestation/none"
	"github.com/islishude/webauthn/attestation/packed"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

func selectedAttestationFormats(signatureVerifier webcrypto.SignatureVerifier) (*attestation.Registry, error) {
	return attestation.NewRegistry(
		attnone.New(),
		packed.New(signatureVerifier),
	)
}

func restrictedEnrollmentPolicy(allowedAAGUID protocol.AAGUID) attestation.TrustPolicy {
	return attestation.AllOf(
		attestation.RejectNone(),
		attestation.AllowFormats("packed"),
		attestation.AllowTypes(attestation.TypeBasic, attestation.TypeAttCA, attestation.TypeUncertain),
		attestation.RequireAAGUID(allowedAAGUID),
	)
}

func main() {
	_ = selectedAttestationFormats
	_ = restrictedEnrollmentPolicy
}
