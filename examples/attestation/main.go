package main

import (
	"github.com/islishude/webauthn/attestation"
	attnone "github.com/islishude/webauthn/attestation/none"
	"github.com/islishude/webauthn/attestation/packed"
	"github.com/islishude/webauthn/crypto/standard"
	"github.com/islishude/webauthn/protocol"
)

func selectedAttestationFormats() (*attestation.Registry, error) {
	signatureVerifier, err := standard.NewVerifier(protocol.AlgorithmEdDSA, protocol.AlgorithmES256, protocol.AlgorithmRS256)
	if err != nil {
		return nil, err
	}
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
