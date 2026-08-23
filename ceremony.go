package webauthn

import (
	"errors"
	"math"
	"time"

	"github.com/islishude/webauthn/protocol"
)

func registrationUserVerification(selection *protocol.AuthenticatorSelectionCriteria) protocol.UserVerificationRequirement {
	if selection != nil && selection.UserVerification != "" {
		return selection.UserVerification
	}
	return protocol.UserVerificationPreferred
}

func validateUserVerification(value protocol.UserVerificationRequirement) error {
	if value == "" {
		return nil
	}
	if !value.Known() {
		return protocol.ValueError{Field: "user verification", Value: string(value)}
	}
	return nil
}

func algorithmsFromParameters(parameters []protocol.CredentialParameter) []protocol.COSEAlgorithmIdentifier {
	algorithms := make([]protocol.COSEAlgorithmIdentifier, len(parameters))
	for i, parameter := range parameters {
		algorithms[i] = parameter.Algorithm
	}
	return algorithms
}

func timeoutState(timeout time.Duration, now time.Time) (uint32, time.Time, error) {
	if timeout < 0 {
		return 0, time.Time{}, errors.New("timeout must not be negative")
	}
	if timeout == 0 {
		timeout = DefaultCeremonyTimeout
	}
	milliseconds := timeout.Milliseconds()
	if milliseconds == 0 {
		milliseconds = 1
	}
	if milliseconds > math.MaxUint32 {
		return 0, time.Time{}, errors.New("timeout exceeds uint32 milliseconds")
	}
	return uint32(milliseconds), now.Add(timeout), nil
}

func cloneCredentialDescriptors(descriptors []protocol.CredentialDescriptor) []protocol.CredentialDescriptor {
	if descriptors == nil {
		return nil
	}
	out := make([]protocol.CredentialDescriptor, len(descriptors))
	for i, descriptor := range descriptors {
		out[i] = descriptor.Clone()
	}
	return out
}
