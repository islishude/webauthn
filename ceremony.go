package webauthn

import (
	"crypto/sha256"
	"errors"
	"fmt"
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

func timeoutState(timeout time.Duration, stateTTL time.Duration, now time.Time) (uint32, time.Time, error) {
	if timeout < 0 {
		return 0, time.Time{}, errors.New("timeout must not be negative")
	}
	if stateTTL < 0 {
		return 0, time.Time{}, errors.New("state ttl must not be negative")
	}
	if timeout == 0 {
		timeout = DefaultBrowserTimeout
	}
	if stateTTL == 0 {
		stateTTL = DefaultChallengeTTL
	}
	if stateTTL < timeout {
		return 0, time.Time{}, errors.New("state ttl must not be shorter than timeout")
	}
	milliseconds := timeout.Milliseconds()
	if milliseconds == 0 {
		milliseconds = 1
	}
	if milliseconds > math.MaxUint32 {
		return 0, time.Time{}, errors.New("timeout exceeds uint32 milliseconds")
	}
	return uint32(milliseconds), now.Add(stateTTL), nil
}

func registrationCredentialParameters(parameters []protocol.CredentialParameter) ([]protocol.CredentialParameter, error) {
	if len(parameters) == 0 {
		return []protocol.CredentialParameter{
			{Type: protocol.CredentialTypePublicKey, Algorithm: protocol.AlgorithmES256},
			{Type: protocol.CredentialTypePublicKey, Algorithm: protocol.AlgorithmRS256},
		}, nil
	}

	out := make([]protocol.CredentialParameter, 0, len(parameters))
	for _, parameter := range parameters {
		if err := parameter.Validate(); err != nil {
			return nil, err
		}
		if parameter.Type != protocol.CredentialTypePublicKey {
			continue
		}
		out = append(out, parameter)
	}
	if len(out) == 0 {
		return nil, errors.New("no supported public key credential parameters")
	}
	return out, nil
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

func normalizeAuthenticatorAttachment(value protocol.AuthenticatorAttachment) protocol.AuthenticatorAttachment {
	if value.Known() {
		return value
	}
	return ""
}

func verifyClientData(raw protocol.ClientDataJSON, expectedType protocol.ClientDataType, challenge protocol.Challenge, originPolicy OriginPolicy) ([]byte, error) {
	clientData, err := protocol.ParseCollectedClientData(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	if err := clientData.ValidateType(expectedType); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	challengeBytes, err := clientData.ChallengeBytes()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	if !challenge.EqualBytes(challengeBytes) {
		return nil, ErrChallengeMismatch
	}
	if err := verifyCollectedClientOrigin(originPolicy, clientData); err != nil {
		return nil, err
	}

	hash := sha256.Sum256(raw.AppendTo(nil))
	return hash[:], nil
}
