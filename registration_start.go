package webauthn

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

// ChallengeGenerator generates server-side registration challenges.
type ChallengeGenerator interface {
	GenerateChallenge(context.Context) (protocol.Challenge, error)
}

// ChallengeGeneratorFunc adapts a function into a ChallengeGenerator.
type ChallengeGeneratorFunc func(context.Context) (protocol.Challenge, error)

// GenerateChallenge calls f(ctx).
func (f ChallengeGeneratorFunc) GenerateChallenge(ctx context.Context) (protocol.Challenge, error) {
	return f(ctx)
}

// RandomChallengeGenerator generates challenges from a random reader.
type RandomChallengeGenerator struct {
	Reader io.Reader
	Length int
}

// GenerateChallenge returns a fresh random challenge.
func (g RandomChallengeGenerator) GenerateChallenge(ctx context.Context) (protocol.Challenge, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return protocol.Challenge{}, ctx.Err()
	default:
	}
	length := g.Length
	if length == 0 {
		length = protocol.RecommendedChallengeLength
	}
	if length < protocol.MinChallengeLength {
		return protocol.Challenge{}, protocol.ByteLengthError{Field: "challenge", Length: length, Min: protocol.MinChallengeLength}
	}
	reader := g.Reader
	if reader == nil {
		reader = rand.Reader
	}
	raw := make([]byte, length)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return protocol.Challenge{}, err
	}
	return protocol.NewChallenge(raw)
}

// RegistrationStartOptions configures registration option creation.
type RegistrationStartOptions struct {
	RP                     protocol.RPEntity
	User                   protocol.UserEntity
	OriginPolicy           OriginPolicy
	Challenge              protocol.Challenge
	ChallengeGenerator     ChallengeGenerator
	PubKeyCredParams       []protocol.CredentialParameter
	Timeout                time.Duration
	ExcludeCredentials     []protocol.CredentialDescriptor
	AuthenticatorSelection *protocol.AuthenticatorSelectionCriteria
	Hints                  []protocol.PublicKeyCredentialHint
	Attestation            protocol.AttestationConveyancePreference
	AttestationFormats     []string
	Extensions             protocol.ExtensionInputs
	ExtensionRegistry      *extension.Registry
	ExtensionInputPolicy   ExtensionInputPolicy
	Now                    func() time.Time
}

// ExtensionInputPolicy controls unknown extension inputs at ceremony start.
type ExtensionInputPolicy struct {
	RejectUnknown bool
}

// RegistrationStartResult contains browser creation options and caller-stored
// ceremony state.
type RegistrationStartResult struct {
	Options protocol.PublicKeyCredentialCreationOptions
	State   RegistrationState
}

// RegistrationState is stored by callers between registration start and finish.
type RegistrationState struct {
	Challenge                 protocol.Challenge
	RPID                      string
	OriginPolicy              OriginPolicy
	UserHandle                protocol.UserHandle
	RequestedUserVerification protocol.UserVerificationRequirement
	RequestedExtensions       protocol.ExtensionInputs
	AllowedAlgorithms         []protocol.COSEAlgorithmIdentifier
	Attestation               protocol.AttestationConveyancePreference
	ExpiresAt                 time.Time
}

// StartRegistration builds WebAuthn creation options and ceremony state.
func StartRegistration(ctx context.Context, options RegistrationStartOptions) (RegistrationStartResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := options.RP.Validate(); err != nil {
		return RegistrationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}
	if err := options.User.Validate(); err != nil {
		return RegistrationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}
	if err := validateOriginPolicy(options.OriginPolicy); err != nil {
		return RegistrationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}
	if len(options.PubKeyCredParams) == 0 {
		return RegistrationStartResult{}, fmt.Errorf("%w: public key credential parameters are required", ErrInvalidConfiguration)
	}
	for _, parameter := range options.PubKeyCredParams {
		if err := parameter.Validate(); err != nil {
			return RegistrationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
		}
	}

	challenge := options.Challenge
	if challenge.Len() == 0 {
		generator := options.ChallengeGenerator
		if generator == nil {
			generator = RandomChallengeGenerator{}
		}
		generated, err := generator.GenerateChallenge(ctx)
		if err != nil {
			return RegistrationStartResult{}, err
		}
		challenge = generated
	}

	userVerification := registrationUserVerification(options.AuthenticatorSelection)
	if err := validateUserVerification(userVerification); err != nil {
		return RegistrationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}
	preparedExtensions, err := prepareExtensionInputs(extension.OperationRegistration, options.Extensions, options.ExtensionRegistry, options.ExtensionInputPolicy, nil)
	if err != nil {
		return RegistrationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}
	optionExtensions, err := cloneExtensionInputs(preparedExtensions)
	if err != nil {
		return RegistrationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}
	stateExtensions, err := cloneExtensionInputs(preparedExtensions)
	if err != nil {
		return RegistrationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}

	attestationConveyance := options.Attestation
	if attestationConveyance == "" {
		attestationConveyance = protocol.AttestationNone
	}
	if !attestationConveyance.Known() {
		return RegistrationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, protocol.ValueError{Field: "attestation", Value: string(attestationConveyance)})
	}
	authenticatorSelection := options.AuthenticatorSelection.Clone()
	if authenticatorSelection != nil && authenticatorSelection.UserVerification == "" {
		authenticatorSelection.UserVerification = userVerification
	}
	timeoutMilliseconds, expiresAt, err := timeoutState(options.Timeout, options.now())
	if err != nil {
		return RegistrationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}

	creationOptions := protocol.PublicKeyCredentialCreationOptions{
		RP:                     options.RP,
		User:                   options.User,
		Challenge:              challenge,
		PubKeyCredParams:       slices.Clone(options.PubKeyCredParams),
		TimeoutMilliseconds:    timeoutMilliseconds,
		ExcludeCredentials:     cloneCredentialDescriptors(options.ExcludeCredentials),
		AuthenticatorSelection: authenticatorSelection,
		Hints:                  slices.Clone(options.Hints),
		Attestation:            attestationConveyance,
		AttestationFormats:     slices.Clone(options.AttestationFormats),
		Extensions:             optionExtensions,
	}
	if err := creationOptions.Validate(); err != nil {
		return RegistrationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}
	state := RegistrationState{
		Challenge:                 challenge,
		RPID:                      options.RP.ID,
		OriginPolicy:              options.OriginPolicy.clone(),
		UserHandle:                options.User.ID,
		RequestedUserVerification: userVerification,
		RequestedExtensions:       stateExtensions,
		AllowedAlgorithms:         algorithmsFromParameters(options.PubKeyCredParams),
		Attestation:               attestationConveyance,
		ExpiresAt:                 expiresAt,
	}
	return RegistrationStartResult{Options: creationOptions, State: state}, nil
}

func (o RegistrationStartOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}
