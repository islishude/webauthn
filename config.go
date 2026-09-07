package webauthn

import (
	"fmt"
	"slices"
	"time"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/codec"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/internal/interfaceutil"
	"github.com/islishude/webauthn/internal/protocolidentifier"
	"github.com/islishude/webauthn/protocol"
)

// Config holds reusable ceremony policy. New copies configuration values;
// injected dependencies and callbacks must remain stable and concurrency-safe.
type Config struct {
	// RP and OriginPolicy are required trusted server configuration.
	RP           protocol.RPEntity
	OriginPolicy OriginPolicy
	// PubKeyCredParams is the shared registration/authentication allow-list.
	// Empty uses the low-level ES256/RS256 defaults.
	PubKeyCredParams []protocol.CredentialParameter
	// All three decoders are required, including for unsolicited extensions.
	AttestationObjectDecoder   codec.AttestationObjectDecoder
	CredentialPublicKeyDecoder codec.COSEKeyDecoder
	ExtensionMapDecoder        codec.ExtensionMapDecoder
	// SignatureVerifier and AlgorithmPolicy are required. The policy must accept
	// every advertised algorithm; actual verifier capability is the adapter's contract.
	SignatureVerifier webcrypto.SignatureVerifier
	AlgorithmPolicy   webcrypto.AlgorithmPolicy
	// AttestationRegistry and AttestationTrustPolicy must be selected explicitly.
	AttestationRegistry    *attestation.Registry
	AttestationTrustPolicy attestation.TrustPolicy
	// ExtensionRegistry is optional when no extensions are requested.
	ExtensionRegistry *extension.Registry
	Registration      RegistrationConfig
	Authentication    AuthenticationConfig
	// Timeout is a browser hint; zero uses DefaultBrowserTimeout.
	Timeout time.Duration
	// StateTTL is server-side lifetime; zero uses DefaultChallengeTTL.
	StateTTL time.Duration
	// ChallengeGenerator defaults to RandomChallengeGenerator. Now defaults to time.Now.
	ChallengeGenerator ChallengeGenerator
	Now                func() time.Time
}

// RegistrationConfig contains fixed registration preferences and extension policy.
type RegistrationConfig struct {
	// AuthenticatorSelection defaults to preferred UV and browser selection defaults.
	AuthenticatorSelection *protocol.AuthenticatorSelectionCriteria
	// Attestation defaults to none; AttestationFormats contains optional preferences.
	Attestation          protocol.AttestationConveyancePreference
	AttestationFormats   []string
	ExtensionInputPolicy ExtensionInputPolicy
	ExtensionPolicy      RegistrationExtensionPolicy
}

// AuthenticationConfig contains fixed authentication policy.
type AuthenticationConfig struct {
	// UserVerification defaults to preferred.
	UserVerification     protocol.UserVerificationRequirement
	ExtensionInputPolicy ExtensionInputPolicy
	ExtensionPolicy      AuthenticationExtensionPolicy
	// CounterPolicy defaults to reporting clone risk without rolling back the counter.
	CounterPolicy CounterPolicy
}

// RelyingParty reuses validated configuration across ceremonies. It is safe for
// concurrent use if its dependencies are safe. Its zero value is not usable.
type RelyingParty struct {
	config     Config
	algorithms []protocol.COSEAlgorithmIdentifier
	ready      bool
}

// New validates configuration without generating challenges or verifying
// signatures/attestations. AlgorithmPolicy is queried during validation.
func New(config Config) (*RelyingParty, error) {
	config.OriginPolicy = config.OriginPolicy.clone()
	config.Registration.AuthenticatorSelection = config.Registration.AuthenticatorSelection.Clone()
	config.Registration.AttestationFormats = slices.Clone(config.Registration.AttestationFormats)
	parameters, err := registrationCredentialParameters(config.PubKeyCredParams)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}
	config.PubKeyCredParams = parameters
	if config.Timeout == 0 {
		config.Timeout = DefaultBrowserTimeout
	}
	if config.StateTTL == 0 {
		config.StateTTL = DefaultChallengeTTL
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.ChallengeGenerator == nil {
		config.ChallengeGenerator = RandomChallengeGenerator{}
	}
	if config.Registration.Attestation == "" {
		config.Registration.Attestation = protocol.AttestationNone
	}
	if config.Authentication.UserVerification == "" {
		config.Authentication.UserVerification = protocol.UserVerificationPreferred
	}
	if selection := config.Registration.AuthenticatorSelection; selection != nil && selection.UserVerification == "" {
		selection.UserVerification = protocol.UserVerificationPreferred
	}
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}
	return &RelyingParty{config: config, algorithms: algorithmsFromParameters(parameters), ready: true}, nil
}

func validateConfig(c Config) error {
	if err := c.RP.Validate(); err != nil {
		return err
	}
	if err := validateOriginPolicy(c.OriginPolicy); err != nil {
		return err
	}
	if err := validateRPIDOriginPolicy(c.RP.ID, c.OriginPolicy); err != nil {
		return err
	}
	if _, _, err := timeoutState(c.Timeout, c.StateTTL, time.Time{}); err != nil {
		return err
	}
	if err := validateFinishDependencies(RegistrationFinishOptions{AttestationObjectDecoder: c.AttestationObjectDecoder, CredentialPublicKeyDecoder: c.CredentialPublicKeyDecoder, AttestationRegistry: c.AttestationRegistry, AttestationTrustPolicy: c.AttestationTrustPolicy}); err != nil {
		return err
	}
	for _, dependency := range []struct {
		name  string
		value any
	}{
		{"extension map decoder", c.ExtensionMapDecoder}, {"signature verifier", c.SignatureVerifier},
		{"algorithm policy", c.AlgorithmPolicy}, {"attestation trust policy", c.AttestationTrustPolicy},
		{"challenge generator", c.ChallengeGenerator},
	} {
		if interfaceutil.IsNil(dependency.value) {
			return fmt.Errorf("%s is required", dependency.name)
		}
	}
	if err := validateUserVerification(registrationUserVerification(c.Registration.AuthenticatorSelection)); err != nil {
		return err
	}
	if err := validateUserVerification(c.Authentication.UserVerification); err != nil {
		return err
	}
	if !c.Registration.Attestation.Known() {
		return protocol.ValueError{Field: "attestation", Value: string(c.Registration.Attestation)}
	}
	for _, format := range c.Registration.AttestationFormats {
		if !protocolidentifier.Valid(format) {
			return fmt.Errorf("invalid attestation format preference")
		}
	}
	if c.Authentication.CounterPolicy.RejectCloneRisk && c.Authentication.CounterPolicy.UpdateOnCloneRisk {
		return fmt.Errorf("clone-risk policy cannot reject and update")
	}
	for _, parameter := range c.PubKeyCredParams {
		if !c.AlgorithmPolicy.AcceptsAlgorithm(parameter.Algorithm) {
			return ErrUnsupportedAlgorithm
		}
	}
	return nil
}
