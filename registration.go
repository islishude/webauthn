package webauthn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"time"

	"github.com/islishude/webauthn/attestation"
	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

var (
	// ErrMalformedResponse reports an invalid or internally inconsistent
	// registration response.
	ErrMalformedResponse = errors.New("webauthn: malformed registration response")
	// ErrChallengeMismatch reports a client challenge that does not match state.
	ErrChallengeMismatch = errors.New("webauthn: challenge mismatch")
	// ErrOriginMismatch reports a client origin or cross-origin policy failure.
	ErrOriginMismatch = errors.New("webauthn: origin mismatch")
	// ErrRPIDHashMismatch reports an authenticator rpIdHash mismatch.
	ErrRPIDHashMismatch = errors.New("webauthn: rp id hash mismatch")
	// ErrUserPresenceRequired reports a missing UP flag.
	ErrUserPresenceRequired = errors.New("webauthn: user presence required")
	// ErrUserVerificationRequired reports a missing UV flag when required.
	ErrUserVerificationRequired = errors.New("webauthn: user verification required")
	// ErrUnsupportedAlgorithm reports a credential public-key algorithm failure.
	ErrUnsupportedAlgorithm = errors.New("webauthn: unsupported algorithm")
	// ErrUnsupportedAttestationFormat reports a missing format verifier.
	ErrUnsupportedAttestationFormat = errors.New("webauthn: unsupported attestation format")
	// ErrInvalidAttestation reports an invalid attestation statement.
	ErrInvalidAttestation = errors.New("webauthn: invalid attestation")
	// ErrRejectedAttestationPolicy reports an attestation policy rejection.
	ErrRejectedAttestationPolicy = errors.New("webauthn: attestation rejected by policy")
	// ErrExtensionPolicy reports an extension policy rejection.
	ErrExtensionPolicy = errors.New("webauthn: extension policy failure")
	// ErrCeremonyExpired reports registration state past its expiry.
	ErrCeremonyExpired = errors.New("webauthn: registration ceremony expired")
	// ErrDuplicateCredential reports an application-provided uniqueness failure.
	ErrDuplicateCredential = errors.New("webauthn: credential already registered")
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
	reader := g.Reader
	if reader == nil {
		reader = rand.Reader
	}

	bytes := make([]byte, length)
	if _, err := io.ReadFull(reader, bytes); err != nil {
		return protocol.Challenge{}, err
	}

	return protocol.NewChallenge(bytes)
}

// RegistrationStartOptions configures registration option creation.
type RegistrationStartOptions struct {
	RP                     protocol.RPEntity
	User                   protocol.UserEntity
	AllowedOrigins         []string
	AllowCrossOrigin       bool
	TokenBindingID         string
	Challenge              protocol.Challenge
	ChallengeGenerator     ChallengeGenerator
	PubKeyCredParams       []protocol.CredentialParameter
	Timeout                time.Duration
	ExcludeCredentials     []protocol.CredentialDescriptor
	AuthenticatorSelection *protocol.AuthenticatorSelectionCriteria
	Attestation            protocol.AttestationConveyancePreference
	UserVerification       protocol.UserVerificationRequirement
	Extensions             protocol.ExtensionInputs
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
	AllowedOrigins            []string
	AllowCrossOrigin          bool
	TokenBindingID            string
	User                      protocol.UserEntity
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
		return RegistrationStartResult{}, err
	}
	if err := options.User.Validate(); err != nil {
		return RegistrationStartResult{}, err
	}
	if err := validateOrigins(options.AllowedOrigins); err != nil {
		return RegistrationStartResult{}, err
	}
	if len(options.PubKeyCredParams) == 0 {
		return RegistrationStartResult{}, errors.New("public key credential parameters are required")
	}
	for _, param := range options.PubKeyCredParams {
		if err := param.Validate(); err != nil {
			return RegistrationStartResult{}, err
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

	userVerification := registrationUserVerification(options)
	if err := validateUserVerification(userVerification); err != nil {
		return RegistrationStartResult{}, err
	}

	attestationConveyance := options.Attestation
	if attestationConveyance == "" {
		attestationConveyance = protocol.AttestationNone
	}
	if !attestationConveyance.Known() {
		return RegistrationStartResult{}, protocol.ValueError{Field: "attestation", Value: string(attestationConveyance)}
	}

	authenticatorSelection := options.AuthenticatorSelection.Clone()
	if authenticatorSelection != nil && authenticatorSelection.UserVerification == "" {
		authenticatorSelection.UserVerification = userVerification
	}

	timeoutMilliseconds, expiresAt, err := timeoutState(options.Timeout)
	if err != nil {
		return RegistrationStartResult{}, err
	}

	creationOptions := protocol.PublicKeyCredentialCreationOptions{
		RP:                     options.RP,
		User:                   options.User,
		Challenge:              challenge,
		PubKeyCredParams:       slices.Clone(options.PubKeyCredParams),
		TimeoutMilliseconds:    timeoutMilliseconds,
		ExcludeCredentials:     cloneCredentialDescriptors(options.ExcludeCredentials),
		AuthenticatorSelection: authenticatorSelection,
		Attestation:            attestationConveyance,
		Extensions:             cloneExtensionInputs(options.Extensions),
	}
	if err := creationOptions.Validate(); err != nil {
		return RegistrationStartResult{}, err
	}

	state := RegistrationState{
		Challenge:                 challenge,
		RPID:                      options.RP.ID,
		AllowedOrigins:            slices.Clone(options.AllowedOrigins),
		AllowCrossOrigin:          options.AllowCrossOrigin,
		TokenBindingID:            options.TokenBindingID,
		User:                      options.User,
		RequestedUserVerification: userVerification,
		RequestedExtensions:       cloneExtensionInputs(options.Extensions),
		AllowedAlgorithms:         algorithmsFromParameters(options.PubKeyCredParams),
		Attestation:               attestationConveyance,
		ExpiresAt:                 expiresAt,
	}

	return RegistrationStartResult{Options: creationOptions, State: state}, nil
}

// RegistrationResponse is the structured, transport-neutral browser
// registration response input.
type RegistrationResponse struct {
	Type                   protocol.PublicKeyCredentialType
	RawID                  protocol.RawID
	ClientDataJSON         protocol.ClientDataJSON
	AttestationObject      protocol.AttestationObject
	Transports             []protocol.AuthenticatorTransport
	ClientExtensionResults map[string]any
}

// RegistrationAttestationPolicy controls attestation acceptance after format
// verification.
type RegistrationAttestationPolicy struct {
	AllowNone bool
}

// AttestationTrustResult records the RP policy outcome.
type AttestationTrustResult = attestation.TrustResult

// RegistrationExtensionPolicy controls extension output handling.
type RegistrationExtensionPolicy struct {
	RejectUnrequested bool
	RejectUnknown     bool
}

// RegistrationFinishOptions configures registration response verification.
type RegistrationFinishOptions struct {
	State                       RegistrationState
	Response                    RegistrationResponse
	Decoders                    codec.Decoders
	AttestationRegistry         *attestation.Registry
	AttestationPolicy           RegistrationAttestationPolicy
	AttestationTrustPolicy      attestation.TrustPolicy
	ExtensionRegistry           *extension.Registry
	ExtensionPolicy             RegistrationExtensionPolicy
	CredentialAlreadyRegistered bool
	Now                         func() time.Time
}

// CredentialRecord is the persistence-ready credential material returned after
// registration verification.
type CredentialRecord struct {
	ID              protocol.CredentialID
	PublicKey       codec.CredentialPublicKey
	UserHandle      protocol.UserHandle
	RPID            string
	AAGUID          protocol.AAGUID
	SignCount       uint32
	Transports      []protocol.AuthenticatorTransport
	AttestationType attestation.Type
}

// RegistrationResult is the verified registration ceremony output.
type RegistrationResult struct {
	Credential          CredentialRecord
	Attestation         attestation.VerificationResult
	AttestationTrust    AttestationTrustResult
	Extensions          []extension.Result
	Warnings            []string
	DuplicateCredential bool
}

// FinishRegistration verifies a WebAuthn registration response.
func FinishRegistration(ctx context.Context, options RegistrationFinishOptions) (RegistrationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateFinishDependencies(options); err != nil {
		return RegistrationResult{}, err
	}
	if err := validateRegistrationState(options.State, options.now()); err != nil {
		return RegistrationResult{}, err
	}
	if options.CredentialAlreadyRegistered {
		return RegistrationResult{DuplicateCredential: true}, ErrDuplicateCredential
	}
	if err := validateRegistrationResponseShape(options.Response); err != nil {
		return RegistrationResult{}, err
	}

	clientData, clientDataHash, err := verifyRegistrationClientData(options.State, options.Response.ClientDataJSON)
	if err != nil {
		return RegistrationResult{}, err
	}

	decodedAttestation, err := options.Decoders.DecodeAttestationObject(options.Response.AttestationObject)
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}

	parsedAuthData, err := verifyRegistrationAuthenticatorData(options.State, decodedAttestation.AuthenticatorData)
	if err != nil {
		return RegistrationResult{}, err
	}
	attested := parsedAuthData.AttestedCredentialData
	if attested == nil {
		return RegistrationResult{}, fmt.Errorf("%w: %w", ErrMalformedResponse, protocol.ErrAttestedCredentialDataMissing)
	}
	if !bytes.Equal(options.Response.RawID.Bytes(), attested.CredentialID.Bytes()) {
		return RegistrationResult{}, ErrMalformedResponse
	}

	credentialPublicKey, authenticatorExtensions, err := decodeCredentialPublicKeyAndExtensions(options.Decoders, parsedAuthData, *attested)
	if err != nil {
		return RegistrationResult{}, err
	}
	if !algorithmAllowed(credentialPublicKey.Algorithm, options.State.AllowedAlgorithms) {
		return RegistrationResult{}, ErrUnsupportedAlgorithm
	}

	extensionResults, err := verifyRegistrationExtensions(ctx, registrationExtensionInputs{
		state:                   options.State,
		policy:                  options.ExtensionPolicy,
		registry:                options.ExtensionRegistry,
		clientExtensionResults:  options.Response.ClientExtensionResults,
		authenticatorExtensions: authenticatorExtensions,
	})
	if err != nil {
		return RegistrationResult{}, err
	}

	attestationResult, trustResult, err := verifyRegistrationAttestation(ctx, registrationAttestationInputs{
		policy:              options.AttestationPolicy,
		trustPolicy:         options.AttestationTrustPolicy,
		registry:            options.AttestationRegistry,
		decodedAttestation:  decodedAttestation,
		credentialPublicKey: credentialPublicKey,
		clientDataHash:      clientDataHash,
		aaguid:              attested.AAGUID,
	})
	if err != nil {
		return RegistrationResult{}, err
	}

	result := RegistrationResult{
		Credential: CredentialRecord{
			ID:              attested.CredentialID,
			PublicKey:       credentialPublicKey,
			UserHandle:      options.State.User.ID,
			RPID:            options.State.RPID,
			AAGUID:          attested.AAGUID,
			SignCount:       parsedAuthData.SignCount,
			Transports:      slices.Clone(options.Response.Transports),
			AttestationType: attestationResult.Type,
		},
		Attestation:      attestationResult,
		AttestationTrust: trustResult,
		Extensions:       extensionResults,
		Warnings:         registrationWarnings(attestationResult, trustResult, clientData),
	}

	return result, nil
}

func (o RegistrationFinishOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}

	return time.Now()
}

func validateFinishDependencies(options RegistrationFinishOptions) error {
	if options.Decoders == nil {
		return errors.New("registration decoders are required")
	}
	if options.AttestationRegistry == nil {
		return errors.New("attestation registry is required")
	}

	return nil
}

func validateRegistrationState(state RegistrationState, now time.Time) error {
	if state.Challenge.Len() == 0 || state.RPID == "" {
		return ErrMalformedResponse
	}
	if err := validateOrigins(state.AllowedOrigins); err != nil {
		return err
	}
	if !state.ExpiresAt.IsZero() && now.After(state.ExpiresAt) {
		return ErrCeremonyExpired
	}
	if len(state.AllowedAlgorithms) == 0 {
		return ErrUnsupportedAlgorithm
	}
	if err := validateUserVerification(state.RequestedUserVerification); err != nil {
		return err
	}

	return nil
}

func validateRegistrationResponseShape(response RegistrationResponse) error {
	if err := response.Type.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	if response.RawID.Bytes() == nil || response.ClientDataJSON.Bytes() == nil || response.AttestationObject.Bytes() == nil {
		return ErrMalformedResponse
	}

	return nil
}

func verifyRegistrationClientData(state RegistrationState, raw protocol.ClientDataJSON) (protocol.CollectedClientData, []byte, error) {
	clientData, err := protocol.ParseCollectedClientData(raw)
	if err != nil {
		return protocol.CollectedClientData{}, nil, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	if err := clientData.ValidateType(protocol.ClientDataTypeCreate); err != nil {
		return protocol.CollectedClientData{}, nil, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	challengeBytes, err := clientData.ChallengeBytes()
	if err != nil {
		return protocol.CollectedClientData{}, nil, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	if !state.Challenge.EqualBytes(challengeBytes) {
		return protocol.CollectedClientData{}, nil, ErrChallengeMismatch
	}
	if !originAllowed(clientData.Origin, state.AllowedOrigins) {
		return protocol.CollectedClientData{}, nil, ErrOriginMismatch
	}
	if clientData.CrossOrigin != nil && *clientData.CrossOrigin && !state.AllowCrossOrigin {
		return protocol.CollectedClientData{}, nil, ErrOriginMismatch
	}
	if clientData.TokenBinding != nil && state.TokenBindingID != "" && clientData.TokenBinding.ID != state.TokenBindingID {
		return protocol.CollectedClientData{}, nil, ErrMalformedResponse
	}

	hash := sha256.Sum256(raw.Bytes())
	return clientData, hash[:], nil
}

func verifyRegistrationAuthenticatorData(state RegistrationState, raw protocol.AuthenticatorData) (protocol.ParsedAuthenticatorData, error) {
	parsed, err := protocol.ParseAuthenticatorData(raw)
	if err != nil {
		return protocol.ParsedAuthenticatorData{}, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}

	expectedRPIDHash := sha256.Sum256([]byte(state.RPID))
	if !bytes.Equal(parsed.RPIDHash, expectedRPIDHash[:]) {
		return protocol.ParsedAuthenticatorData{}, ErrRPIDHashMismatch
	}
	if !parsed.Flags.UserPresent() {
		return protocol.ParsedAuthenticatorData{}, ErrUserPresenceRequired
	}
	if state.RequestedUserVerification == protocol.UserVerificationRequired && !parsed.Flags.UserVerified() {
		return protocol.ParsedAuthenticatorData{}, ErrUserVerificationRequired
	}
	if !parsed.Flags.HasAttestedCredentialData() {
		return protocol.ParsedAuthenticatorData{}, fmt.Errorf("%w: %w", ErrMalformedResponse, protocol.ErrAttestedCredentialDataMissing)
	}

	return parsed, nil
}

func decodeCredentialPublicKeyAndExtensions(decoders codec.Decoders, parsed protocol.ParsedAuthenticatorData, attested protocol.AttestedCredentialData) (codec.CredentialPublicKey, codec.ExtensionMap, error) {
	publicKey, err := decoders.DecodeCredentialPublicKey(attested.CredentialPublicKeyAndExtensions)
	if err != nil {
		return codec.CredentialPublicKey{}, nil, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}

	rawKey := publicKey.Raw()
	if len(rawKey) == 0 || len(rawKey) > len(attested.CredentialPublicKeyAndExtensions) {
		return codec.CredentialPublicKey{}, nil, ErrMalformedResponse
	}

	extensionBytes := attested.CredentialPublicKeyAndExtensions[len(rawKey):]
	if !parsed.Flags.HasExtensionData() {
		if len(extensionBytes) != 0 {
			return codec.CredentialPublicKey{}, nil, ErrMalformedResponse
		}

		return publicKey, nil, nil
	}
	if len(extensionBytes) == 0 {
		return codec.CredentialPublicKey{}, nil, ErrMalformedResponse
	}

	extensions, err := decoders.DecodeExtensionMap(extensionBytes)
	if err != nil {
		return codec.CredentialPublicKey{}, nil, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}

	return publicKey, extensions, nil
}

type registrationAttestationInputs struct {
	policy              RegistrationAttestationPolicy
	trustPolicy         attestation.TrustPolicy
	registry            *attestation.Registry
	decodedAttestation  codec.DecodedAttestationObject
	credentialPublicKey codec.CredentialPublicKey
	clientDataHash      []byte
	aaguid              protocol.AAGUID
}

func verifyRegistrationAttestation(ctx context.Context, inputs registrationAttestationInputs) (attestation.VerificationResult, AttestationTrustResult, error) {
	verifier, ok := inputs.registry.Lookup(inputs.decodedAttestation.Format)
	if !ok {
		return attestation.VerificationResult{}, AttestationTrustResult{}, ErrUnsupportedAttestationFormat
	}

	result, err := verifier.VerifyAttestation(ctx, attestation.VerificationRequest{
		Format:               inputs.decodedAttestation.Format,
		AuthenticatorData:    inputs.decodedAttestation.AuthenticatorData,
		ClientDataHash:       inputs.clientDataHash,
		Statement:            inputs.decodedAttestation.Statement,
		CredentialPublicKey:  inputs.credentialPublicKey,
		RawAttestationObject: inputs.decodedAttestation.Raw,
	})
	if err != nil {
		return attestation.VerificationResult{}, AttestationTrustResult{}, fmt.Errorf("%w: %w", ErrInvalidAttestation, err)
	}
	if !result.CryptographicallyValid {
		return attestation.VerificationResult{}, AttestationTrustResult{}, ErrInvalidAttestation
	}
	if inputs.trustPolicy != nil {
		trustResult, err := inputs.trustPolicy.EvaluateAttestationTrust(ctx, attestation.TrustRequest{
			Format:               inputs.decodedAttestation.Format,
			Result:               result,
			AAGUID:               inputs.aaguid,
			AuthenticatorData:    inputs.decodedAttestation.AuthenticatorData,
			CredentialPublicKey:  inputs.credentialPublicKey,
			RawAttestationObject: inputs.decodedAttestation.Raw,
		})
		if err != nil {
			return attestation.VerificationResult{}, AttestationTrustResult{}, fmt.Errorf("%w: %w", ErrRejectedAttestationPolicy, err)
		}
		if !trustResult.Accepted {
			return attestation.VerificationResult{}, AttestationTrustResult{}, ErrRejectedAttestationPolicy
		}

		return result, trustResult, nil
	}
	if result.Type == attestation.TypeNone {
		if !inputs.policy.AllowNone {
			return attestation.VerificationResult{}, AttestationTrustResult{}, ErrRejectedAttestationPolicy
		}

		return result, AttestationTrustResult{Accepted: true, Reason: "none attestation accepted by policy"}, nil
	}

	return attestation.VerificationResult{}, AttestationTrustResult{}, ErrRejectedAttestationPolicy
}

type registrationExtensionInputs struct {
	state                   RegistrationState
	policy                  RegistrationExtensionPolicy
	registry                *extension.Registry
	clientExtensionResults  map[string]any
	authenticatorExtensions codec.ExtensionMap
}

func verifyRegistrationExtensions(ctx context.Context, inputs registrationExtensionInputs) ([]extension.Result, error) {
	ids := map[string]struct{}{}
	for id := range inputs.state.RequestedExtensions {
		ids[id] = struct{}{}
	}
	for id := range inputs.clientExtensionResults {
		ids[id] = struct{}{}
	}
	for id := range inputs.authenticatorExtensions {
		ids[id] = struct{}{}
	}

	results := make([]extension.Result, 0, len(ids))
	for id := range ids {
		clientInput, requested := inputs.state.RequestedExtensions[id]
		clientOutput, hasClientOutput := inputs.clientExtensionResults[id]
		authenticatorOutput, hasAuthenticatorOutput := inputs.authenticatorExtensions[id]

		handler, known := lookupExtensionHandler(inputs.registry, id)
		if !known && inputs.policy.RejectUnknown {
			return nil, ErrExtensionPolicy
		}

		hasOutput := hasClientOutput || hasAuthenticatorOutput
		if !requested && hasOutput {
			if inputs.policy.RejectUnrequested {
				return nil, ErrExtensionPolicy
			}
			results = append(results, rawExtensionResult(id, rawExtensionInputs{
				requested:              requested,
				clientInput:            clientInput,
				clientOutput:           clientOutput,
				hasClientOutput:        hasClientOutput,
				authenticatorOutput:    authenticatorOutput,
				hasAuthenticatorOutput: hasAuthenticatorOutput,
				warning:                "unrequested extension output ignored",
			}))
			continue
		}

		if !known {
			results = append(results, rawExtensionResult(id, rawExtensionInputs{
				requested:              requested,
				clientInput:            clientInput,
				clientOutput:           clientOutput,
				hasClientOutput:        hasClientOutput,
				authenticatorOutput:    authenticatorOutput,
				hasAuthenticatorOutput: hasAuthenticatorOutput,
				warning:                "unknown extension preserved",
			}))
			continue
		}

		result, err := handler.HandleExtension(ctx, extension.Request{
			Operation:           extension.OperationRegistration,
			ID:                  id,
			Requested:           requested,
			ClientInput:         clientInput,
			ClientOutput:        clientOutput,
			AuthenticatorOutput: authenticatorOutput,
		})
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtensionPolicy, err)
		}
		results = append(results, result)
	}

	return results, nil
}

func lookupExtensionHandler(registry *extension.Registry, id string) (extension.Handler, bool) {
	if registry == nil {
		return nil, false
	}

	return registry.Lookup(id)
}

type rawExtensionInputs struct {
	requested              bool
	clientInput            any
	clientOutput           any
	hasClientOutput        bool
	authenticatorOutput    any
	hasAuthenticatorOutput bool
	warning                string
}

func rawExtensionResult(id string, input rawExtensionInputs) extension.Result {
	outputs := map[string]any{"requested": input.requested}
	if input.clientInput != nil {
		outputs["clientInput"] = input.clientInput
	}
	if input.hasClientOutput {
		outputs["clientOutput"] = input.clientOutput
	}
	if input.hasAuthenticatorOutput {
		outputs["authenticatorOutput"] = input.authenticatorOutput
	}

	return extension.Result{
		ID:       id,
		Accepted: false,
		Outputs:  outputs,
		Warnings: []string{input.warning},
	}
}

func registrationUserVerification(options RegistrationStartOptions) protocol.UserVerificationRequirement {
	if options.UserVerification != "" {
		return options.UserVerification
	}
	if options.AuthenticatorSelection != nil && options.AuthenticatorSelection.UserVerification != "" {
		return options.AuthenticatorSelection.UserVerification
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

func validateOrigins(origins []string) error {
	if len(origins) == 0 {
		return errors.New("allowed origins are required")
	}
	if slices.Contains(origins, "") {
		return errors.New("allowed origins must not contain empty values")
	}

	return nil
}

func originAllowed(origin string, allowedOrigins []string) bool {
	return slices.Contains(allowedOrigins, origin)
}

func algorithmAllowed(algorithm protocol.COSEAlgorithmIdentifier, allowed []protocol.COSEAlgorithmIdentifier) bool {
	return slices.Contains(allowed, algorithm)
}

func algorithmsFromParameters(parameters []protocol.CredentialParameter) []protocol.COSEAlgorithmIdentifier {
	algorithms := make([]protocol.COSEAlgorithmIdentifier, len(parameters))
	for i, parameter := range parameters {
		algorithms[i] = parameter.Algorithm
	}

	return algorithms
}

func timeoutState(timeout time.Duration) (uint32, time.Time, error) {
	if timeout <= 0 {
		return 0, time.Time{}, nil
	}

	milliseconds := timeout.Milliseconds()
	if milliseconds == 0 {
		milliseconds = 1
	}
	if milliseconds > math.MaxUint32 {
		return 0, time.Time{}, errors.New("timeout exceeds uint32 milliseconds")
	}

	return uint32(milliseconds), time.Now().Add(timeout), nil
}

func clientDataWarnings(protocol.CollectedClientData) []string {
	return nil
}

func registrationWarnings(attestationResult attestation.VerificationResult, trustResult AttestationTrustResult, clientData protocol.CollectedClientData) []string {
	warnings := slices.Clone(attestationResult.Warnings)
	warnings = append(warnings, trustResult.Warnings...)
	warnings = append(warnings, clientDataWarnings(clientData)...)

	return warnings
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

func cloneExtensionInputs(inputs protocol.ExtensionInputs) protocol.ExtensionInputs {
	if inputs == nil {
		return nil
	}

	out := make(protocol.ExtensionInputs, len(inputs))
	maps.Copy(out, inputs)

	return out
}
