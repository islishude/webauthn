package webauthn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/islishude/webauthn/codec"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
)

var (
	// ErrCredentialNotAllowed reports an assertion credential outside the
	// ceremony allow list or stored credential binding.
	ErrCredentialNotAllowed = errors.New("webauthn: credential not allowed")
	// ErrUserHandleRequired reports a discoverable-credential assertion without
	// a user handle.
	ErrUserHandleRequired = errors.New("webauthn: user handle required")
	// ErrCredentialOwnershipMismatch reports an assertion for the wrong user.
	ErrCredentialOwnershipMismatch = errors.New("webauthn: credential ownership mismatch")
	// ErrInvalidSignature reports failed assertion signature verification.
	ErrInvalidSignature = errors.New("webauthn: invalid signature")
	// ErrCloneRisk reports a sign counter rollback or non-increment.
	ErrCloneRisk = errors.New("webauthn: signature counter clone risk")
)

// AuthenticationStartOptions configures assertion option creation.
type AuthenticationStartOptions struct {
	RPID               string
	AllowedOrigins     []string
	AllowCrossOrigin   bool
	TokenBindingID     string
	Challenge          protocol.Challenge
	ChallengeGenerator ChallengeGenerator
	Timeout            time.Duration
	AllowCredentials   []protocol.CredentialDescriptor
	UserVerification   protocol.UserVerificationRequirement
	Extensions         protocol.ExtensionInputs
	ExpectedUserHandle protocol.UserHandle
}

// AuthenticationStartResult contains browser request options and caller-stored
// ceremony state.
type AuthenticationStartResult struct {
	Options protocol.PublicKeyCredentialRequestOptions
	State   AuthenticationState
}

// AuthenticationState is stored by callers between authentication start and
// finish.
type AuthenticationState struct {
	Challenge                 protocol.Challenge
	RPID                      string
	AllowedOrigins            []string
	AllowCrossOrigin          bool
	TokenBindingID            string
	RequestedUserVerification protocol.UserVerificationRequirement
	RequestedExtensions       protocol.ExtensionInputs
	AllowCredentials          []protocol.CredentialDescriptor
	ExpectedUserHandle        protocol.UserHandle
	ExpiresAt                 time.Time
}

// StartAuthentication builds WebAuthn assertion options and ceremony state.
func StartAuthentication(ctx context.Context, options AuthenticationStartOptions) (AuthenticationStartResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if options.RPID == "" {
		return AuthenticationStartResult{}, errors.New("rp id is required")
	}
	if err := validateOrigins(options.AllowedOrigins); err != nil {
		return AuthenticationStartResult{}, err
	}
	for _, descriptor := range options.AllowCredentials {
		if err := descriptor.Validate(); err != nil {
			return AuthenticationStartResult{}, err
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
			return AuthenticationStartResult{}, err
		}
		challenge = generated
	}

	userVerification := options.UserVerification
	if userVerification == "" {
		userVerification = protocol.UserVerificationPreferred
	}
	if err := validateUserVerification(userVerification); err != nil {
		return AuthenticationStartResult{}, err
	}

	timeoutMilliseconds, expiresAt, err := timeoutState(options.Timeout)
	if err != nil {
		return AuthenticationStartResult{}, err
	}

	requestOptions := protocol.PublicKeyCredentialRequestOptions{
		Challenge:           challenge,
		TimeoutMilliseconds: timeoutMilliseconds,
		RPID:                options.RPID,
		AllowCredentials:    cloneCredentialDescriptors(options.AllowCredentials),
		UserVerification:    userVerification,
		Extensions:          cloneExtensionInputs(options.Extensions),
	}
	if err := requestOptions.Validate(); err != nil {
		return AuthenticationStartResult{}, err
	}

	state := AuthenticationState{
		Challenge:                 challenge,
		RPID:                      options.RPID,
		AllowedOrigins:            slices.Clone(options.AllowedOrigins),
		AllowCrossOrigin:          options.AllowCrossOrigin,
		TokenBindingID:            options.TokenBindingID,
		RequestedUserVerification: userVerification,
		RequestedExtensions:       cloneExtensionInputs(options.Extensions),
		AllowCredentials:          cloneCredentialDescriptors(options.AllowCredentials),
		ExpectedUserHandle:        options.ExpectedUserHandle,
		ExpiresAt:                 expiresAt,
	}

	return AuthenticationStartResult{Options: requestOptions, State: state}, nil
}

// AuthenticationResponse is the structured, transport-neutral browser
// assertion response input.
type AuthenticationResponse struct {
	Type                   protocol.PublicKeyCredentialType
	RawID                  protocol.RawID
	ClientDataJSON         protocol.ClientDataJSON
	AuthenticatorData      protocol.AuthenticatorData
	Signature              protocol.Signature
	UserHandle             protocol.UserHandle
	ClientExtensionResults map[string]any
}

// AuthenticationExtensionPolicy controls authentication extension behavior.
type AuthenticationExtensionPolicy struct {
	RejectUnrequested bool
	RejectUnknown     bool
	AppID             string
}

// CounterPolicy controls how sign counter clone-risk signals affect results.
type CounterPolicy struct {
	RejectCloneRisk bool
}

// CounterStatus classifies sign counter comparison.
type CounterStatus string

const (
	CounterStatusUnsupported CounterStatus = "unsupported"
	CounterStatusIncremented CounterStatus = "incremented"
	CounterStatusCloneRisk   CounterStatus = "clone-risk"
)

// CounterResult reports the WebAuthn sign counter comparison.
type CounterResult struct {
	Stored    uint32
	New       uint32
	Status    CounterStatus
	CloneRisk bool
}

// AuthenticationFinishOptions configures assertion verification.
type AuthenticationFinishOptions struct {
	State             AuthenticationState
	Response          AuthenticationResponse
	Credential        CredentialRecord
	Decoders          codec.Decoders
	SignatureVerifier webcrypto.SignatureVerifier
	AlgorithmPolicy   webcrypto.AlgorithmPolicy
	ExtensionRegistry *extension.Registry
	ExtensionPolicy   AuthenticationExtensionPolicy
	CounterPolicy     CounterPolicy
	Now               func() time.Time
}

// CredentialUpdate is the persistence-ready credential update after
// authentication.
type CredentialUpdate struct {
	ID        protocol.CredentialID
	SignCount uint32
}

// AuthenticationResult is the verified authentication ceremony output.
type AuthenticationResult struct {
	Credential      CredentialRecord
	AuthenticatedAs protocol.UserHandle
	Counter         CounterResult
	Update          CredentialUpdate
	Extensions      []extension.Result
	Warnings        []string
}

// FinishAuthentication verifies a WebAuthn authentication assertion.
func FinishAuthentication(ctx context.Context, options AuthenticationFinishOptions) (AuthenticationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateAuthenticationDependencies(options); err != nil {
		return AuthenticationResult{}, err
	}
	if err := validateAuthenticationState(options.State, options.now()); err != nil {
		return AuthenticationResult{}, err
	}
	if err := validateAuthenticationResponseShape(options.Response); err != nil {
		return AuthenticationResult{}, err
	}
	if err := verifyAuthenticationCredentialBinding(options.State, options.Response, options.Credential); err != nil {
		return AuthenticationResult{}, err
	}
	if err := verifyAuthenticationUserBinding(options.State, options.Response, options.Credential); err != nil {
		return AuthenticationResult{}, err
	}

	_, clientDataHash, err := verifyAuthenticationClientData(options.State, options.Response.ClientDataJSON)
	if err != nil {
		return AuthenticationResult{}, err
	}

	parsedAuthData, err := verifyAuthenticationAuthenticatorData(options.State, options.Response, options.Credential, options.ExtensionPolicy)
	if err != nil {
		return AuthenticationResult{}, err
	}
	authenticatorExtensions, err := decodeAuthenticationExtensions(options.Decoders, parsedAuthData)
	if err != nil {
		return AuthenticationResult{}, err
	}
	extensionResults, err := verifyAuthenticationExtensions(ctx, authenticationExtensionInputs{
		state:                   options.State,
		policy:                  options.ExtensionPolicy,
		registry:                options.ExtensionRegistry,
		clientExtensionResults:  options.Response.ClientExtensionResults,
		authenticatorExtensions: authenticatorExtensions,
	})
	if err != nil {
		return AuthenticationResult{}, err
	}

	if options.AlgorithmPolicy != nil && !options.AlgorithmPolicy.AcceptsAlgorithm(options.Credential.PublicKey.Algorithm) {
		return AuthenticationResult{}, ErrUnsupportedAlgorithm
	}
	if err := verifyAuthenticationSignature(ctx, options.SignatureVerifier, options.Credential, options.Response, clientDataHash); err != nil {
		return AuthenticationResult{}, err
	}

	counter := compareCounters(options.Credential.SignCount, parsedAuthData.SignCount)
	if counter.CloneRisk && options.CounterPolicy.RejectCloneRisk {
		return AuthenticationResult{}, ErrCloneRisk
	}

	credential := options.Credential
	credential.SignCount = parsedAuthData.SignCount

	return AuthenticationResult{
		Credential:      credential,
		AuthenticatedAs: credential.UserHandle,
		Counter:         counter,
		Update:          CredentialUpdate{ID: credential.ID, SignCount: parsedAuthData.SignCount},
		Extensions:      extensionResults,
		Warnings:        authenticationWarnings(counter),
	}, nil
}

func (o AuthenticationFinishOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}

	return time.Now()
}

func validateAuthenticationDependencies(options AuthenticationFinishOptions) error {
	if options.SignatureVerifier == nil {
		return errors.New("signature verifier is required")
	}
	if options.Credential.ID.Len() == 0 || options.Credential.UserHandle.Len() == 0 {
		return ErrCredentialNotAllowed
	}

	return nil
}

func validateAuthenticationState(state AuthenticationState, now time.Time) error {
	if state.Challenge.Len() == 0 || state.RPID == "" {
		return ErrMalformedResponse
	}
	if err := validateOrigins(state.AllowedOrigins); err != nil {
		return err
	}
	if !state.ExpiresAt.IsZero() && now.After(state.ExpiresAt) {
		return ErrCeremonyExpired
	}
	if err := validateUserVerification(state.RequestedUserVerification); err != nil {
		return err
	}

	return nil
}

func validateAuthenticationResponseShape(response AuthenticationResponse) error {
	if err := response.Type.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	if response.RawID.Bytes() == nil || response.ClientDataJSON.Bytes() == nil || response.AuthenticatorData.Bytes() == nil || response.Signature.Bytes() == nil {
		return ErrMalformedResponse
	}

	return nil
}

func verifyAuthenticationCredentialBinding(state AuthenticationState, response AuthenticationResponse, credential CredentialRecord) error {
	if !bytes.Equal(response.RawID.Bytes(), credential.ID.Bytes()) {
		return ErrCredentialNotAllowed
	}
	if len(state.AllowCredentials) == 0 {
		return nil
	}
	for _, descriptor := range state.AllowCredentials {
		if bytes.Equal(response.RawID.Bytes(), descriptor.ID.Bytes()) {
			return nil
		}
	}

	return ErrCredentialNotAllowed
}

func verifyAuthenticationUserBinding(state AuthenticationState, response AuthenticationResponse, credential CredentialRecord) error {
	expected := state.ExpectedUserHandle
	if expected.Len() != 0 {
		if !bytes.Equal(credential.UserHandle.Bytes(), expected.Bytes()) {
			return ErrCredentialOwnershipMismatch
		}
		if response.UserHandle.Len() != 0 && !bytes.Equal(response.UserHandle.Bytes(), expected.Bytes()) {
			return ErrCredentialOwnershipMismatch
		}

		return nil
	}
	if response.UserHandle.Len() == 0 {
		return ErrUserHandleRequired
	}
	if !bytes.Equal(response.UserHandle.Bytes(), credential.UserHandle.Bytes()) {
		return ErrCredentialOwnershipMismatch
	}

	return nil
}

func verifyAuthenticationClientData(state AuthenticationState, raw protocol.ClientDataJSON) (protocol.CollectedClientData, []byte, error) {
	clientData, err := protocol.ParseCollectedClientData(raw)
	if err != nil {
		return protocol.CollectedClientData{}, nil, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	if err := clientData.ValidateType(protocol.ClientDataTypeGet); err != nil {
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

func verifyAuthenticationAuthenticatorData(state AuthenticationState, response AuthenticationResponse, credential CredentialRecord, policy AuthenticationExtensionPolicy) (protocol.ParsedAuthenticatorData, error) {
	parsed, err := protocol.ParseAuthenticatorData(response.AuthenticatorData)
	if err != nil {
		return protocol.ParsedAuthenticatorData{}, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	if parsed.Flags.HasAttestedCredentialData() {
		return protocol.ParsedAuthenticatorData{}, ErrMalformedResponse
	}

	expectedRPIDHash := sha256.Sum256([]byte(state.RPID))
	if !bytes.Equal(parsed.RPIDHash, expectedRPIDHash[:]) {
		if !authenticationAppIDAllowed(state, response, policy, parsed.RPIDHash) {
			return protocol.ParsedAuthenticatorData{}, ErrRPIDHashMismatch
		}
	}
	if !parsed.Flags.UserPresent() {
		return protocol.ParsedAuthenticatorData{}, ErrUserPresenceRequired
	}
	if state.RequestedUserVerification == protocol.UserVerificationRequired && !parsed.Flags.UserVerified() {
		return protocol.ParsedAuthenticatorData{}, ErrUserVerificationRequired
	}
	if credential.PublicKey.Algorithm == 0 {
		return protocol.ParsedAuthenticatorData{}, ErrUnsupportedAlgorithm
	}

	return parsed, nil
}

func authenticationAppIDAllowed(state AuthenticationState, response AuthenticationResponse, policy AuthenticationExtensionPolicy, rpIDHash []byte) bool {
	if policy.AppID == "" {
		return false
	}
	requestedAppID, requested := state.RequestedExtensions[extension.IDAppID]
	if !requested {
		return false
	}
	appID, ok := requestedAppID.(string)
	if !ok || appID == "" || appID != policy.AppID {
		return false
	}
	used, ok := response.ClientExtensionResults[extension.IDAppID].(bool)
	if !ok || !used {
		return false
	}

	appIDHash := sha256.Sum256([]byte(policy.AppID))
	return bytes.Equal(rpIDHash, appIDHash[:])
}

func decodeAuthenticationExtensions(decoders codec.Decoders, parsed protocol.ParsedAuthenticatorData) (codec.ExtensionMap, error) {
	if !parsed.Flags.HasExtensionData() {
		return nil, nil
	}
	if decoders == nil {
		return nil, fmt.Errorf("%w: authentication decoders are required for authenticator extensions", ErrMalformedResponse)
	}

	extensions, err := decoders.DecodeExtensionMap(parsed.ExtensionData)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}

	return extensions, nil
}

type authenticationExtensionInputs struct {
	state                   AuthenticationState
	policy                  AuthenticationExtensionPolicy
	registry                *extension.Registry
	clientExtensionResults  map[string]any
	authenticatorExtensions codec.ExtensionMap
}

func verifyAuthenticationExtensions(ctx context.Context, inputs authenticationExtensionInputs) ([]extension.Result, error) {
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
			Operation:           extension.OperationAuthentication,
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

func verifyAuthenticationSignature(ctx context.Context, verifier webcrypto.SignatureVerifier, credential CredentialRecord, response AuthenticationResponse, clientDataHash []byte) error {
	signed := append(response.AuthenticatorData.Bytes(), clientDataHash...)
	if err := verifier.VerifySignature(ctx, webcrypto.SignatureInput{
		Algorithm: credential.PublicKey.Algorithm,
		PublicKey: credential.PublicKey.Key,
		Signed:    signed,
		Signature: response.Signature,
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	return nil
}

func compareCounters(stored uint32, new uint32) CounterResult {
	switch {
	case stored == 0 && new == 0:
		return CounterResult{Stored: stored, New: new, Status: CounterStatusUnsupported}
	case new > stored:
		return CounterResult{Stored: stored, New: new, Status: CounterStatusIncremented}
	default:
		return CounterResult{Stored: stored, New: new, Status: CounterStatusCloneRisk, CloneRisk: true}
	}
}

func authenticationWarnings(counter CounterResult) []string {
	if counter.CloneRisk {
		return []string{ErrCloneRisk.Error()}
	}

	return nil
}
