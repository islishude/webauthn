package webauthn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
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
	OriginPolicy       OriginPolicy
	Challenge          protocol.Challenge
	ChallengeGenerator ChallengeGenerator
	Timeout            time.Duration
	AllowCredentials   []protocol.CredentialDescriptor
	UserVerification   protocol.UserVerificationRequirement
	Hints              []protocol.PublicKeyCredentialHint
	Extensions         protocol.ExtensionInputs
	ExpectedUserHandle protocol.UserHandle
	Now                func() time.Time
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
	OriginPolicy              OriginPolicy
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
		return AuthenticationStartResult{}, fmt.Errorf("%w: rp id is required", ErrInvalidConfiguration)
	}
	if err := validateOriginPolicy(options.OriginPolicy); err != nil {
		return AuthenticationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}
	for _, descriptor := range options.AllowCredentials {
		if err := descriptor.Validate(); err != nil {
			return AuthenticationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
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
		return AuthenticationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}

	timeoutMilliseconds, expiresAt, err := timeoutState(options.Timeout, options.now())
	if err != nil {
		return AuthenticationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}

	requestOptions := protocol.PublicKeyCredentialRequestOptions{
		Challenge:           challenge,
		TimeoutMilliseconds: timeoutMilliseconds,
		RPID:                options.RPID,
		AllowCredentials:    cloneCredentialDescriptors(options.AllowCredentials),
		UserVerification:    userVerification,
		Hints:               slices.Clone(options.Hints),
		Extensions:          maps.Clone(options.Extensions),
	}
	if err := requestOptions.Validate(); err != nil {
		return AuthenticationStartResult{}, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}

	state := AuthenticationState{
		Challenge:                 challenge,
		RPID:                      options.RPID,
		OriginPolicy:              options.OriginPolicy.clone(),
		RequestedUserVerification: userVerification,
		RequestedExtensions:       maps.Clone(options.Extensions),
		AllowCredentials:          cloneCredentialDescriptors(options.AllowCredentials),
		ExpectedUserHandle:        options.ExpectedUserHandle,
		ExpiresAt:                 expiresAt,
	}

	return AuthenticationStartResult{Options: requestOptions, State: state}, nil
}

func (o AuthenticationStartOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}

	return time.Now()
}

// AuthenticationResponse is the structured, transport-neutral browser
// assertion response input.
type AuthenticationResponse struct {
	Type                    protocol.PublicKeyCredentialType
	RawID                   protocol.RawID
	ClientDataJSON          protocol.ClientDataJSON
	AuthenticatorData       protocol.AuthenticatorData
	Signature               protocol.Signature
	UserHandle              protocol.UserHandle
	AuthenticatorAttachment protocol.AuthenticatorAttachment
	ClientExtensionResults  map[string]any
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
	State               AuthenticationState
	Response            AuthenticationResponse
	Credential          CredentialRecord
	ExtensionMapDecoder codec.ExtensionMapDecoder
	SignatureVerifier   webcrypto.SignatureVerifier
	AlgorithmPolicy     webcrypto.AlgorithmPolicy
	ExtensionRegistry   *extension.Registry
	ExtensionPolicy     AuthenticationExtensionPolicy
	CounterPolicy       CounterPolicy
	Now                 func() time.Time
}

// CredentialUpdate is the persistence-ready credential update after
// authentication.
type CredentialUpdate struct {
	ID             protocol.CredentialID
	SignCount      uint32
	BackupEligible bool
	BackupState    bool
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
	authenticatorExtensions, err := decodeAuthenticationExtensions(options.ExtensionMapDecoder, parsedAuthData)
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
	credential.BackupEligible = parsedAuthData.Flags.BackupEligible()
	credential.BackupState = parsedAuthData.Flags.BackupState()
	if options.Response.AuthenticatorAttachment != "" {
		credential.AuthenticatorAttachment = options.Response.AuthenticatorAttachment
	}

	return AuthenticationResult{
		Credential:      credential,
		AuthenticatedAs: credential.UserHandle,
		Counter:         counter,
		Update: CredentialUpdate{
			ID:             credential.ID,
			SignCount:      parsedAuthData.SignCount,
			BackupEligible: parsedAuthData.Flags.BackupEligible(),
			BackupState:    parsedAuthData.Flags.BackupState(),
		},
		Extensions: extensionResults,
		Warnings:   authenticationWarnings(counter),
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
		return fmt.Errorf("%w: signature verifier is required", ErrInvalidConfiguration)
	}
	if options.Credential.ID.Len() == 0 || options.Credential.UserHandle.Len() == 0 {
		return ErrCredentialNotAllowed
	}

	return nil
}

func validateAuthenticationState(state AuthenticationState, now time.Time) error {
	if state.Challenge.Len() == 0 || state.RPID == "" {
		return ErrInvalidCeremonyState
	}
	if err := validateOriginPolicy(state.OriginPolicy); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
	}
	if !state.ExpiresAt.IsZero() && now.After(state.ExpiresAt) {
		return ErrCeremonyExpired
	}
	if err := validateUserVerification(state.RequestedUserVerification); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
	}

	return nil
}

func validateAuthenticationResponseShape(response AuthenticationResponse) error {
	if err := response.Type.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	if response.RawID.IsNil() || response.ClientDataJSON.IsNil() || response.AuthenticatorData.IsNil() || response.Signature.IsNil() {
		return ErrMalformedResponse
	}

	return nil
}

func verifyAuthenticationCredentialBinding(state AuthenticationState, response AuthenticationResponse, credential CredentialRecord) error {
	if !credential.ID.EqualRawID(response.RawID) {
		return ErrCredentialNotAllowed
	}
	if len(state.AllowCredentials) == 0 {
		return nil
	}
	for _, descriptor := range state.AllowCredentials {
		if descriptor.ID.EqualRawID(response.RawID) {
			return nil
		}
	}

	return ErrCredentialNotAllowed
}

func verifyAuthenticationUserBinding(state AuthenticationState, response AuthenticationResponse, credential CredentialRecord) error {
	expected := state.ExpectedUserHandle
	if expected.Len() != 0 {
		if !credential.UserHandle.Equal(expected) {
			return ErrCredentialOwnershipMismatch
		}
		if response.UserHandle.Len() != 0 && !response.UserHandle.Equal(expected) {
			return ErrCredentialOwnershipMismatch
		}

		return nil
	}
	if response.UserHandle.Len() == 0 {
		return ErrUserHandleRequired
	}
	if !response.UserHandle.Equal(credential.UserHandle) {
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
	if err := verifyCollectedClientOrigin(state.OriginPolicy, clientData); err != nil {
		return protocol.CollectedClientData{}, nil, err
	}

	hash := sha256.Sum256(raw.AppendTo(nil))
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

func decodeAuthenticationExtensions(decoder codec.ExtensionMapDecoder, parsed protocol.ParsedAuthenticatorData) (codec.ExtensionMap, error) {
	if !parsed.Flags.HasExtensionData() {
		return nil, nil
	}
	if decoder == nil {
		return nil, fmt.Errorf("%w: authentication extension map decoder is required for authenticator extensions", ErrInvalidConfiguration)
	}

	extensions, err := decoder.DecodeExtensionMap(parsed.ExtensionData)
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
	return verifyExtensions(ctx, extensionVerificationInputs{
		operation:               extension.OperationAuthentication,
		requestedExtensions:     inputs.state.RequestedExtensions,
		policy:                  extensionOutputPolicy{rejectUnrequested: inputs.policy.RejectUnrequested, rejectUnknown: inputs.policy.RejectUnknown},
		registry:                inputs.registry,
		clientExtensionResults:  inputs.clientExtensionResults,
		authenticatorExtensions: inputs.authenticatorExtensions,
		clientInputTransform: func(id string, clientInput any) any {
			if id == extension.IDPRF {
				return attachAllowedCredentialIDsToPRFInput(clientInput, inputs.state.AllowCredentials)
			}
			return clientInput
		},
	})
}

func attachAllowedCredentialIDsToPRFInput(input any, credentials []protocol.CredentialDescriptor) any {
	allowed := make([]string, len(credentials))
	for i, credential := range credentials {
		allowed[i] = base64.RawURLEncoding.EncodeToString(credential.ID.AppendTo(nil))
	}

	switch typed := input.(type) {
	case extension.PRFInput:
		typed.AllowCredentials = allowed
		return typed
	case map[string]any:
		out := maps.Clone(typed)
		out["allowCredentials"] = allowed
		return out
	default:
		return input
	}
}

func verifyAuthenticationSignature(ctx context.Context, verifier webcrypto.SignatureVerifier, credential CredentialRecord, response AuthenticationResponse, clientDataHash []byte) error {
	signed := response.AuthenticatorData.AppendTo(make([]byte, 0, response.AuthenticatorData.Len()+len(clientDataHash)))
	signed = append(signed, clientDataHash...)
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
