package webauthn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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
	// ErrInvalidConfiguration reports missing or invalid caller configuration.
	ErrInvalidConfiguration = errors.New("webauthn: invalid configuration")
	// ErrInvalidCeremonyState reports missing or invalid caller-stored ceremony
	// state.
	ErrInvalidCeremonyState = errors.New("webauthn: invalid ceremony state")
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
	// ErrCeremonyExpired reports ceremony state at or past its expiry.
	ErrCeremonyExpired = errors.New("webauthn: registration ceremony expired")
	// ErrDuplicateCredential reports an application-provided uniqueness failure.
	ErrDuplicateCredential = errors.New("webauthn: credential already registered")
	// ErrInvalidBackupState reports a backup-state flag without backup eligibility.
	ErrInvalidBackupState = errors.New("webauthn: invalid credential backup state")
	// ErrBackupEligibilityMismatch reports an authentication-time BE flag change.
	ErrBackupEligibilityMismatch = errors.New("webauthn: credential backup eligibility mismatch")
	// ErrCredentialRPIDMismatch reports use of a credential outside its stored RP ID.
	ErrCredentialRPIDMismatch = errors.New("webauthn: credential rp id mismatch")
)

const (
	// DefaultCeremonyTimeout is used when callers leave Timeout at its zero value.
	DefaultCeremonyTimeout = 5 * time.Minute
)

// RegistrationResponse is the structured, transport-neutral browser
// registration response input.
type RegistrationResponse struct {
	Type                    protocol.PublicKeyCredentialType
	RawID                   protocol.RawID
	ClientDataJSON          protocol.ClientDataJSON
	AuthenticatorData       protocol.AuthenticatorData
	AttestationObject       protocol.AttestationObject
	PublicKey               []byte
	PublicKeyAlgorithm      protocol.COSEAlgorithmIdentifier
	Transports              []protocol.AuthenticatorTransport
	AuthenticatorAttachment protocol.AuthenticatorAttachment
	ClientExtensionResults  map[string]any
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
	AttestationObjectDecoder    codec.AttestationObjectDecoder
	CredentialPublicKeyDecoder  codec.COSEKeyDecoder
	ExtensionMapDecoder         codec.ExtensionMapDecoder
	AttestationRegistry         *attestation.Registry
	AttestationTrustPolicy      attestation.TrustPolicy
	ExtensionRegistry           *extension.Registry
	ExtensionPolicy             RegistrationExtensionPolicy
	CredentialAlreadyRegistered bool
	Now                         func() time.Time
}

// CredentialRecord is storage-neutral credential material returned after
// registration verification.
type CredentialRecord struct {
	ID                      protocol.CredentialID
	PublicKey               codec.CredentialPublicKey
	UserHandle              protocol.UserHandle
	RPID                    string
	AAGUID                  protocol.AAGUID
	SignCount               uint32
	Transports              []protocol.AuthenticatorTransport
	BackupEligible          bool
	BackupState             bool
	UVInitialized           bool
	AuthenticatorAttachment protocol.AuthenticatorAttachment
	AttestationType         attestation.Type
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

	_, clientDataHash, err := verifyRegistrationClientData(options.State, options.Response.ClientDataJSON)
	if err != nil {
		return RegistrationResult{}, err
	}

	decodedAttestation, err := options.AttestationObjectDecoder.DecodeAttestationObject(options.Response.AttestationObject)
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}

	if !options.Response.AuthenticatorData.IsNil() && !options.Response.AuthenticatorData.Equal(decodedAttestation.AuthenticatorData) {
		return RegistrationResult{}, ErrMalformedResponse
	}

	parsedAuthData, err := verifyRegistrationAuthenticatorData(options.State, decodedAttestation.AuthenticatorData)
	if err != nil {
		return RegistrationResult{}, err
	}
	attested := parsedAuthData.AttestedCredentialData
	if attested == nil {
		return RegistrationResult{}, fmt.Errorf("%w: %w", ErrMalformedResponse, protocol.ErrAttestedCredentialDataMissing)
	}
	if !attested.CredentialID.EqualRawID(options.Response.RawID) {
		return RegistrationResult{}, ErrMalformedResponse
	}

	credentialPublicKey, authenticatorExtensions, err := decodeCredentialPublicKeyAndExtensions(options.CredentialPublicKeyDecoder, options.ExtensionMapDecoder, parsedAuthData, *attested)
	if err != nil {
		return RegistrationResult{}, err
	}
	if !slices.Contains(options.State.AllowedAlgorithms, credentialPublicKey.Algorithm) {
		return RegistrationResult{}, ErrUnsupportedAlgorithm
	}
	if options.Response.PublicKeyAlgorithm != 0 && options.Response.PublicKeyAlgorithm != credentialPublicKey.Algorithm {
		return RegistrationResult{}, ErrMalformedResponse
	}

	attestationResult, trustResult, err := verifyRegistrationAttestation(ctx, registrationAttestationInputs{
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

	result := RegistrationResult{
		Credential: CredentialRecord{
			ID:                      attested.CredentialID,
			PublicKey:               credentialPublicKey,
			UserHandle:              options.State.UserHandle,
			RPID:                    options.State.RPID,
			AAGUID:                  attested.AAGUID,
			SignCount:               parsedAuthData.SignCount,
			Transports:              slices.Clone(options.Response.Transports),
			BackupEligible:          parsedAuthData.Flags.BackupEligible(),
			BackupState:             parsedAuthData.Flags.BackupState(),
			UVInitialized:           parsedAuthData.Flags.UserVerified(),
			AuthenticatorAttachment: options.Response.AuthenticatorAttachment,
			AttestationType:         attestationResult.Type,
		},
		Attestation:      attestationResult,
		AttestationTrust: trustResult,
		Extensions:       extensionResults,
		Warnings:         slices.Concat(attestationResult.Warnings, trustResult.Warnings),
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
	if options.AttestationObjectDecoder == nil {
		return fmt.Errorf("%w: registration attestation object decoder is required", ErrInvalidConfiguration)
	}
	if options.CredentialPublicKeyDecoder == nil {
		return fmt.Errorf("%w: registration credential public key decoder is required", ErrInvalidConfiguration)
	}
	if options.AttestationRegistry == nil {
		return fmt.Errorf("%w: attestation registry is required", ErrInvalidConfiguration)
	}

	return nil
}

func validateRegistrationState(state RegistrationState, now time.Time) error {
	if state.Challenge.Len() == 0 || state.RPID == "" {
		return ErrInvalidCeremonyState
	}
	if err := validateOriginPolicy(state.OriginPolicy); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
	}
	if state.UserHandle.Len() == 0 {
		return fmt.Errorf("%w: user handle is required", ErrInvalidCeremonyState)
	}
	if !state.ExpiresAt.IsZero() && !now.Before(state.ExpiresAt) {
		return ErrCeremonyExpired
	}
	if len(state.AllowedAlgorithms) == 0 {
		return fmt.Errorf("%w: allowed algorithms are required", ErrInvalidCeremonyState)
	}
	if err := validateUserVerification(state.RequestedUserVerification); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCeremonyState, err)
	}

	return nil
}

func validateRegistrationResponseShape(response RegistrationResponse) error {
	if err := response.Type.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	if response.RawID.IsNil() || response.ClientDataJSON.IsNil() || response.AttestationObject.IsNil() {
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
	if err := verifyCollectedClientOrigin(state.OriginPolicy, clientData); err != nil {
		return protocol.CollectedClientData{}, nil, err
	}

	hash := sha256.Sum256(raw.AppendTo(nil))
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
	if parsed.Flags.BackupState() && !parsed.Flags.BackupEligible() {
		return protocol.ParsedAuthenticatorData{}, ErrInvalidBackupState
	}
	if !parsed.Flags.HasAttestedCredentialData() {
		return protocol.ParsedAuthenticatorData{}, fmt.Errorf("%w: %w", ErrMalformedResponse, protocol.ErrAttestedCredentialDataMissing)
	}

	return parsed, nil
}

func decodeCredentialPublicKeyAndExtensions(keyDecoder codec.COSEKeyDecoder, extensionDecoder codec.ExtensionMapDecoder, parsed protocol.ParsedAuthenticatorData, attested protocol.AttestedCredentialData) (codec.CredentialPublicKey, codec.ExtensionMap, error) {
	publicKey, err := keyDecoder.DecodeCredentialPublicKey(attested.CredentialPublicKeyAndExtensions)
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

	if extensionDecoder == nil {
		return codec.CredentialPublicKey{}, nil, fmt.Errorf("%w: registration extension map decoder is required for authenticator extensions", ErrInvalidConfiguration)
	}
	extensions, err := extensionDecoder.DecodeExtensionMap(extensionBytes)
	if err != nil {
		return codec.CredentialPublicKey{}, nil, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}

	return publicKey, extensions, nil
}

type registrationAttestationInputs struct {
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
	if inputs.trustPolicy == nil {
		return attestation.VerificationResult{}, AttestationTrustResult{}, ErrRejectedAttestationPolicy
	}
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
