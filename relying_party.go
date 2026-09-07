package webauthn

import (
	"context"
	"fmt"
	"slices"

	"github.com/islishude/webauthn/protocol"
)

// RegistrationRequest contains per-ceremony registration data.
type RegistrationRequest struct {
	// User is required. Its handle must be a stable, opaque account identifier.
	User protocol.UserEntity
	// ExcludeCredentials lists credentials already associated with the account.
	ExcludeCredentials []protocol.CredentialDescriptor
	// Extensions and Hints are optional, and are copied by the ceremony builder.
	Extensions protocol.ExtensionInputs
	Hints      []protocol.PublicKeyCredentialHint
	// ConditionalMediation requires a capability check and a matching outer browser option.
	ConditionalMediation bool
}

// AuthenticationRequest contains per-ceremony authentication data.
type AuthenticationRequest struct {
	// Empty AllowCredentials enables discoverable credential authentication.
	AllowCredentials []protocol.CredentialDescriptor
	// ExpectedUserHandle binds username-first authentication; leave zero for discoverable login.
	ExpectedUserHandle protocol.UserHandle
	Extensions         protocol.ExtensionInputs
	Hints              []protocol.PublicKeyCredentialHint
}

// RegistrationVerification contains a browser response and trusted, single-use state.
type RegistrationVerification struct {
	State    RegistrationState
	Response RegistrationResponse
}

// AuthenticationVerification contains the assertion, stored credential and single-use state.
type AuthenticationVerification struct {
	State      AuthenticationState
	Response   AuthenticationResponse
	Credential CredentialRecord
	// UVInitializationAuthorized requires authorization by an additional authentication factor.
	UVInitializationAuthorized bool
}

// StartRegistration creates options and state for the caller to store and consume once.
func (rp *RelyingParty) StartRegistration(ctx context.Context, request RegistrationRequest) (RegistrationStartResult, error) {
	if rp == nil || !rp.ready {
		return RegistrationStartResult{}, ErrInvalidConfiguration
	}
	c := rp.config
	return StartRegistration(ctx, RegistrationStartOptions{
		RP: c.RP, OriginPolicy: c.OriginPolicy, User: request.User,
		ChallengeGenerator: c.ChallengeGenerator, Timeout: c.Timeout, StateTTL: c.StateTTL, Now: c.Now,
		PubKeyCredParams: c.PubKeyCredParams, AuthenticatorSelection: c.Registration.AuthenticatorSelection,
		Attestation: c.Registration.Attestation, AttestationFormats: c.Registration.AttestationFormats,
		ExtensionRegistry: c.ExtensionRegistry, ExtensionInputPolicy: c.Registration.ExtensionInputPolicy,
		ExcludeCredentials: request.ExcludeCredentials, Extensions: request.Extensions, Hints: request.Hints,
		ConditionalMediation: request.ConditionalMediation,
	})
}

// FinishRegistration verifies state/configuration agreement and delegates protocol verification.
// Insert the returned credential atomically under a unique credential ID constraint.
func (rp *RelyingParty) FinishRegistration(ctx context.Context, request RegistrationVerification) (RegistrationResult, error) {
	if rp == nil || !rp.ready {
		return RegistrationResult{}, ErrInvalidConfiguration
	}
	c, s := rp.config, request.State
	if !rp.matchesOrigin(s.RPID, s.OriginPolicy) || s.RequestedUserVerification != registrationUserVerification(c.Registration.AuthenticatorSelection) || !slices.Equal(s.AllowedAlgorithms, rp.algorithms) || s.Attestation != c.Registration.Attestation {
		return RegistrationResult{}, fmt.Errorf("%w: state does not match relying party configuration", ErrInvalidCeremonyState)
	}
	return FinishRegistration(ctx, RegistrationFinishOptions{
		State: s, Response: request.Response, Now: c.Now,
		AttestationObjectDecoder: c.AttestationObjectDecoder, CredentialPublicKeyDecoder: c.CredentialPublicKeyDecoder,
		ExtensionMapDecoder: c.ExtensionMapDecoder, AttestationRegistry: c.AttestationRegistry,
		AttestationTrustPolicy: c.AttestationTrustPolicy, ExtensionRegistry: c.ExtensionRegistry,
		ExtensionPolicy: c.Registration.ExtensionPolicy,
	})
}

// StartAuthentication creates options and single-use state. Empty allow credentials
// and user handle select discoverable login; the response handle is only a lookup hint until verified.
func (rp *RelyingParty) StartAuthentication(ctx context.Context, request AuthenticationRequest) (AuthenticationStartResult, error) {
	if rp == nil || !rp.ready {
		return AuthenticationStartResult{}, ErrInvalidConfiguration
	}
	c := rp.config
	return StartAuthentication(ctx, AuthenticationStartOptions{
		RPID: c.RP.ID, OriginPolicy: c.OriginPolicy, ChallengeGenerator: c.ChallengeGenerator,
		Timeout: c.Timeout, StateTTL: c.StateTTL, Now: c.Now,
		UserVerification: c.Authentication.UserVerification, ExtensionRegistry: c.ExtensionRegistry,
		ExtensionInputPolicy: c.Authentication.ExtensionInputPolicy, AllowCredentials: request.AllowCredentials,
		ExpectedUserHandle: request.ExpectedUserHandle, Extensions: request.Extensions, Hints: request.Hints,
	})
}

// FinishAuthentication returns verified identity and a conditional credential update.
// Persist that update successfully before creating an application session.
func (rp *RelyingParty) FinishAuthentication(ctx context.Context, request AuthenticationVerification) (AuthenticationResult, error) {
	if rp == nil || !rp.ready {
		return AuthenticationResult{}, ErrInvalidConfiguration
	}
	c, s := rp.config, request.State
	if !rp.matchesOrigin(s.RPID, s.OriginPolicy) || s.RequestedUserVerification != c.Authentication.UserVerification {
		return AuthenticationResult{}, fmt.Errorf("%w: state does not match relying party configuration", ErrInvalidCeremonyState)
	}
	if !slices.Contains(rp.algorithms, request.Credential.PublicKey.Algorithm) {
		return AuthenticationResult{}, ErrUnsupportedAlgorithm
	}
	return FinishAuthentication(ctx, AuthenticationFinishOptions{
		State: s, Response: request.Response, Credential: request.Credential, Now: c.Now,
		SignatureVerifier: c.SignatureVerifier, AlgorithmPolicy: c.AlgorithmPolicy, ExtensionMapDecoder: c.ExtensionMapDecoder,
		ExtensionRegistry: c.ExtensionRegistry, ExtensionPolicy: c.Authentication.ExtensionPolicy,
		CounterPolicy: c.Authentication.CounterPolicy, UVInitializationAuthorized: request.UVInitializationAuthorized,
	})
}

func (rp *RelyingParty) matchesOrigin(id string, policy OriginPolicy) bool {
	c := rp.config
	return id == c.RP.ID && slices.Equal(policy.AllowedOrigins, c.OriginPolicy.AllowedOrigins) &&
		slices.Equal(policy.AllowedTopOrigins, c.OriginPolicy.AllowedTopOrigins) &&
		policy.AllowRelatedOrigins == c.OriginPolicy.AllowRelatedOrigins &&
		policy.AllowCrossOriginWithoutTopOrigin == c.OriginPolicy.AllowCrossOriginWithoutTopOrigin
}
