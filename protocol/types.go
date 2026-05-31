package protocol

import (
	"errors"
	"fmt"
)

// ErrUnsupportedValue marks a DOMString value that is not accepted at a
// validation boundary.
var ErrUnsupportedValue = errors.New("unsupported protocol value")

// ValueError reports an unsupported protocol value.
type ValueError struct {
	Field string
	Value string
}

func (e ValueError) Error() string {
	return fmt.Sprintf("%s has unsupported value %q", e.Field, e.Value)
}

func (e ValueError) Unwrap() error {
	return ErrUnsupportedValue
}

// PublicKeyCredentialType is the WebAuthn credential type DOMString.
type PublicKeyCredentialType string

const (
	// CredentialTypePublicKey is the only credential type accepted by WebAuthn.
	CredentialTypePublicKey PublicKeyCredentialType = "public-key"
)

// Known reports whether the value is known by this package.
func (t PublicKeyCredentialType) Known() bool {
	return t == CredentialTypePublicKey
}

// Validate rejects unknown credential types at protocol validation boundaries.
func (t PublicKeyCredentialType) Validate() error {
	if !t.Known() {
		return ValueError{Field: "credential type", Value: string(t)}
	}

	return nil
}

// AuthenticatorTransport is a credential transport hint.
type AuthenticatorTransport string

const (
	TransportUSB      AuthenticatorTransport = "usb"
	TransportNFC      AuthenticatorTransport = "nfc"
	TransportBLE      AuthenticatorTransport = "ble"
	TransportInternal AuthenticatorTransport = "internal"
)

// Known reports whether the value is known by this package.
func (t AuthenticatorTransport) Known() bool {
	switch t {
	case TransportUSB, TransportNFC, TransportBLE, TransportInternal:
		return true
	default:
		return false
	}
}

// AttestationConveyancePreference is the RP's requested attestation conveyance.
type AttestationConveyancePreference string

const (
	AttestationNone       AttestationConveyancePreference = "none"
	AttestationIndirect   AttestationConveyancePreference = "indirect"
	AttestationDirect     AttestationConveyancePreference = "direct"
	AttestationEnterprise AttestationConveyancePreference = "enterprise"
)

// Known reports whether the value is known by this package.
func (p AttestationConveyancePreference) Known() bool {
	switch p {
	case AttestationNone, AttestationIndirect, AttestationDirect, AttestationEnterprise:
		return true
	default:
		return false
	}
}

// UserVerificationRequirement is the RP's user verification preference.
type UserVerificationRequirement string

const (
	UserVerificationRequired    UserVerificationRequirement = "required"
	UserVerificationPreferred   UserVerificationRequirement = "preferred"
	UserVerificationDiscouraged UserVerificationRequirement = "discouraged"
)

// Known reports whether the value is known by this package.
func (r UserVerificationRequirement) Known() bool {
	switch r {
	case UserVerificationRequired, UserVerificationPreferred, UserVerificationDiscouraged:
		return true
	default:
		return false
	}
}

// AuthenticatorAttachment is the RP's authenticator attachment preference.
type AuthenticatorAttachment string

const (
	AuthenticatorAttachmentPlatform      AuthenticatorAttachment = "platform"
	AuthenticatorAttachmentCrossPlatform AuthenticatorAttachment = "cross-platform"
)

// Known reports whether the value is known by this package.
func (a AuthenticatorAttachment) Known() bool {
	switch a {
	case AuthenticatorAttachmentPlatform, AuthenticatorAttachmentCrossPlatform:
		return true
	default:
		return false
	}
}

// ResidentKeyRequirement is the discoverable credential preference.
type ResidentKeyRequirement string

const (
	ResidentKeyDiscouraged ResidentKeyRequirement = "discouraged"
	ResidentKeyPreferred   ResidentKeyRequirement = "preferred"
	ResidentKeyRequired    ResidentKeyRequirement = "required"
)

// Known reports whether the value is known by this package.
func (r ResidentKeyRequirement) Known() bool {
	switch r {
	case ResidentKeyDiscouraged, ResidentKeyPreferred, ResidentKeyRequired:
		return true
	default:
		return false
	}
}

// COSEAlgorithmIdentifier identifies a COSE signing algorithm.
type COSEAlgorithmIdentifier int64

// CredentialParameter describes an accepted public-key algorithm.
type CredentialParameter struct {
	Type      PublicKeyCredentialType
	Algorithm COSEAlgorithmIdentifier
}

// Validate rejects credential parameter values that WebAuthn cannot use.
func (p CredentialParameter) Validate() error {
	return p.Type.Validate()
}

// RPEntity is the relying-party entity dictionary.
type RPEntity struct {
	ID   string
	Name string
}

// Validate checks fields required by the RP entity dictionary.
func (e RPEntity) Validate() error {
	if e.ID == "" {
		return errors.New("rp id is required")
	}
	if e.Name == "" {
		return errors.New("rp name is required")
	}

	return nil
}

// UserEntity is the public-key credential user entity dictionary.
type UserEntity struct {
	ID          UserHandle
	Name        string
	DisplayName string
}

// Validate checks fields required by the user entity dictionary.
func (e UserEntity) Validate() error {
	if e.ID.Len() == 0 {
		return errors.New("user id is required")
	}
	if e.Name == "" {
		return errors.New("user name is required")
	}
	if e.DisplayName == "" {
		return errors.New("user display name is required")
	}

	return nil
}

// CredentialDescriptor identifies a credential and optional transport hints.
type CredentialDescriptor struct {
	Type       PublicKeyCredentialType
	ID         CredentialID
	Transports []AuthenticatorTransport
}

// Validate checks fields required by the credential descriptor dictionary.
func (d CredentialDescriptor) Validate() error {
	if err := d.Type.Validate(); err != nil {
		return err
	}
	if d.ID.Len() == 0 {
		return errors.New("credential id is required")
	}

	return nil
}

// AuthenticatorSelectionCriteria describes authenticator selection preferences.
type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment AuthenticatorAttachment
	ResidentKey             ResidentKeyRequirement
	RequireResidentKey      bool
	UserVerification        UserVerificationRequirement
}

// ExtensionInputs preserves client extension inputs by identifier.
type ExtensionInputs map[string]any

// PublicKeyCredentialCreationOptions is the core creation options model before
// any browser JSON transport encoding.
type PublicKeyCredentialCreationOptions struct {
	RP                     RPEntity
	User                   UserEntity
	Challenge              Challenge
	PubKeyCredParams       []CredentialParameter
	TimeoutMilliseconds    uint32
	ExcludeCredentials     []CredentialDescriptor
	AuthenticatorSelection *AuthenticatorSelectionCriteria
	Attestation            AttestationConveyancePreference
	Extensions             ExtensionInputs
}

// Validate checks the required WebAuthn creation option fields.
func (o PublicKeyCredentialCreationOptions) Validate() error {
	if err := o.RP.Validate(); err != nil {
		return err
	}
	if err := o.User.Validate(); err != nil {
		return err
	}
	if o.Challenge.Len() == 0 {
		return errors.New("challenge is required")
	}
	if len(o.PubKeyCredParams) == 0 {
		return errors.New("public key credential parameters are required")
	}
	for _, param := range o.PubKeyCredParams {
		if err := param.Validate(); err != nil {
			return err
		}
	}
	for _, descriptor := range o.ExcludeCredentials {
		if err := descriptor.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// PublicKeyCredentialRequestOptions is the core assertion options model before
// any browser JSON transport encoding.
type PublicKeyCredentialRequestOptions struct {
	Challenge           Challenge
	TimeoutMilliseconds uint32
	RPID                string
	AllowCredentials    []CredentialDescriptor
	UserVerification    UserVerificationRequirement
	Extensions          ExtensionInputs
}

// Validate checks the required WebAuthn request option fields.
func (o PublicKeyCredentialRequestOptions) Validate() error {
	if o.Challenge.Len() == 0 {
		return errors.New("challenge is required")
	}
	for _, descriptor := range o.AllowCredentials {
		if err := descriptor.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// ClientDataType is the collected client data type value.
type ClientDataType string

const (
	ClientDataTypeCreate ClientDataType = "webauthn.create"
	ClientDataTypeGet    ClientDataType = "webauthn.get"
)

// Known reports whether the value is known by this package.
func (t ClientDataType) Known() bool {
	switch t {
	case ClientDataTypeCreate, ClientDataTypeGet:
		return true
	default:
		return false
	}
}

// TokenBindingStatus is the collected client data token binding status.
type TokenBindingStatus string

const (
	TokenBindingPresent   TokenBindingStatus = "present"
	TokenBindingSupported TokenBindingStatus = "supported"
)

// TokenBinding is the collected client data token binding member.
type TokenBinding struct {
	Status TokenBindingStatus
	ID     string
}

// CollectedClientData is the decoded client data structure together with the
// raw clientDataJSON bytes that produced it.
type CollectedClientData struct {
	Type         ClientDataType
	Challenge    string
	Origin       string
	CrossOrigin  *bool
	TokenBinding *TokenBinding
	Raw          ClientDataJSON
}

// ValidateType checks the ceremony type at verification boundaries.
func (d CollectedClientData) ValidateType(expected ClientDataType) error {
	if d.Type != expected {
		return ValueError{Field: "client data type", Value: string(d.Type)}
	}

	return nil
}
