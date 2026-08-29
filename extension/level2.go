package extension

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
)

const (
	// IDAppID is the FIDO AppID extension identifier.
	IDAppID = "appid"
	// IDAppIDExclude is the FIDO AppID exclusion extension identifier.
	IDAppIDExclude = "appidExclude"
	// IDUVM is the user verification method extension identifier.
	IDUVM = "uvm"
	// IDCredProps is the credential properties extension identifier.
	IDCredProps = "credProps"
	// IDLargeBlob is the large blob extension identifier.
	IDLargeBlob = "largeBlob"
)

// Level2Handlers returns handlers for WebAuthn Level 2 defined extensions.
func Level2Handlers() []HandlerEntry {
	return []HandlerEntry{
		Register(AppIDHandler{}),
		Register(AppIDExcludeHandler{}),
		Register(UVMHandler{}),
		Register(CredPropsHandler{}),
		Register(LargeBlobHandler{}),
	}
}

// NewLevel2Registry builds a registry with WebAuthn Level 2 defined extensions.
func NewLevel2Registry() (*Registry, error) {
	return NewRegistry(Level2Handlers()...)
}

// AppIDResult is the parsed FIDO AppID extension result.
type AppIDResult struct {
	AppID string
	Used  bool
}

// AppIDHandler validates the authentication-only FIDO AppID extension.
type AppIDHandler struct{}

// ID returns "appid".
func (AppIDHandler) ID() string {
	return IDAppID
}

// ValidateInput validates AppID extension input at ceremony start.
func (AppIDHandler) ValidateInput(request InputRequest) (string, error) {
	if err := requireInputOperation(request, OperationAuthentication); err != nil {
		return "", err
	}
	input, err := rawValue(request.Input)
	if err != nil {
		return "", err
	}
	return requiredStringValue(input, IDAppID)
}

// VerifyOutput validates AppID client output after core verification.
func (AppIDHandler) VerifyOutput(_ context.Context, request OutputRequest[string]) (Verification[AppIDResult], error) {
	if err := requireOperation(request, OperationAuthentication); err != nil {
		return Verification[AppIDResult]{}, err
	}
	if !request.Requested {
		return Verification[AppIDResult]{}, invalidRequest(IDAppID + " must be requested")
	}
	if hasAuthenticatorOutput(request) {
		return Verification[AppIDResult]{}, invalidRequest("appid has no authenticator output")
	}

	output := AppIDResult{AppID: request.ClientInput}
	if !hasClientOutput(request) {
		return Verification[AppIDResult]{Output: output}, nil
	}

	used, ok := As[bool](request.ClientOutput)
	if !ok {
		return Verification[AppIDResult]{}, invalidRequest("appid client output must be boolean")
	}
	output.Used = used

	return Verification[AppIDResult]{Accepted: true, Output: output}, nil
}

// AppIDExcludeResult is the parsed FIDO AppID exclusion extension result.
type AppIDExcludeResult struct {
	AppID string
	// ActedUpon reports that the client processed appidExclude. A successful
	// registration response cannot mean that a matching credential was found.
	ActedUpon bool
}

// AppIDExcludeHandler validates the registration-only AppID exclusion extension.
type AppIDExcludeHandler struct{}

// ID returns "appidExclude".
func (AppIDExcludeHandler) ID() string {
	return IDAppIDExclude
}

// ValidateInput validates AppID exclusion input at ceremony start.
func (AppIDExcludeHandler) ValidateInput(request InputRequest) (string, error) {
	if err := requireInputOperation(request, OperationRegistration); err != nil {
		return "", err
	}
	input, err := rawValue(request.Input)
	if err != nil {
		return "", err
	}
	return requiredStringValue(input, IDAppIDExclude)
}

// VerifyOutput validates AppID exclusion client output after core verification.
func (AppIDExcludeHandler) VerifyOutput(_ context.Context, request OutputRequest[string]) (Verification[AppIDExcludeResult], error) {
	if err := requireOperation(request, OperationRegistration); err != nil {
		return Verification[AppIDExcludeResult]{}, err
	}
	if !request.Requested {
		return Verification[AppIDExcludeResult]{}, invalidRequest(IDAppIDExclude + " must be requested")
	}
	if hasAuthenticatorOutput(request) {
		return Verification[AppIDExcludeResult]{}, invalidRequest("appidExclude has no authenticator output")
	}

	output := AppIDExcludeResult{AppID: request.ClientInput}
	if !hasClientOutput(request) {
		return Verification[AppIDExcludeResult]{Output: output}, nil
	}

	actedUpon, ok := As[bool](request.ClientOutput)
	if !ok || !actedUpon {
		return Verification[AppIDExcludeResult]{}, invalidRequest("appidExclude client output must be true")
	}
	output.ActedUpon = actedUpon

	return Verification[AppIDExcludeResult]{Accepted: true, Output: output}, nil
}

// CredentialPropertiesResult is the parsed credential properties output.
type CredentialPropertiesResult struct {
	ResidentKey *bool
}

// CredPropsHandler validates the registration-only credential properties extension.
type CredPropsHandler struct{}

// ID returns "credProps".
func (CredPropsHandler) ID() string {
	return IDCredProps
}

// ValidateInput validates credential properties input at ceremony start.
func (CredPropsHandler) ValidateInput(request InputRequest) (bool, error) {
	if err := requireInputOperation(request, OperationRegistration); err != nil {
		return false, err
	}
	input, err := rawValue(request.Input)
	if err != nil {
		return false, err
	}
	if err := requiredTrueValue(input, IDCredProps); err != nil {
		return false, err
	}
	return true, nil
}

// VerifyOutput validates and parses credential properties output after core verification.
func (CredPropsHandler) VerifyOutput(_ context.Context, request OutputRequest[bool]) (Verification[CredentialPropertiesResult], error) {
	if err := requireOperation(request, OperationRegistration); err != nil {
		return Verification[CredentialPropertiesResult]{}, err
	}
	if !request.Requested {
		return Verification[CredentialPropertiesResult]{}, invalidRequest(IDCredProps + " must be requested")
	}
	if hasAuthenticatorOutput(request) {
		return Verification[CredentialPropertiesResult]{}, invalidRequest("credProps has no authenticator output")
	}

	if !hasClientOutput(request) {
		return Verification[CredentialPropertiesResult]{Output: CredentialPropertiesResult{}}, nil
	}
	raw, err := request.ClientOutput.Clone()
	if err != nil {
		return Verification[CredentialPropertiesResult]{}, err
	}
	output, err := parseCredentialPropertiesOutput(raw)
	if err != nil {
		return Verification[CredentialPropertiesResult]{}, err
	}

	return Verification[CredentialPropertiesResult]{Accepted: true, Output: output}, nil
}

func requireOperation[I any](request OutputRequest[I], allowed ...Operation) error {
	if slices.Contains(allowed, request.Operation) {
		return nil
	}

	return fmt.Errorf("%w: %s for %s", ErrInvalidOperation, request.ID, request.Operation)
}

func requireInputOperation(request InputRequest, allowed ...Operation) error {
	if slices.Contains(allowed, request.Operation) {
		return nil
	}
	return fmt.Errorf("%w: %s for %s", ErrInvalidOperation, request.ID, request.Operation)
}

func requiredStringValue(value any, id string) (string, error) {
	out, ok := value.(string)
	if !ok || out == "" {
		return "", invalidRequest(id + " input must be a non-empty string")
	}
	return out, nil
}

func requiredTrueValue(value any, id string) error {
	truth, ok := value.(bool)
	if !ok || !truth {
		return invalidRequest(id + " input must be true")
	}
	return nil
}

func invalidRequest(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, reason)
}

func parseCredentialPropertiesOutput(value any) (CredentialPropertiesResult, error) {
	if output, ok := value.(CredentialPropertiesResult); ok {
		return CredentialPropertiesResult{ResidentKey: cloneBoolPtr(output.ResidentKey)}, nil
	}
	fields, ok := objectFields(value)
	if !ok {
		return CredentialPropertiesResult{}, invalidRequest("credProps client output must be an object")
	}

	var output CredentialPropertiesResult
	if raw, ok := fields["rk"]; ok {
		residentKey, ok := raw.(bool)
		if !ok {
			return CredentialPropertiesResult{}, invalidRequest("credProps rk must be boolean")
		}
		output.ResidentKey = boolPtr(residentKey)
	}

	return output, nil
}

func objectFields(value any) (map[string]any, bool) {
	switch fields := value.(type) {
	case map[string]any:
		return fields, true
	case map[string]string:
		out := make(map[string]any, len(fields))
		for key, value := range fields {
			out[key] = value
		}
		return out, true
	case map[string]bool:
		out := make(map[string]any, len(fields))
		for key, value := range fields {
			out[key] = value
		}
		return out, true
	default:
		return nil, false
	}
}

func anySlice(value any) ([]any, bool) {
	switch values := value.(type) {
	case []any:
		return values, true
	case []uint:
		return sliceToAny(values), true
	case []uint8:
		return sliceToAny(values), true
	case []uint16:
		return sliceToAny(values), true
	case []uint32:
		return sliceToAny(values), true
	case []uint64:
		return sliceToAny(values), true
	case []int:
		return sliceToAny(values), true
	case []int64:
		return sliceToAny(values), true
	case []float64:
		return sliceToAny(values), true
	default:
		return nil, false
	}
}

func sliceToAny[T cmp.Ordered](values []T) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func unsignedValue(value any, max uint64) (uint64, bool) {
	switch n := value.(type) {
	case uint:
		return unsignedInRange(uint64(n), max)
	case uint8:
		return unsignedInRange(uint64(n), max)
	case uint16:
		return unsignedInRange(uint64(n), max)
	case uint32:
		return unsignedInRange(uint64(n), max)
	case uint64:
		return unsignedInRange(n, max)
	case int:
		if n < 0 {
			return 0, false
		}
		return unsignedInRange(uint64(n), max)
	case int64:
		if n < 0 {
			return 0, false
		}
		return unsignedInRange(uint64(n), max)
	case float64:
		if n < 0 || math.Trunc(n) != n || n > float64(max) {
			return 0, false
		}
		return uint64(n), true
	default:
		return 0, false
	}
}

func unsignedInRange(value uint64, max uint64) (uint64, bool) {
	if value > max {
		return 0, false
	}

	return value, true
}

func boolPtr(value bool) *bool {
	out := value
	return &out
}

func cloneBoolPtr(value *bool) *bool {
	if value == nil {
		return nil
	}

	return boolPtr(*value)
}
