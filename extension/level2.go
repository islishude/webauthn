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
func Level2Handlers() []Handler {
	return []Handler{
		AppIDHandler{},
		AppIDExcludeHandler{},
		UVMHandler{},
		CredPropsHandler{},
		LargeBlobHandler{},
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
func (AppIDHandler) ValidateInput(request InputRequest) (any, error) {
	if err := requireInputOperation(request, OperationAuthentication); err != nil {
		return nil, err
	}
	return requiredStringValue(request.Input, IDAppID)
}

// VerifyOutput validates AppID client output after core verification.
func (handler AppIDHandler) VerifyOutput(_ context.Context, request OutputRequest) (Result, error) {
	if err := requireOperation(request, OperationAuthentication); err != nil {
		return Result{}, err
	}
	if !request.Requested {
		return Result{}, invalidRequest(IDAppID + " must be requested")
	}
	normalized, err := handler.ValidateInput(InputRequest{Operation: request.Operation, ID: request.ID, Input: request.ClientInput})
	if err != nil {
		return Result{}, err
	}
	appID := normalized.(string)
	if hasAuthenticatorOutput(request) {
		return Result{}, invalidRequest("appid has no authenticator output")
	}

	output := AppIDResult{AppID: appID}
	if !hasClientOutput(request) {
		return Result{ID: IDAppID, Outputs: map[string]any{IDAppID: output}}, nil
	}

	used, ok := request.ClientOutput.(bool)
	if !ok {
		return Result{}, invalidRequest("appid client output must be boolean")
	}
	output.Used = used

	return Result{ID: IDAppID, Accepted: true, Outputs: map[string]any{IDAppID: output}}, nil
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
func (AppIDExcludeHandler) ValidateInput(request InputRequest) (any, error) {
	if err := requireInputOperation(request, OperationRegistration); err != nil {
		return nil, err
	}
	return requiredStringValue(request.Input, IDAppIDExclude)
}

// VerifyOutput validates AppID exclusion client output after core verification.
func (handler AppIDExcludeHandler) VerifyOutput(_ context.Context, request OutputRequest) (Result, error) {
	if err := requireOperation(request, OperationRegistration); err != nil {
		return Result{}, err
	}
	if !request.Requested {
		return Result{}, invalidRequest(IDAppIDExclude + " must be requested")
	}
	normalized, err := handler.ValidateInput(InputRequest{Operation: request.Operation, ID: request.ID, Input: request.ClientInput})
	if err != nil {
		return Result{}, err
	}
	appID := normalized.(string)
	if hasAuthenticatorOutput(request) {
		return Result{}, invalidRequest("appidExclude has no authenticator output")
	}

	output := AppIDExcludeResult{AppID: appID}
	if !hasClientOutput(request) {
		return Result{ID: IDAppIDExclude, Outputs: map[string]any{IDAppIDExclude: output}}, nil
	}

	actedUpon, ok := request.ClientOutput.(bool)
	if !ok || !actedUpon {
		return Result{}, invalidRequest("appidExclude client output must be true")
	}
	output.ActedUpon = actedUpon

	return Result{ID: IDAppIDExclude, Accepted: true, Outputs: map[string]any{IDAppIDExclude: output}}, nil
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
func (CredPropsHandler) ValidateInput(request InputRequest) (any, error) {
	if err := requireInputOperation(request, OperationRegistration); err != nil {
		return nil, err
	}
	if err := requiredTrueValue(request.Input, IDCredProps); err != nil {
		return nil, err
	}
	return true, nil
}

// VerifyOutput validates and parses credential properties output after core verification.
func (handler CredPropsHandler) VerifyOutput(_ context.Context, request OutputRequest) (Result, error) {
	if err := requireOperation(request, OperationRegistration); err != nil {
		return Result{}, err
	}
	if !request.Requested {
		return Result{}, invalidRequest(IDCredProps + " must be requested")
	}
	if _, err := handler.ValidateInput(InputRequest{Operation: request.Operation, ID: request.ID, Input: request.ClientInput}); err != nil {
		return Result{}, err
	}
	if hasAuthenticatorOutput(request) {
		return Result{}, invalidRequest("credProps has no authenticator output")
	}

	if !hasClientOutput(request) {
		return Result{ID: IDCredProps, Outputs: map[string]any{IDCredProps: CredentialPropertiesResult{}}}, nil
	}
	output, err := parseCredentialPropertiesOutput(request.ClientOutput)
	if err != nil {
		return Result{}, err
	}

	return Result{ID: IDCredProps, Accepted: true, Outputs: map[string]any{IDCredProps: output}}, nil
}

func requireOperation(request OutputRequest, allowed ...Operation) error {
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
