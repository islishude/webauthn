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

// HandleExtension validates AppID extension input and client output.
func (AppIDHandler) HandleExtension(_ context.Context, request Request) (Result, error) {
	if err := requireOperation(request, OperationAuthentication); err != nil {
		return Result{}, err
	}
	appID, err := requiredStringInput(request, IDAppID)
	if err != nil {
		return Result{}, err
	}
	if request.AuthenticatorOutput != nil {
		return Result{}, invalidRequest("appid has no authenticator output")
	}

	output := AppIDResult{AppID: appID}
	if request.ClientOutput == nil {
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
	AppID    string
	Excluded bool
}

// AppIDExcludeHandler validates the registration-only AppID exclusion extension.
type AppIDExcludeHandler struct{}

// ID returns "appidExclude".
func (AppIDExcludeHandler) ID() string {
	return IDAppIDExclude
}

// HandleExtension validates AppID exclusion input and client output.
func (AppIDExcludeHandler) HandleExtension(_ context.Context, request Request) (Result, error) {
	if err := requireOperation(request, OperationRegistration); err != nil {
		return Result{}, err
	}
	appID, err := requiredStringInput(request, IDAppIDExclude)
	if err != nil {
		return Result{}, err
	}
	if request.AuthenticatorOutput != nil {
		return Result{}, invalidRequest("appidExclude has no authenticator output")
	}

	output := AppIDExcludeResult{AppID: appID}
	if request.ClientOutput == nil {
		return Result{ID: IDAppIDExclude, Outputs: map[string]any{IDAppIDExclude: output}}, nil
	}

	excluded, ok := request.ClientOutput.(bool)
	if !ok {
		return Result{}, invalidRequest("appidExclude client output must be boolean")
	}
	output.Excluded = excluded

	return Result{ID: IDAppIDExclude, Accepted: true, Outputs: map[string]any{IDAppIDExclude: output}}, nil
}

// UVMEntry is one user verification method extension entry.
//
// Deprecated: The uvm extension is deprecated in WebAuthn Level 3.
type UVMEntry struct {
	UserVerificationMethod uint32
	KeyProtectionType      uint16
	MatcherProtectionType  uint16
}

// UVMResult is the parsed user verification method extension output.
//
// Deprecated: The uvm extension is deprecated in WebAuthn Level 3.
type UVMResult struct {
	Entries []UVMEntry
}

// UVMHandler validates the user verification method extension.
//
// Deprecated: The uvm extension is deprecated in WebAuthn Level 3.
type UVMHandler struct{}

// ID returns "uvm".
//
// Deprecated: The uvm extension is deprecated in WebAuthn Level 3.
func (UVMHandler) ID() string {
	return IDUVM
}

// HandleExtension validates and parses UVM client or authenticator output.
func (UVMHandler) HandleExtension(_ context.Context, request Request) (Result, error) {
	if err := requireOperation(request, OperationRegistration, OperationAuthentication); err != nil {
		return Result{}, err
	}
	if err := requiredTrueInput(request, IDUVM); err != nil {
		return Result{}, err
	}

	var entries []UVMEntry
	var haveOutput bool
	if request.ClientOutput != nil {
		parsed, err := parseUVMEntries(request.ClientOutput)
		if err != nil {
			return Result{}, err
		}
		entries = parsed
		haveOutput = true
	}
	if request.AuthenticatorOutput != nil {
		parsed, err := parseUVMEntries(request.AuthenticatorOutput)
		if err != nil {
			return Result{}, err
		}
		if haveOutput && !uvmEntriesEqual(entries, parsed) {
			return Result{}, invalidRequest("uvm client and authenticator outputs differ")
		}
		entries = parsed
		haveOutput = true
	}

	output := UVMResult{Entries: cloneUVMEntries(entries)}
	return Result{ID: IDUVM, Accepted: haveOutput, Deprecated: true, Outputs: map[string]any{IDUVM: output}}, nil
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

// HandleExtension validates and parses credential properties output.
func (CredPropsHandler) HandleExtension(_ context.Context, request Request) (Result, error) {
	if err := requireOperation(request, OperationRegistration); err != nil {
		return Result{}, err
	}
	if err := requiredTrueInput(request, IDCredProps); err != nil {
		return Result{}, err
	}
	if request.AuthenticatorOutput != nil {
		return Result{}, invalidRequest("credProps has no authenticator output")
	}

	if request.ClientOutput == nil {
		return Result{ID: IDCredProps, Outputs: map[string]any{IDCredProps: CredentialPropertiesResult{}}}, nil
	}
	output, err := parseCredentialPropertiesOutput(request.ClientOutput)
	if err != nil {
		return Result{}, err
	}

	return Result{ID: IDCredProps, Accepted: true, Outputs: map[string]any{IDCredProps: output}}, nil
}

// LargeBlobSupport identifies registration-time large blob support policy.
type LargeBlobSupport string

const (
	// LargeBlobSupportRequired requires a large-blob-capable authenticator.
	LargeBlobSupportRequired LargeBlobSupport = "required"
	// LargeBlobSupportPreferred asks for large blob support when available.
	LargeBlobSupportPreferred LargeBlobSupport = "preferred"
)

// LargeBlobInput is a typed largeBlob client extension input.
type LargeBlobInput struct {
	Support LargeBlobSupport
	Read    *bool
	Write   []byte
}

// LargeBlobResult is the parsed largeBlob input and output.
type LargeBlobResult struct {
	Support   LargeBlobSupport
	Read      *bool
	Write     []byte
	Supported *bool
	Blob      []byte
	Written   *bool
}

// LargeBlobHandler validates the large blob extension.
type LargeBlobHandler struct{}

// ID returns "largeBlob".
func (LargeBlobHandler) ID() string {
	return IDLargeBlob
}

// HandleExtension validates and parses largeBlob input and client output.
func (LargeBlobHandler) HandleExtension(_ context.Context, request Request) (Result, error) {
	if err := requireOperation(request, OperationRegistration, OperationAuthentication); err != nil {
		return Result{}, err
	}
	if !request.Requested {
		return Result{}, invalidRequest("largeBlob must be requested")
	}
	input, presence, err := parseLargeBlobInput(request.ClientInput)
	if err != nil {
		return Result{}, err
	}
	if request.AuthenticatorOutput != nil {
		return Result{}, invalidRequest("largeBlob has no authenticator output")
	}
	if err := validateLargeBlobInput(request.Operation, input, presence); err != nil {
		return Result{}, err
	}

	output := largeBlobResultFromInput(input)
	if request.ClientOutput == nil {
		return Result{ID: IDLargeBlob, Outputs: map[string]any{IDLargeBlob: output}}, nil
	}
	if err := parseLargeBlobOutput(request.Operation, input, presence, request.ClientOutput, &output); err != nil {
		return Result{}, err
	}

	return Result{ID: IDLargeBlob, Accepted: true, Outputs: map[string]any{IDLargeBlob: output}}, nil
}

type largeBlobInputPresence struct {
	support bool
	read    bool
	write   bool
}

type largeBlobOutputPresence struct {
	supported bool
	blob      bool
	written   bool
}

func requireOperation(request Request, allowed ...Operation) error {
	if slices.Contains(allowed, request.Operation) {
		return nil
	}

	return fmt.Errorf("%w: %s for %s", ErrInvalidOperation, request.ID, request.Operation)
}

func requiredStringInput(request Request, id string) (string, error) {
	if !request.Requested {
		return "", invalidRequest(id + " must be requested")
	}
	value, ok := request.ClientInput.(string)
	if !ok || value == "" {
		return "", invalidRequest(id + " input must be a non-empty string")
	}

	return value, nil
}

func requiredTrueInput(request Request, id string) error {
	if !request.Requested {
		return invalidRequest(id + " must be requested")
	}
	value, ok := request.ClientInput.(bool)
	if !ok || !value {
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

func parseUVMEntries(value any) ([]UVMEntry, error) {
	if entries, ok := value.([]UVMEntry); ok {
		if err := validateUVMEntryCount(len(entries)); err != nil {
			return nil, err
		}

		return cloneUVMEntries(entries), nil
	}
	if result, ok := value.(UVMResult); ok {
		if err := validateUVMEntryCount(len(result.Entries)); err != nil {
			return nil, err
		}

		return cloneUVMEntries(result.Entries), nil
	}

	rawEntries, ok := anySlice(value)
	if !ok {
		return nil, invalidRequest("uvm output must be an array")
	}
	if err := validateUVMEntryCount(len(rawEntries)); err != nil {
		return nil, err
	}

	entries := make([]UVMEntry, len(rawEntries))
	for i, rawEntry := range rawEntries {
		values, ok := anySlice(rawEntry)
		if !ok || len(values) != 3 {
			return nil, invalidRequest("uvm entry must contain three integers")
		}
		method, ok := unsignedValue(values[0], math.MaxUint32)
		if !ok {
			return nil, invalidRequest("uvm method must be uint32")
		}
		keyProtection, ok := unsignedValue(values[1], math.MaxUint16)
		if !ok {
			return nil, invalidRequest("uvm key protection must be uint16")
		}
		matcherProtection, ok := unsignedValue(values[2], math.MaxUint16)
		if !ok {
			return nil, invalidRequest("uvm matcher protection must be uint16")
		}
		entries[i] = UVMEntry{
			UserVerificationMethod: uint32(method),            //nolint:gosec // method is bounded by math.MaxUint32 above.
			KeyProtectionType:      uint16(keyProtection),     //nolint:gosec // keyProtection is bounded by math.MaxUint16 above.
			MatcherProtectionType:  uint16(matcherProtection), //nolint:gosec // matcherProtection is bounded by math.MaxUint16 above.
		}
	}

	return entries, nil
}

func validateUVMEntryCount(count int) error {
	if count < 1 || count > 3 {
		return invalidRequest("uvm output must contain one to three entries")
	}

	return nil
}

func parseLargeBlobInput(value any) (LargeBlobInput, largeBlobInputPresence, error) {
	switch input := value.(type) {
	case LargeBlobInput:
		return cloneLargeBlobInput(input), largeBlobInputPresence{
			support: input.Support != "",
			read:    input.Read != nil,
			write:   input.Write != nil,
		}, nil
	case map[string]any, map[string]string, map[string]bool:
		fields, _ := objectFields(value)
		return largeBlobInputFromFields(fields)
	default:
		if value == nil {
			return LargeBlobInput{}, largeBlobInputPresence{}, invalidRequest("largeBlob input must be an object")
		}

		return LargeBlobInput{}, largeBlobInputPresence{}, invalidRequest("largeBlob input must be an object")
	}
}

func largeBlobInputFromFields(fields map[string]any) (LargeBlobInput, largeBlobInputPresence, error) {
	var input LargeBlobInput
	var presence largeBlobInputPresence

	if raw, ok := fields["support"]; ok {
		support, ok := raw.(string)
		if !ok {
			return LargeBlobInput{}, largeBlobInputPresence{}, invalidRequest("largeBlob support must be a string")
		}
		input.Support = LargeBlobSupport(support)
		presence.support = true
	}
	if raw, ok := fields["read"]; ok {
		read, ok := raw.(bool)
		if !ok {
			return LargeBlobInput{}, largeBlobInputPresence{}, invalidRequest("largeBlob read must be boolean")
		}
		input.Read = boolPtr(read)
		presence.read = true
	}
	if raw, ok := fields["write"]; ok {
		write, ok := raw.([]byte)
		if !ok {
			return LargeBlobInput{}, largeBlobInputPresence{}, invalidRequest("largeBlob write must be bytes")
		}
		input.Write = slices.Clone(write)
		presence.write = true
	}

	return input, presence, nil
}

func validateLargeBlobInput(operation Operation, input LargeBlobInput, presence largeBlobInputPresence) error {
	if presence.support && input.Support != LargeBlobSupportRequired && input.Support != LargeBlobSupportPreferred {
		return invalidRequest("largeBlob support must be required or preferred")
	}

	switch operation {
	case OperationRegistration:
		if presence.read || presence.write {
			return invalidRequest("largeBlob read and write are authentication-only inputs")
		}
	case OperationAuthentication:
		if presence.support {
			return invalidRequest("largeBlob support is registration-only input")
		}
		if presence.read && presence.write {
			return invalidRequest("largeBlob read and write are mutually exclusive")
		}
	}

	return nil
}

func parseLargeBlobOutput(operation Operation, input LargeBlobInput, presence largeBlobInputPresence, value any, output *LargeBlobResult) error {
	var outputPresence largeBlobOutputPresence
	if typed, ok := value.(LargeBlobResult); ok {
		typed = cloneLargeBlobResult(typed)
		outputPresence = largeBlobOutputPresence{
			supported: typed.Supported != nil,
			blob:      typed.Blob != nil,
			written:   typed.Written != nil,
		}
		typed.Support = output.Support
		typed.Read = cloneBoolPtr(output.Read)
		typed.Write = slices.Clone(output.Write)
		*output = typed
		return validateLargeBlobOutput(operation, input, presence, outputPresence, output)
	}

	fields, ok := objectFields(value)
	if !ok {
		return invalidRequest("largeBlob client output must be an object")
	}
	if raw, ok := fields["supported"]; ok {
		supported, ok := raw.(bool)
		if !ok {
			return invalidRequest("largeBlob supported must be boolean")
		}
		output.Supported = boolPtr(supported)
		outputPresence.supported = true
	}
	if raw, ok := fields["blob"]; ok {
		blob, ok := raw.([]byte)
		if !ok {
			return invalidRequest("largeBlob blob must be bytes")
		}
		output.Blob = slices.Clone(blob)
		outputPresence.blob = true
	}
	if raw, ok := fields["written"]; ok {
		written, ok := raw.(bool)
		if !ok {
			return invalidRequest("largeBlob written must be boolean")
		}
		output.Written = boolPtr(written)
		outputPresence.written = true
	}

	return validateLargeBlobOutput(operation, input, presence, outputPresence, output)
}

func validateLargeBlobOutput(operation Operation, input LargeBlobInput, inputPresence largeBlobInputPresence, outputPresence largeBlobOutputPresence, output *LargeBlobResult) error {
	switch operation {
	case OperationRegistration:
		if outputPresence.blob || outputPresence.written {
			return invalidRequest("largeBlob blob and written are authentication-only outputs")
		}
		if inputPresence.support && input.Support == LargeBlobSupportRequired && outputPresence.supported && output.Supported != nil && !*output.Supported {
			return invalidRequest("largeBlob required support was not provided")
		}
	case OperationAuthentication:
		if outputPresence.supported {
			return invalidRequest("largeBlob supported is registration-only output")
		}
		readRequested := inputPresence.read && input.Read != nil && *input.Read
		if outputPresence.blob && !readRequested {
			return invalidRequest("largeBlob blob requires read input")
		}
		if outputPresence.written && !inputPresence.write {
			return invalidRequest("largeBlob written requires write input")
		}
	}

	return nil
}

func largeBlobResultFromInput(input LargeBlobInput) LargeBlobResult {
	return LargeBlobResult{
		Support: input.Support,
		Read:    cloneBoolPtr(input.Read),
		Write:   slices.Clone(input.Write),
	}
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

func cloneUVMEntries(entries []UVMEntry) []UVMEntry {
	return slices.Clone(entries)
}

func uvmEntriesEqual(a []UVMEntry, b []UVMEntry) bool {
	return slices.Equal(a, b)
}

func cloneLargeBlobInput(input LargeBlobInput) LargeBlobInput {
	return LargeBlobInput{
		Support: input.Support,
		Read:    cloneBoolPtr(input.Read),
		Write:   slices.Clone(input.Write),
	}
}

func cloneLargeBlobResult(input LargeBlobResult) LargeBlobResult {
	return LargeBlobResult{
		Support:   input.Support,
		Read:      cloneBoolPtr(input.Read),
		Write:     slices.Clone(input.Write),
		Supported: cloneBoolPtr(input.Supported),
		Blob:      slices.Clone(input.Blob),
		Written:   cloneBoolPtr(input.Written),
	}
}
