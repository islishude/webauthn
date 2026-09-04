package extension

import (
	"context"
	"math"
	"slices"
)

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

// Revision returns the built-in semantic revision.
//
// Deprecated: The uvm extension is deprecated in WebAuthn Level 3.
func (UVMHandler) Revision() string {
	return RevisionLevel3Recommendation
}

// ValidateInput validates UVM input at ceremony start.
func (UVMHandler) ValidateInput(request InputRequest) (bool, error) {
	if err := requireInputOperation(request, OperationRegistration, OperationAuthentication); err != nil {
		return false, err
	}
	input, err := rawValue(request.Input)
	if err != nil {
		return false, err
	}
	if err := requiredTrueValue(input, IDUVM); err != nil {
		return false, err
	}
	return true, nil
}

// VerifyOutput validates and parses UVM output after core verification.
func (UVMHandler) VerifyOutput(_ context.Context, request OutputRequest[bool]) (Verification[UVMResult], error) {
	if err := requireOperation(request, OperationRegistration, OperationAuthentication); err != nil {
		return Verification[UVMResult]{}, err
	}
	if !request.Requested {
		return Verification[UVMResult]{}, invalidRequest(IDUVM + " must be requested")
	}

	var entries []UVMEntry
	var haveOutput bool
	if hasClientOutput(request) {
		raw, err := request.ClientOutput.Clone()
		if err != nil {
			return Verification[UVMResult]{}, err
		}
		parsed, err := parseUVMEntries(raw)
		if err != nil {
			return Verification[UVMResult]{}, err
		}
		entries = parsed
		haveOutput = true
	}
	if hasAuthenticatorOutput(request) {
		raw, err := request.AuthenticatorOutput.Clone()
		if err != nil {
			return Verification[UVMResult]{}, err
		}
		parsed, err := parseUVMEntries(raw)
		if err != nil {
			return Verification[UVMResult]{}, err
		}
		if haveOutput && !uvmEntriesEqual(entries, parsed) {
			return Verification[UVMResult]{}, invalidRequest("uvm client and authenticator outputs differ")
		}
		entries = parsed
		haveOutput = true
	}

	output := UVMResult{Entries: cloneUVMEntries(entries)}
	return Verification[UVMResult]{Accepted: haveOutput, Deprecated: true, Output: output}, nil
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
			UserVerificationMethod: uint32(method),            //nolint:gosec // bounded above.
			KeyProtectionType:      uint16(keyProtection),     //nolint:gosec // bounded above.
			MatcherProtectionType:  uint16(matcherProtection), //nolint:gosec // bounded above.
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

func cloneUVMEntries(entries []UVMEntry) []UVMEntry {
	return slices.Clone(entries)
}

func uvmEntriesEqual(a []UVMEntry, b []UVMEntry) bool {
	return slices.Equal(a, b)
}
