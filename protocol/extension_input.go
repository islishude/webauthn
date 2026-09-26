package protocol

// ExtensionInput is a client extension input with an explicit defensive-copy
// contract. Implementations must return an independent copy of mutable data.
// Built-in structured inputs live in extension; unknown wire values use its
// explicit RawInput adapter.
type ExtensionInput interface {
	CloneExtensionInput() (ExtensionInput, error)
}

// BoolInput is a boolean client extension input.
type BoolInput bool

// CloneExtensionInput returns this immutable value.
func (v BoolInput) CloneExtensionInput() (ExtensionInput, error) { return v, nil }

// StringInput is a string client extension input.
type StringInput string

// CloneExtensionInput returns this immutable value.
func (v StringInput) CloneExtensionInput() (ExtensionInput, error) { return v, nil }
