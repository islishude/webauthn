package browser

import (
	"encoding/json/jsontext"

	"github.com/islishude/webauthn/extension"
)

// ExtensionJSON retains each browser extension as encoded JSON until its
// format-specific conversion. The representation preserves absent and null
// fields without allowing arbitrary Go objects in a wire DTO.
type ExtensionJSON map[string]jsontext.Value

// PRFValuesJSON is the browser representation of PRF byte values.
type PRFValuesJSON struct {
	First  string  `json:"first"`
	Second *string `json:"second,omitzero"`
}

// PRFInputJSON is the browser prf input dictionary.
type PRFInputJSON struct {
	Eval             *PRFValuesJSON            `json:"eval,omitzero"`
	EvalByCredential *map[string]PRFValuesJSON `json:"evalByCredential,omitzero"`
}

// LargeBlobInputJSON is the browser largeBlob input dictionary. Pointers retain
// explicitly false reads and empty writes.
type LargeBlobInputJSON struct {
	Support extension.LargeBlobSupport `json:"support,omitempty"`
	Read    *bool                      `json:"read,omitzero"`
	Write   *string                    `json:"write,omitzero"`
}
