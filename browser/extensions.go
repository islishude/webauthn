package browser

import (
	"encoding/json"

	"github.com/islishude/webauthn/extension"
)

// ExtensionJSON retains each browser extension as encoded JSON until its
// format-specific conversion. The representation preserves absent and null
// fields without allowing arbitrary Go objects in a wire DTO.
type ExtensionJSON map[string]json.RawMessage

// PRFValuesJSON is the browser representation of PRF byte values.
type PRFValuesJSON struct {
	First  string  `json:"first"`
	Second *string `json:"second,omitempty"`
}

// PRFInputJSON is the browser prf input dictionary.
type PRFInputJSON struct {
	Eval             *PRFValuesJSON            `json:"eval,omitempty"`
	EvalByCredential *map[string]PRFValuesJSON `json:"evalByCredential,omitempty"`
}

// LargeBlobInputJSON is the browser largeBlob input dictionary. Pointers retain
// explicitly false reads and empty writes.
type LargeBlobInputJSON struct {
	Support extension.LargeBlobSupport `json:"support,omitempty"`
	Read    *bool                      `json:"read,omitempty"`
	Write   *string                    `json:"write,omitempty"`
}
