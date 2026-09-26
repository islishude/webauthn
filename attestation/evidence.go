package attestation

import "github.com/islishude/webauthn/internal/interfaceutil"

// Evidence is format-specific verified information with an explicit copy
// contract. Concrete types belong to their optional format packages so the
// registry never imports those packages. Copies must not share mutable data.
type Evidence interface{ CloneEvidence() Evidence }

func cloneEvidence(value Evidence) Evidence {
	if interfaceutil.IsNil(value) {
		return nil
	}
	return value.CloneEvidence()
}

// EvidenceAs retrieves an independent, typed copy of format evidence.
func EvidenceAs[T Evidence](value Evidence) (T, bool) {
	cloned := cloneEvidence(value)
	typed, ok := cloned.(T)
	return typed, ok
}
