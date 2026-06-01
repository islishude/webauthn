package webauthn

import (
	"errors"
	"slices"

	"github.com/islishude/webauthn/protocol"
)

// OriginPolicy defines the origins accepted for a ceremony.
type OriginPolicy struct {
	// AllowedOrigins are accepted CollectedClientData.origin values.
	AllowedOrigins []string
	// AllowedTopOrigins are accepted CollectedClientData.topOrigin values.
	AllowedTopOrigins []string
	// AllowCrossOriginWithoutTopOrigin accepts legacy cross-origin client data
	// that does not include topOrigin.
	AllowCrossOriginWithoutTopOrigin bool
}

func (p OriginPolicy) clone() OriginPolicy {
	return OriginPolicy{
		AllowedOrigins:                   slices.Clone(p.AllowedOrigins),
		AllowedTopOrigins:                slices.Clone(p.AllowedTopOrigins),
		AllowCrossOriginWithoutTopOrigin: p.AllowCrossOriginWithoutTopOrigin,
	}
}

func validateOriginPolicy(policy OriginPolicy) error {
	if len(policy.AllowedOrigins) == 0 {
		return errors.New("allowed origins are required")
	}
	if slices.Contains(policy.AllowedOrigins, "") {
		return errors.New("allowed origins must not contain empty values")
	}
	if slices.Contains(policy.AllowedTopOrigins, "") {
		return errors.New("allowed top origins must not contain empty values")
	}

	return nil
}

func verifyCollectedClientOrigin(policy OriginPolicy, clientData protocol.CollectedClientData) error {
	if !slices.Contains(policy.AllowedOrigins, clientData.Origin) {
		return ErrOriginMismatch
	}

	crossOrigin := clientData.CrossOrigin != nil && *clientData.CrossOrigin
	if clientData.TopOrigin != "" {
		if !crossOrigin {
			return ErrOriginMismatch
		}
		if !slices.Contains(policy.AllowedTopOrigins, clientData.TopOrigin) {
			return ErrOriginMismatch
		}

		return nil
	}

	if crossOrigin && !policy.AllowCrossOriginWithoutTopOrigin {
		return ErrOriginMismatch
	}

	return nil
}
