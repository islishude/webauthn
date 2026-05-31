package protocol

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
)

var (
	// ErrMalformedClientData reports collected client data that cannot be
	// decoded or is missing fields required by WebAuthn ceremonies.
	ErrMalformedClientData = errors.New("malformed client data")
)

// ParseCollectedClientData decodes browser-provided clientDataJSON while
// preserving the original serialized bytes for hashing.
func ParseCollectedClientData(raw ClientDataJSON) (CollectedClientData, error) {
	var decoded struct {
		Type         ClientDataType `json:"type"`
		Challenge    string         `json:"challenge"`
		Origin       string         `json:"origin"`
		CrossOrigin  *bool          `json:"crossOrigin"`
		TokenBinding *TokenBinding  `json:"tokenBinding"`
	}

	if err := json.Unmarshal(raw.Bytes(), &decoded); err != nil {
		return CollectedClientData{}, err
	}
	if decoded.Type == "" || decoded.Challenge == "" || decoded.Origin == "" {
		return CollectedClientData{}, ErrMalformedClientData
	}
	if decoded.TokenBinding != nil {
		switch decoded.TokenBinding.Status {
		case TokenBindingPresent:
			if decoded.TokenBinding.ID == "" {
				return CollectedClientData{}, ErrMalformedClientData
			}
		case TokenBindingSupported:
		default:
			return CollectedClientData{}, ErrMalformedClientData
		}
	}

	return CollectedClientData{
		Type:         decoded.Type,
		Challenge:    decoded.Challenge,
		Origin:       decoded.Origin,
		CrossOrigin:  decoded.CrossOrigin,
		TokenBinding: decoded.TokenBinding,
		Raw:          raw,
	}, nil
}

// ChallengeBytes decodes the collected client data challenge using unpadded
// base64url, as used by browser WebAuthn client data.
func (d CollectedClientData) ChallengeBytes() ([]byte, error) {
	challenge, err := base64.RawURLEncoding.DecodeString(d.Challenge)
	if err != nil {
		return nil, err
	}

	return slices.Clone(challenge), nil
}
