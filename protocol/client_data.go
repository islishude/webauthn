package protocol

import (
	"bytes"
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
		TokenBinding *TokenBinding  `json:"tokenBinding"`
	}

	// WebAuthn's UTF-8 decode step strips one leading byte-order mark for JSON
	// parsing. The original bytes remain in Raw and are still hashed verbatim by
	// the ceremony verifier.
	jsonText := bytes.TrimPrefix(raw.value, []byte{0xef, 0xbb, 0xbf})
	if err := json.Unmarshal(jsonText, &decoded); err != nil {
		return CollectedClientData{}, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(jsonText, &members); err != nil {
		return CollectedClientData{}, err
	}
	if decoded.Type == "" || decoded.Challenge == "" || decoded.Origin == "" {
		return CollectedClientData{}, ErrMalformedClientData
	}

	var crossOrigin *bool
	if rawCrossOrigin, present := members["crossOrigin"]; present {
		var value any
		if err := json.Unmarshal(rawCrossOrigin, &value); err != nil {
			return CollectedClientData{}, ErrMalformedClientData
		}
		boolean, ok := value.(bool)
		if !ok {
			return CollectedClientData{}, ErrMalformedClientData
		}
		crossOrigin = &boolean
	}

	var topOrigin string
	_, topOriginSet := members["topOrigin"]
	if topOriginSet {
		var value any
		if err := json.Unmarshal(members["topOrigin"], &value); err != nil {
			return CollectedClientData{}, ErrMalformedClientData
		}
		var ok bool
		topOrigin, ok = value.(string)
		if !ok || topOrigin == "" {
			return CollectedClientData{}, ErrMalformedClientData
		}
	}
	return CollectedClientData{
		Type:         decoded.Type,
		Challenge:    decoded.Challenge,
		Origin:       decoded.Origin,
		CrossOrigin:  crossOrigin,
		TopOrigin:    topOrigin,
		TokenBinding: decoded.TokenBinding,
		Raw:          raw,
		topOriginSet: topOriginSet,
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
