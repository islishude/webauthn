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
		Type         ClientDataType  `json:"type"`
		Challenge    string          `json:"challenge"`
		Origin       string          `json:"origin"`
		CrossOrigin  json.RawMessage `json:"crossOrigin"`
		TopOrigin    json.RawMessage `json:"topOrigin"`
		TokenBinding *TokenBinding   `json:"tokenBinding"`
	}

	// WebAuthn's UTF-8 decode step strips one leading byte-order mark for JSON
	// parsing. The original bytes remain in Raw and are still hashed verbatim by
	// the ceremony verifier.
	jsonText := bytes.TrimPrefix(raw.value, []byte{0xef, 0xbb, 0xbf})
	if err := json.Unmarshal(jsonText, &decoded); err != nil {
		return CollectedClientData{}, err
	}
	if decoded.Type == "" || decoded.Challenge == "" || decoded.Origin == "" {
		return CollectedClientData{}, ErrMalformedClientData
	}

	var crossOrigin *bool
	if decoded.CrossOrigin != nil {
		if bytes.Equal(bytes.TrimSpace(decoded.CrossOrigin), []byte("null")) {
			return CollectedClientData{}, ErrMalformedClientData
		}
		var boolean bool
		if err := json.Unmarshal(decoded.CrossOrigin, &boolean); err != nil {
			return CollectedClientData{}, ErrMalformedClientData
		}
		crossOrigin = &boolean
	}

	var topOrigin string
	topOriginSet := decoded.TopOrigin != nil
	if topOriginSet {
		if bytes.Equal(bytes.TrimSpace(decoded.TopOrigin), []byte("null")) {
			return CollectedClientData{}, ErrMalformedClientData
		}
		if err := json.Unmarshal(decoded.TopOrigin, &topOrigin); err != nil || topOrigin == "" {
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
	encoding := base64.RawURLEncoding.Strict()
	challenge, err := encoding.DecodeString(d.Challenge)
	if err != nil {
		return nil, err
	}
	if encoding.EncodeToString(challenge) != d.Challenge {
		return nil, ErrMalformedClientData
	}

	return slices.Clone(challenge), nil
}
