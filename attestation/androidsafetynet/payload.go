package androidsafetynet

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

func validatePayload(raw []byte, expectedNonce string) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrInvalidPayload
	}

	nonce, ok := payload["nonce"].(string)
	if !ok || nonce == "" {
		return ErrInvalidPayload
	}
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(expectedNonce)) != 1 {
		return ErrInvalidNonce
	}

	ctsProfileMatch, ok := payload["ctsProfileMatch"].(bool)
	if !ok || !ctsProfileMatch {
		return ErrInvalidPayload
	}

	timestamp, ok := payload["timestampMs"].(json.Number)
	if !ok {
		return ErrInvalidPayload
	}
	if _, err := strconv.ParseInt(timestamp.String(), 10, 64); err != nil {
		return ErrInvalidPayload
	}

	return nil
}
