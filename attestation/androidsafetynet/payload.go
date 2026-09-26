package androidsafetynet

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/islishude/webauthn/attestation"
)

// Evidence contains verified SafetyNet application and integrity claims.
type Evidence struct {
	Version              string
	Timestamp            time.Time
	APKPackageName       string
	APKCertificateSHA256 [][]byte
	CTSProfileMatch      bool
	BasicIntegrity       bool
}

// CloneEvidence returns an independent copy of the verified claims.
func (e Evidence) CloneEvidence() attestation.Evidence {
	e.APKCertificateSHA256 = slices.Clone(e.APKCertificateSHA256)
	for i := range e.APKCertificateSHA256 {
		e.APKCertificateSHA256[i] = slices.Clone(e.APKCertificateSHA256[i])
	}
	return e
}

func validatePayload(raw []byte, expectedNonce string, version string, policy Policy) (Evidence, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// Index exact claim names; struct decoding would also accept case variants.
	var payload map[string]json.RawMessage
	if err := decoder.Decode(&payload); err != nil {
		return Evidence{}, fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return Evidence{}, ErrInvalidPayload
	}
	if len(policy.AllowedVersions) != 0 && !slices.Contains(policy.AllowedVersions, version) {
		return Evidence{}, ErrInvalidPayload
	}
	nonce, err := payloadClaim[string](payload["nonce"])
	if err != nil || nonce == "" {
		return Evidence{}, ErrInvalidPayload
	}
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(expectedNonce)) != 1 {
		return Evidence{}, ErrInvalidNonce
	}
	cts, ctsPresent, err := booleanPayloadClaim(payload, "ctsProfileMatch")
	if err != nil {
		return Evidence{}, err
	}
	if policy.RequireCTSProfileMatch && (!ctsPresent || !cts) {
		return Evidence{}, ErrInvalidPayload
	}
	basic, basicPresent, err := booleanPayloadClaim(payload, "basicIntegrity")
	if err != nil {
		return Evidence{}, err
	}
	if policy.RequireBasicIntegrity && (!basicPresent || !basic) {
		return Evidence{}, ErrInvalidPayload
	}
	timestamp, err := payloadClaim[int64](payload["timestampMs"])
	if err != nil || timestamp <= 0 {
		return Evidence{}, ErrInvalidPayload
	}
	timestampTime := time.UnixMilli(timestamp)
	now := policy.now()
	if timestampTime.Before(now.Add(-policy.MaxAge)) || timestampTime.After(now.Add(policy.ClockSkew)) {
		return Evidence{}, ErrInvalidPayload
	}
	packageName, err := payloadClaim[string](payload["apkPackageName"])
	if err != nil || packageName != policy.ExpectedAPKPackageName {
		return Evidence{}, ErrInvalidPayload
	}
	encodedDigests, err := payloadClaim[[]string](payload["apkCertificateDigestSha256"])
	if err != nil {
		return Evidence{}, err
	}
	digests, err := parseCertificateDigests(encodedDigests)
	if err != nil || !containsExpectedDigest(digests, policy.ExpectedAPKCertificateSHA256) {
		return Evidence{}, ErrInvalidPayload
	}
	return Evidence{Version: version, Timestamp: timestampTime, APKPackageName: packageName, APKCertificateSHA256: digests, CTSProfileMatch: cts, BasicIntegrity: basic}, nil
}

func payloadClaim[T any](raw json.RawMessage) (T, error) {
	var value T
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return value, ErrInvalidPayload
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}
	return value, nil
}

func booleanPayloadClaim(payload map[string]json.RawMessage, name string) (bool, bool, error) {
	raw, present := payload[name]
	if !present {
		return false, false, nil
	}
	value, err := payloadClaim[bool](raw)
	return value, true, err
}

func parseCertificateDigests(values []string) ([][]byte, error) {
	if len(values) == 0 {
		return nil, ErrInvalidPayload
	}
	out := make([][]byte, len(values))
	encoding := base64.StdEncoding.Strict()
	for i, encoded := range values {
		decoded, err := encoding.DecodeString(encoded)
		if err != nil || len(decoded) != 32 || encoding.EncodeToString(decoded) != encoded {
			return nil, ErrInvalidPayload
		}
		out[i] = decoded
	}
	return out, nil
}

func containsExpectedDigest(actual [][]byte, expected [][]byte) bool {
	for _, candidate := range actual {
		for _, allowed := range expected {
			if subtle.ConstantTimeCompare(candidate, allowed) == 1 {
				return true
			}
		}
	}
	return false
}
