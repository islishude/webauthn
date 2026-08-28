package androidsafetynet

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"
)

func validatePayload(raw []byte, expectedNonce string, version string, policy Policy) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, ErrInvalidPayload
	}
	if len(policy.AllowedVersions) != 0 && !slices.Contains(policy.AllowedVersions, version) {
		return nil, ErrInvalidPayload
	}

	nonce, ok := payload["nonce"].(string)
	if !ok || nonce == "" {
		return nil, ErrInvalidPayload
	}
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(expectedNonce)) != 1 {
		return nil, ErrInvalidNonce
	}

	ctsProfileMatch, ctsPresent, err := booleanPayloadClaim(payload, "ctsProfileMatch")
	if err != nil {
		return nil, err
	}
	if policy.RequireCTSProfileMatch && (!ctsPresent || !ctsProfileMatch) {
		return nil, ErrInvalidPayload
	}
	basicIntegrity, basicPresent, err := booleanPayloadClaim(payload, "basicIntegrity")
	if err != nil {
		return nil, err
	}
	if policy.RequireBasicIntegrity && (!basicPresent || !basicIntegrity) {
		return nil, ErrInvalidPayload
	}

	timestamp, ok := payload["timestampMs"].(json.Number)
	if !ok {
		return nil, ErrInvalidPayload
	}
	timestampMilliseconds, err := strconv.ParseInt(timestamp.String(), 10, 64)
	if err != nil || timestampMilliseconds <= 0 {
		return nil, ErrInvalidPayload
	}
	timestampTime := time.UnixMilli(timestampMilliseconds)
	now := policy.now()
	if timestampTime.Before(now.Add(-policy.MaxAge)) || timestampTime.After(now.Add(policy.ClockSkew)) {
		return nil, ErrInvalidPayload
	}

	packageName, ok := payload["apkPackageName"].(string)
	if !ok || packageName != policy.ExpectedAPKPackageName {
		return nil, ErrInvalidPayload
	}
	digests, err := parseCertificateDigests(payload["apkCertificateDigestSha256"])
	if err != nil || !containsExpectedDigest(digests, policy.ExpectedAPKCertificateSHA256) {
		return nil, ErrInvalidPayload
	}

	return map[string]any{
		"version":                    version,
		"timestamp":                  timestampTime,
		"apkPackageName":             packageName,
		"apkCertificateDigestSHA256": digests,
		"ctsProfileMatch":            ctsProfileMatch,
		"basicIntegrity":             basicIntegrity,
	}, nil
}

func booleanPayloadClaim(payload map[string]any, name string) (bool, bool, error) {
	raw, present := payload[name]
	if !present {
		return false, false, nil
	}
	value, ok := raw.(bool)
	if !ok {
		return false, true, ErrInvalidPayload
	}
	return value, true, nil
}

func parseCertificateDigests(value any) ([][]byte, error) {
	values, ok := value.([]any)
	if !ok || len(values) == 0 {
		return nil, ErrInvalidPayload
	}
	out := make([][]byte, len(values))
	encoding := base64.StdEncoding.Strict()
	for i, value := range values {
		encoded, ok := value.(string)
		if !ok || encoded == "" {
			return nil, ErrInvalidPayload
		}
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
