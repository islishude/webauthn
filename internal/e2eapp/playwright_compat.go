package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/islishude/webauthn/codec"
	"github.com/islishude/webauthn/internal/interfaceutil"
	"github.com/islishude/webauthn/protocol"
)

// normalizePlaywrightRegistrationJSON fills the Level 3 authenticatorData
// convenience member from the authoritative attestationObject only for the
// test-only Playwright Credentials shim, which can omit the member or mirror
// attestationObject into it. Other supplied values remain untouched so the
// public browser decoder and root source-consistency check stay strict.
func normalizePlaywrightRegistrationJSON(data []byte, decoder codec.AttestationObjectDecoder) ([]byte, error) {
	if interfaceutil.IsNil(decoder) {
		return nil, errors.New("attestation object decoder is required")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(root["response"], &response); err != nil || response == nil {
		return nil, errors.New("registration response is required")
	}
	if rawAuthenticatorData, present := response["authenticatorData"]; present {
		if !sameJSONString(rawAuthenticatorData, response["attestationObject"]) {
			return data, nil
		}
	}

	var encodedAttestationObject string
	if err := json.Unmarshal(response["attestationObject"], &encodedAttestationObject); err != nil || encodedAttestationObject == "" {
		return nil, errors.New("attestation object is required")
	}
	encoding := base64.RawURLEncoding.Strict()
	rawAttestationObject, err := encoding.DecodeString(encodedAttestationObject)
	if err != nil || encoding.EncodeToString(rawAttestationObject) != encodedAttestationObject {
		return nil, errors.New("attestation object encoding is invalid")
	}
	attestationObject, err := protocol.NewAttestationObject(rawAttestationObject)
	if err != nil {
		return nil, err
	}
	decoded, err := decoder.DecodeAttestationObject(attestationObject)
	if err != nil {
		return nil, err
	}
	encodedAuthenticatorData, err := json.Marshal(encoding.EncodeToString(decoded.AuthenticatorData.Bytes()))
	if err != nil {
		return nil, err
	}
	response["authenticatorData"] = encodedAuthenticatorData
	root["response"], err = json.Marshal(response)
	if err != nil {
		return nil, err
	}
	return json.Marshal(root)
}

func sameJSONString(left json.RawMessage, right json.RawMessage) bool {
	var leftValue string
	var rightValue string
	return json.Unmarshal(left, &leftValue) == nil &&
		json.Unmarshal(right, &rightValue) == nil &&
		leftValue == rightValue
}
