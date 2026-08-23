package androidkey

import (
	"bytes"
	"encoding/asn1"
	"fmt"
)

const (
	asn1TagSequence = 16
	asn1TagSet      = 17

	androidKeyPurposeSign         = 2
	androidKeyOriginGenerated     = 0
	androidSecurityLevelTEE       = 1
	androidSecurityLevelStrongBox = 2

	androidTagPurpose         = 1
	androidTagAllApplications = 600
	androidTagOrigin          = 702
)

type androidKeyDescription struct {
	attestationSecurityLevel int
	keymasterSecurityLevel   int
	attestationChallenge     []byte
	softwareEnforced         androidAuthorizationList
	hardwareEnforced         androidAuthorizationList
}

type androidAuthorizationList struct {
	purposes        []int
	origins         []int
	allApplications bool
}

func validateAndroidKeyExtension(raw []byte, clientDataHash []byte, policy Policy) error {
	description, err := parseAndroidKeyDescription(raw)
	if err != nil {
		return err
	}
	if !bytes.Equal(description.attestationChallenge, clientDataHash) {
		return ErrCertificateRequirements
	}
	if description.softwareEnforced.allApplications || description.hardwareEnforced.allApplications {
		return ErrCertificateRequirements
	}
	selected := []androidAuthorizationList{description.softwareEnforced, description.hardwareEnforced}
	if policy.RequireHardwareEnforced {
		if !hardwareSecurityLevel(description.attestationSecurityLevel) || !hardwareSecurityLevel(description.keymasterSecurityLevel) {
			return ErrCertificateRequirements
		}
		selected = []androidAuthorizationList{description.hardwareEnforced}
	}
	if !authorizationListsExactlyMatchWebAuthn(selected...) {
		return ErrCertificateRequirements
	}

	return nil
}

func parseAndroidKeyDescription(raw []byte) (androidKeyDescription, error) {
	fields, err := parseSequence(raw)
	if err != nil {
		return androidKeyDescription{}, err
	}
	if len(fields) != 8 {
		return androidKeyDescription{}, ErrInvalidExtension
	}

	challenge, err := parseOctetString(fields[4])
	if err != nil {
		return androidKeyDescription{}, err
	}
	softwareEnforced, err := parseAuthorizationList(fields[6])
	if err != nil {
		return androidKeyDescription{}, err
	}
	hardwareEnforced, err := parseAuthorizationList(fields[7])
	if err != nil {
		return androidKeyDescription{}, err
	}

	attestationSecurityLevel, err := parseEnumerated(fields[1])
	if err != nil {
		return androidKeyDescription{}, err
	}
	keymasterSecurityLevel, err := parseEnumerated(fields[3])
	if err != nil {
		return androidKeyDescription{}, err
	}

	return androidKeyDescription{
		attestationSecurityLevel: attestationSecurityLevel,
		keymasterSecurityLevel:   keymasterSecurityLevel,
		attestationChallenge:     challenge,
		softwareEnforced:         softwareEnforced,
		hardwareEnforced:         hardwareEnforced,
	}, nil
}

func parseAuthorizationList(raw asn1.RawValue) (androidAuthorizationList, error) {
	fields, err := parseSequenceValue(raw)
	if err != nil {
		return androidAuthorizationList{}, err
	}

	var list androidAuthorizationList
	for _, field := range fields {
		if field.Class != asn1.ClassContextSpecific {
			continue
		}
		switch field.Tag {
		case androidTagPurpose:
			purposes, err := parseExplicitIntSet(field)
			if err != nil {
				return androidAuthorizationList{}, err
			}
			list.purposes = append(list.purposes, purposes...)
		case androidTagAllApplications:
			if err := parseExplicitNull(field); err != nil {
				return androidAuthorizationList{}, err
			}
			list.allApplications = true
		case androidTagOrigin:
			origin, err := parseExplicitInt(field)
			if err != nil {
				return androidAuthorizationList{}, err
			}
			list.origins = append(list.origins, origin)
		}
	}

	return list, nil
}

func authorizationListsExactlyMatchWebAuthn(lists ...androidAuthorizationList) bool {
	origins := map[int]struct{}{}
	purposes := map[int]struct{}{}
	for _, list := range lists {
		for _, origin := range list.origins {
			origins[origin] = struct{}{}
		}
		for _, purpose := range list.purposes {
			purposes[purpose] = struct{}{}
		}
	}
	_, generated := origins[androidKeyOriginGenerated]
	_, signing := purposes[androidKeyPurposeSign]
	return generated && signing && len(origins) == 1 && len(purposes) == 1
}

func hardwareSecurityLevel(level int) bool {
	return level == androidSecurityLevelTEE || level == androidSecurityLevelStrongBox
}

func parseSequence(raw []byte) ([]asn1.RawValue, error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &outer)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidExtension, err)
	}
	if len(rest) != 0 {
		return nil, ErrInvalidExtension
	}

	return parseSequenceValue(outer)
}

func parseSequenceValue(raw asn1.RawValue) ([]asn1.RawValue, error) {
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1TagSequence || !raw.IsCompound {
		return nil, ErrInvalidExtension
	}

	return parseASN1Items(raw.Bytes)
}

func parseASN1Items(data []byte) ([]asn1.RawValue, error) {
	items := make([]asn1.RawValue, 0)
	for len(data) > 0 {
		var item asn1.RawValue
		rest, err := asn1.Unmarshal(data, &item)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidExtension, err)
		}
		if len(rest) == len(data) {
			return nil, ErrInvalidExtension
		}
		items = append(items, item)
		data = rest
	}

	return items, nil
}

func parseOctetString(raw asn1.RawValue) ([]byte, error) {
	var out []byte
	rest, err := asn1.Unmarshal(raw.FullBytes, &out)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidExtension, err)
	}
	if len(rest) != 0 {
		return nil, ErrInvalidExtension
	}

	return out, nil
}

func parseEnumerated(raw asn1.RawValue) (int, error) {
	var out asn1.Enumerated
	rest, err := asn1.Unmarshal(raw.FullBytes, &out)
	if err != nil || len(rest) != 0 {
		return 0, ErrInvalidExtension
	}
	return int(out), nil
}

func parseExplicitInt(raw asn1.RawValue) (int, error) {
	if raw.Class != asn1.ClassContextSpecific || !raw.IsCompound {
		return 0, ErrInvalidExtension
	}
	var out int
	rest, err := asn1.Unmarshal(raw.Bytes, &out)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidExtension, err)
	}
	if len(rest) != 0 {
		return 0, ErrInvalidExtension
	}

	return out, nil
}

func parseExplicitIntSet(raw asn1.RawValue) ([]int, error) {
	if raw.Class != asn1.ClassContextSpecific || !raw.IsCompound {
		return nil, ErrInvalidExtension
	}

	var set asn1.RawValue
	rest, err := asn1.Unmarshal(raw.Bytes, &set)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidExtension, err)
	}
	if len(rest) != 0 || set.Class != asn1.ClassUniversal || set.Tag != asn1TagSet || !set.IsCompound {
		return nil, ErrInvalidExtension
	}
	items, err := parseASN1Items(set.Bytes)
	if err != nil {
		return nil, err
	}
	out := make([]int, 0, len(items))
	for _, item := range items {
		value, err := parseInteger(item)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}

	return out, nil
}

func parseExplicitNull(raw asn1.RawValue) error {
	if raw.Class != asn1.ClassContextSpecific || !raw.IsCompound {
		return ErrInvalidExtension
	}
	var nullValue asn1.RawValue
	rest, err := asn1.Unmarshal(raw.Bytes, &nullValue)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidExtension, err)
	}
	if len(rest) != 0 ||
		nullValue.Class != asn1.ClassUniversal ||
		nullValue.Tag != 5 ||
		nullValue.IsCompound ||
		len(nullValue.Bytes) != 0 {
		return ErrInvalidExtension
	}

	return nil
}

func parseInteger(raw asn1.RawValue) (int, error) {
	var out int
	rest, err := asn1.Unmarshal(raw.FullBytes, &out)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidExtension, err)
	}
	if len(rest) != 0 {
		return 0, ErrInvalidExtension
	}

	return out, nil
}
