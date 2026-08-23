package packed

import (
	"crypto/x509"
	"encoding/asn1"
	"math/big"

	"github.com/islishude/webauthn/attestation/internal/x509util"
	"github.com/islishude/webauthn/protocol"
)

var (
	oidExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionFIDOAAGUID       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
	oidExtensionFIDOFirmware     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 5}
	oidExtensionFIDOSerialNumber = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 2}

	oidSubjectCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidSubjectOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidSubjectOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidSubjectCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
)

func validatePackedCertificate(certificate *x509.Certificate, aaguid protocol.AAGUID, conveyance protocol.AttestationConveyancePreference) error {
	if certificate.Version != 3 {
		return ErrCertificateRequirements
	}
	if err := validatePackedSubject(certificate); err != nil {
		return ErrCertificateRequirements
	}
	if !x509util.HasExtension(certificate, oidExtensionBasicConstraints) || !certificate.BasicConstraintsValid || certificate.IsCA {
		return ErrCertificateRequirements
	}

	if err := validateAAGUIDExtension(certificate, aaguid); err != nil {
		return err
	}
	if err := validateFirmwareExtension(certificate); err != nil {
		return err
	}
	return validateEnterpriseSerialExtension(certificate, conveyance)
}

func validatePackedSubject(certificate *x509.Certificate) error {
	attributes, err := x509util.ParseNameAttributes(certificate.RawSubject)
	if err != nil {
		return ErrCertificateRequirements
	}
	required := map[string]bool{
		oidSubjectCountry.String():            false,
		oidSubjectOrganization.String():       false,
		oidSubjectOrganizationalUnit.String(): false,
		oidSubjectCommonName.String():         false,
	}
	for _, attribute := range attributes {
		key := attribute.Type.String()
		if _, ok := required[key]; !ok {
			continue
		}
		if required[key] {
			return ErrCertificateRequirements
		}
		switch {
		case attribute.Type.Equal(oidSubjectCountry):
			if attribute.Tag != asn1.TagPrintableString || !validCountryCode(attribute.Value) {
				return ErrCertificateRequirements
			}
		case attribute.Type.Equal(oidSubjectOrganizationalUnit):
			if attribute.Tag != asn1.TagUTF8String || attribute.Value != "Authenticator Attestation" {
				return ErrCertificateRequirements
			}
		default:
			if attribute.Tag != asn1.TagUTF8String || attribute.Value == "" {
				return ErrCertificateRequirements
			}
		}
		required[key] = true
	}
	for _, present := range required {
		if !present {
			return ErrCertificateRequirements
		}
	}
	return nil
}

func validCountryCode(value string) bool {
	return len(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
}

func validateAAGUIDExtension(certificate *x509.Certificate, aaguid protocol.AAGUID) error {
	extension, ok := x509util.FindExtension(certificate, oidExtensionFIDOAAGUID)
	if !ok {
		return nil
	}
	if extension.Critical {
		return ErrCertificateRequirements
	}

	var extensionAAGUID []byte
	rest, err := asn1.Unmarshal(extension.Value, &extensionAAGUID)
	if err != nil || len(rest) != 0 || len(extensionAAGUID) != protocol.AAGUIDLength {
		return ErrCertificateRequirements
	}
	if !aaguid.EqualBytes(extensionAAGUID) {
		return ErrCertificateRequirements
	}

	return nil
}

func validateFirmwareExtension(certificate *x509.Certificate) error {
	extension, ok := x509util.FindExtension(certificate, oidExtensionFIDOFirmware)
	if !ok {
		return nil
	}
	if extension.Critical {
		return ErrCertificateRequirements
	}
	var version *big.Int
	rest, err := asn1.Unmarshal(extension.Value, &version)
	if err != nil || len(rest) != 0 || version == nil || version.Sign() < 0 {
		return ErrCertificateRequirements
	}
	return nil
}

func validateEnterpriseSerialExtension(certificate *x509.Certificate, conveyance protocol.AttestationConveyancePreference) error {
	extension, ok := x509util.FindExtension(certificate, oidExtensionFIDOSerialNumber)
	if !ok {
		return nil
	}
	if conveyance != protocol.AttestationEnterprise || extension.Critical {
		return ErrCertificateRequirements
	}
	var serial []byte
	rest, err := asn1.Unmarshal(extension.Value, &serial)
	if err != nil || len(rest) != 0 || len(serial) == 0 {
		return ErrCertificateRequirements
	}
	return nil
}
