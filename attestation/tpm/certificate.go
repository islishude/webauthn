package tpm

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"

	"github.com/islishude/webauthn/attestation/internal/x509util"
	"github.com/islishude/webauthn/protocol"
)

var (
	oidExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionFIDOAAGUID       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

	oidAIKEKU          = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
)

func validateAIKCertificate(certificate *x509.Certificate, aaguid protocol.AAGUID) error {
	if certificate.Version != 3 {
		return ErrCertificateRequirements
	}
	if !subjectEmpty(certificate.Subject) {
		return ErrCertificateRequirements
	}
	if !x509util.HasExtension(certificate, oidExtensionSubjectAltName) || !hasTPMSANAttributes(certificate) {
		return ErrCertificateRequirements
	}
	if !hasAIKEKU(certificate) {
		return ErrCertificateRequirements
	}
	if !x509util.HasExtension(certificate, oidExtensionBasicConstraints) || !certificate.BasicConstraintsValid || certificate.IsCA {
		return ErrCertificateRequirements
	}

	return validateAAGUIDExtension(certificate, aaguid)
}

func subjectEmpty(subject pkix.Name) bool {
	return len(subject.Country) == 0 &&
		len(subject.Organization) == 0 &&
		len(subject.OrganizationalUnit) == 0 &&
		len(subject.Locality) == 0 &&
		len(subject.Province) == 0 &&
		len(subject.StreetAddress) == 0 &&
		len(subject.PostalCode) == 0 &&
		subject.SerialNumber == "" &&
		subject.CommonName == "" &&
		len(subject.Names) == 0 &&
		len(subject.ExtraNames) == 0
}

func hasAIKEKU(certificate *x509.Certificate) bool {
	return slices.ContainsFunc(certificate.UnknownExtKeyUsage, func(oid asn1.ObjectIdentifier) bool {
		return oid.Equal(oidAIKEKU)
	})
}

func hasTPMSANAttributes(certificate *x509.Certificate) bool {
	extension, ok := x509util.FindExtension(certificate, oidExtensionSubjectAltName)
	if !ok {
		return false
	}

	var generalNames []asn1.RawValue
	rest, err := asn1.Unmarshal(extension.Value, &generalNames)
	if err != nil || len(rest) != 0 {
		return false
	}
	for _, generalName := range generalNames {
		if generalName.Class != asn1.ClassContextSpecific || generalName.Tag != 4 || !generalName.IsCompound {
			continue
		}
		var rdnSequence pkix.RDNSequence
		rest, err := asn1.Unmarshal(generalName.Bytes, &rdnSequence)
		if err == nil && len(rest) == 0 && rdnSequenceHasTPMAttributes(rdnSequence) {
			return true
		}
	}

	return false
}

func rdnSequenceHasTPMAttributes(rdnSequence pkix.RDNSequence) bool {
	required := map[string]bool{
		oidTPMManufacturer.String(): false,
		oidTPMModel.String():        false,
		oidTPMVersion.String():      false,
	}
	for _, relativeNames := range rdnSequence {
		for _, attribute := range relativeNames {
			key := attribute.Type.String()
			if _, ok := required[key]; ok {
				required[key] = true
			}
		}
	}
	for _, found := range required {
		if !found {
			return false
		}
	}

	return true
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
	if !bytes.Equal(extensionAAGUID, aaguid.Bytes()) {
		return ErrCertificateRequirements
	}

	return nil
}
