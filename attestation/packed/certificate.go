package packed

import (
	"crypto/x509"
	"encoding/asn1"
	"slices"

	"github.com/islishude/webauthn/attestation/internal/x509util"
	"github.com/islishude/webauthn/protocol"
)

var (
	oidExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionFIDOAAGUID       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
)

func validatePackedCertificate(certificate *x509.Certificate, aaguid protocol.AAGUID) error {
	if certificate.Version != 3 {
		return ErrCertificateRequirements
	}
	if len(certificate.Subject.Country) == 0 ||
		len(certificate.Subject.Organization) == 0 ||
		len(certificate.Subject.CommonName) == 0 ||
		!slices.Contains(certificate.Subject.OrganizationalUnit, "Authenticator Attestation") {
		return ErrCertificateRequirements
	}
	if !x509util.HasExtension(certificate, oidExtensionBasicConstraints) || !certificate.BasicConstraintsValid || certificate.IsCA {
		return ErrCertificateRequirements
	}

	return validateAAGUIDExtension(certificate, aaguid)
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
