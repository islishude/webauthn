package packed

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"slices"

	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

var (
	oidExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionFIDOAAGUID       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
)

func parseCertificateChain(rawChain [][]byte) (webcrypto.CertificateChain, []*x509.Certificate, error) {
	if len(rawChain) == 0 {
		return nil, nil, ErrInvalidStatement
	}

	chain := make(webcrypto.CertificateChain, len(rawChain))
	certificates := make([]*x509.Certificate, len(rawChain))
	for i, raw := range rawChain {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
		}
		chain[i] = webcrypto.NewCertificate(raw)
		certificates[i] = certificate
	}

	return chain, certificates, nil
}

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
	if !hasExtension(certificate, oidExtensionBasicConstraints) || !certificate.BasicConstraintsValid || certificate.IsCA {
		return ErrCertificateRequirements
	}

	return validateAAGUIDExtension(certificate, aaguid)
}

func validateAAGUIDExtension(certificate *x509.Certificate, aaguid protocol.AAGUID) error {
	extension, ok := findExtension(certificate, oidExtensionFIDOAAGUID)
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

func hasExtension(certificate *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	_, ok := findExtension(certificate, oid)
	return ok
}

func findExtension(certificate *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oid) {
			return extension, true
		}
	}

	return pkix.Extension{}, false
}
