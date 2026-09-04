package webauthn

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/islishude/webauthn/protocol"
)

// OriginPolicy defines the origins accepted for a ceremony.
type OriginPolicy struct {
	// AllowedOrigins are accepted CollectedClientData.origin values.
	AllowedOrigins []string
	// AllowedTopOrigins are accepted CollectedClientData.topOrigin values.
	AllowedTopOrigins []string
	// AllowCrossOriginWithoutTopOrigin accepts legacy cross-origin client data
	// that does not include topOrigin.
	AllowCrossOriginWithoutTopOrigin bool
	// AllowRelatedOrigins permits explicitly configured origins whose host is not
	// equal to or a domain suffix match for the RP ID. Callers remain
	// responsible for performing WebAuthn related-origins validation.
	AllowRelatedOrigins bool
}

func (p OriginPolicy) clone() OriginPolicy {
	return OriginPolicy{
		AllowedOrigins:                   slices.Clone(p.AllowedOrigins),
		AllowedTopOrigins:                slices.Clone(p.AllowedTopOrigins),
		AllowCrossOriginWithoutTopOrigin: p.AllowCrossOriginWithoutTopOrigin,
		AllowRelatedOrigins:              p.AllowRelatedOrigins,
	}
}

func validateOriginPolicy(policy OriginPolicy) error {
	if len(policy.AllowedOrigins) == 0 {
		return errors.New("allowed origins are required")
	}
	for _, origin := range policy.AllowedOrigins {
		if err := validateWebAuthnOrigin(origin); err != nil {
			return fmt.Errorf("allowed origin: %w", err)
		}
	}
	for _, origin := range policy.AllowedTopOrigins {
		if err := validateWebAuthnOrigin(origin); err != nil {
			return fmt.Errorf("allowed top origin: %w", err)
		}
	}

	return nil
}

func validateRPIDOriginPolicy(rpID string, policy OriginPolicy) error {
	if !validRPID(rpID) {
		return errors.New("rp id is invalid")
	}
	if policy.AllowRelatedOrigins {
		return nil
	}
	for _, origin := range policy.AllowedOrigins {
		parsed, err := url.Parse(origin)
		if err != nil {
			return errors.New("allowed origin is invalid")
		}
		host := strings.ToLower(parsed.Hostname())
		if host != rpID && !strings.HasSuffix(host, "."+rpID) {
			return errors.New("allowed origin is not scoped to rp id")
		}
	}
	return nil
}

func validateWebAuthnOrigin(value string) error {
	if value == "" {
		return errors.New("origin is empty")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("origin must be a canonical scheme and authority")
	}
	hostname := parsed.Hostname()
	if hostname == "" || hostname != strings.ToLower(hostname) || parsed.String() != value || !canonicalOriginHost(hostname) {
		return errors.New("origin is not canonical")
	}
	port, explicitPort, ok := canonicalOriginPort(parsed.Host)
	if !ok || (explicitPort && ((parsed.Scheme == "https" && port == 443) || (parsed.Scheme == "http" && port == 80))) {
		return errors.New("origin port is not canonical")
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if hostname == "localhost" {
			return nil
		}
		if address := net.ParseIP(hostname); address != nil && address.IsLoopback() {
			return nil
		}
	}
	return errors.New("origin must use https or loopback http")
}

func validRPID(value string) bool {
	return value == strings.ToLower(value) && strings.TrimSpace(value) == value && net.ParseIP(value) == nil && validDNSName(value)
}

func canonicalOriginHost(hostname string) bool {
	if address := net.ParseIP(hostname); address != nil {
		return address.String() == hostname
	}
	return validDNSName(hostname)
}

func canonicalOriginPort(host string) (int, bool, bool) {
	rawPort := ""
	explicit := false
	if strings.HasPrefix(host, "[") {
		closing := strings.LastIndexByte(host, ']')
		if closing < 0 {
			return 0, false, false
		}
		suffix := host[closing+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return 0, false, false
			}
			explicit = true
			rawPort = suffix[1:]
		}
	} else if separator := strings.LastIndexByte(host, ':'); separator >= 0 {
		if strings.Contains(host[:separator], ":") {
			return 0, false, false
		}
		explicit = true
		rawPort = host[separator+1:]
	}
	if !explicit {
		return 0, false, true
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != rawPort {
		return 0, true, false
	}
	return port, true, true
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.ContainsAny(value, "/:@?#") {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func verifyCollectedClientOrigin(policy OriginPolicy, clientData protocol.CollectedClientData) error {
	if !slices.Contains(policy.AllowedOrigins, clientData.Origin) {
		return ErrOriginMismatch
	}

	crossOrigin := clientData.CrossOrigin != nil && *clientData.CrossOrigin
	if clientData.HasTopOrigin() {
		if !crossOrigin {
			return ErrOriginMismatch
		}
		if !slices.Contains(policy.AllowedTopOrigins, clientData.TopOrigin) {
			return ErrOriginMismatch
		}

		return nil
	}

	if crossOrigin && !policy.AllowCrossOriginWithoutTopOrigin {
		return ErrOriginMismatch
	}

	return nil
}
