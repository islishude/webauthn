// Package protocolidentifier validates WebAuthn extension and attestation
// statement format identifiers shared across package boundaries.
package protocolidentifier

const maxIdentifierLength = 32

// Valid reports whether value satisfies the WebAuthn identifier grammar: one
// to 32 printable US-ASCII octets, excluding double quote and backslash.
func Valid(value string) bool {
	if len(value) == 0 || len(value) > maxIdentifierLength {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x21 || value[i] > 0x7e || value[i] == '"' || value[i] == '\\' {
			return false
		}
	}
	return true
}
