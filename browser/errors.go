package browser

import "errors"

var (
	// ErrMalformedJSON reports browser credential JSON that cannot be decoded.
	ErrMalformedJSON = errors.New("browser: malformed json")
	// ErrInvalidBase64URL reports a browser binary field that is not unpadded base64url.
	ErrInvalidBase64URL = errors.New("browser: invalid base64url")
	// ErrInvalidProtocolValue reports a decoded browser value rejected by protocol validation.
	ErrInvalidProtocolValue = errors.New("browser: invalid protocol value")
)
