package webauthnhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/browser"
	"github.com/islishude/webauthn/protocol"
)

const (
	// DefaultMaxBodyBytes is the read limit used when callers pass a non-positive limit.
	DefaultMaxBodyBytes int64 = 1 << 20
)

var (
	// ErrRequestBodyTooLarge reports a browser response body larger than the configured limit.
	ErrRequestBodyTooLarge = errors.New("webauthn/http: request body too large")
	// ErrReadRequest reports a failure reading an HTTP request body.
	ErrReadRequest = errors.New("webauthn/http: read request")
	// ErrWriteResponse reports a failure writing an HTTP JSON response.
	ErrWriteResponse = errors.New("webauthn/http: write response")
)

// ErrorResponse is the generic JSON shape written by WriteError.
type ErrorResponse struct {
	Error string `json:"error"`
}

// WriteCreationOptions writes browser JSON creation options with HTTP 200.
func WriteCreationOptions(response http.ResponseWriter, options protocol.PublicKeyCredentialCreationOptions) error {
	return WriteJSON(response, http.StatusOK, browser.CredentialCreationOptionsFromProtocol(options))
}

// WriteRequestOptions writes browser JSON request options with HTTP 200.
func WriteRequestOptions(response http.ResponseWriter, options protocol.PublicKeyCredentialRequestOptions) error {
	return WriteJSON(response, http.StatusOK, browser.CredentialRequestOptionsFromProtocol(options))
}

// ReadRegistrationResponse reads and decodes browser JSON registration response input.
func ReadRegistrationResponse(request *http.Request, maxBodyBytes int64) (webauthn.RegistrationResponse, error) {
	data, err := readRequestBody(request, maxBodyBytes)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}

	response, err := browser.RegistrationResponseFromJSON(data)
	if err != nil {
		return webauthn.RegistrationResponse{}, err
	}

	return response, nil
}

// ReadAuthenticationResponse reads and decodes browser JSON authentication response input.
func ReadAuthenticationResponse(request *http.Request, maxBodyBytes int64) (webauthn.AuthenticationResponse, error) {
	data, err := readRequestBody(request, maxBodyBytes)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}

	response, err := browser.AuthenticationResponseFromJSON(data)
	if err != nil {
		return webauthn.AuthenticationResponse{}, err
	}

	return response, nil
}

// WriteJSON writes value as an application/json response with status.
func WriteJSON(response http.ResponseWriter, status int, value any) error {
	if response == nil {
		return fmt.Errorf("%w: response writer is nil", ErrWriteResponse)
	}
	status = normalizeStatus(status)
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		return fmt.Errorf("%w: %w", ErrWriteResponse, err)
	}

	return nil
}

// WriteError writes a generic JSON error response without including err text.
func WriteError(response http.ResponseWriter, status int, _ error) error {
	if status < http.StatusBadRequest {
		status = http.StatusInternalServerError
	}
	message := http.StatusText(status)
	if message == "" {
		message = "error"
	}

	return WriteJSON(response, status, ErrorResponse{Error: message})
}

func readRequestBody(request *http.Request, maxBodyBytes int64) ([]byte, error) {
	if request == nil || request.Body == nil {
		return nil, fmt.Errorf("%w: request body is nil", ErrReadRequest)
	}
	limit := maxBodyBytes
	if limit <= 0 {
		limit = DefaultMaxBodyBytes
	}

	reader := &io.LimitedReader{R: request.Body, N: limit + 1}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadRequest, err)
	}
	if int64(len(data)) > limit {
		return nil, ErrRequestBodyTooLarge
	}

	return data, nil
}

func normalizeStatus(status int) int {
	if status < 100 || status > 999 {
		return http.StatusInternalServerError
	}

	return status
}
