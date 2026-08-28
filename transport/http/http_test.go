package webauthnhttp_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/islishude/webauthn/protocol"
	webauthnhttp "github.com/islishude/webauthn/transport/http"
)

func TestWriteCreationOptions(t *testing.T) {
	t.Parallel()

	challenge := mustChallenge(t, []byte("0123456789abcdef"))
	userHandle := mustUserHandle(t, []byte("user-1"))
	recorder := httptest.NewRecorder()

	err := webauthnhttp.WriteCreationOptions(recorder, protocol.PublicKeyCredentialCreationOptions{
		RP:        protocol.RPEntity{ID: "example.com", Name: "Example"},
		User:      protocol.UserEntity{ID: userHandle, Name: "user@example.com", DisplayName: "Example User"},
		Challenge: challenge,
		PubKeyCredParams: []protocol.CredentialParameter{{
			Type:      protocol.CredentialTypePublicKey,
			Algorithm: -7,
		}},
		Hints:              []protocol.PublicKeyCredentialHint{protocol.HintClientDevice},
		AttestationFormats: []string{"packed"},
	})
	if err != nil {
		t.Fatalf("WriteCreationOptions() error = %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", recorder.Header().Get("Content-Type"))
	}

	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("response JSON error = %v", err)
	}
	if body["challenge"] != encode([]byte("0123456789abcdef")) {
		t.Fatalf("challenge = %#v", body["challenge"])
	}
	if body["hints"].([]any)[0] != string(protocol.HintClientDevice) {
		t.Fatalf("hints = %#v", body["hints"])
	}
}

func TestReadRegistrationResponse(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register/finish", strings.NewReader(registrationResponseJSON()))
	response, err := webauthnhttp.ReadRegistrationResponse(request, 1024)
	if err != nil {
		t.Fatalf("ReadRegistrationResponse() error = %v", err)
	}
	if string(response.RawID.Bytes()) != "credential-1" {
		t.Fatalf("RawID = %q", response.RawID.Bytes())
	}
}

func TestReadAuthenticationResponse(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/login/finish", strings.NewReader(authenticationResponseJSON()))
	response, err := webauthnhttp.ReadAuthenticationResponse(request, 1024)
	if err != nil {
		t.Fatalf("ReadAuthenticationResponse() error = %v", err)
	}
	if string(response.Signature.Bytes()) != "signature" {
		t.Fatalf("Signature = %q", response.Signature.Bytes())
	}
}

func TestReadResponseRejectsLargeBody(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register/finish", strings.NewReader(registrationResponseJSON()))
	_, err := webauthnhttp.ReadRegistrationResponse(request, 8)
	if !errors.Is(err, webauthnhttp.ErrRequestBodyTooLarge) {
		t.Fatalf("ReadRegistrationResponse() error = %v, want ErrRequestBodyTooLarge", err)
	}
}

func TestReadResponseRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register/finish", strings.NewReader("{"))
	_, err := webauthnhttp.ReadRegistrationResponse(request, 1024)
	if err == nil {
		t.Fatal("ReadRegistrationResponse() error = nil")
	}
}

func TestWriteErrorUsesGenericMessage(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	err := webauthnhttp.WriteError(recorder, http.StatusBadRequest, errors.New("credential secret should not leak"))
	if err != nil {
		t.Fatalf("WriteError() error = %v", err)
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "credential secret") {
		t.Fatalf("WriteError leaked sensitive error text: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Bad Request") {
		t.Fatalf("WriteError body = %s", recorder.Body.String())
	}
}

func TestWriteJSONDoesNotCommitSerializationFailures(t *testing.T) {
	t.Parallel()

	writer := &trackingResponseWriter{}
	err := webauthnhttp.WriteJSON(writer, http.StatusOK, map[string]float64{"invalid": math.NaN()})
	if !errors.Is(err, webauthnhttp.ErrWriteResponse) {
		t.Fatalf("WriteJSON() error = %v, want ErrWriteResponse", err)
	}
	if writer.wroteHeader || writer.wroteBody || writer.Header().Get("Content-Type") != "" {
		t.Fatalf("serialization failure committed response: %+v", writer)
	}
}

func TestWriteJSONReportsShortWrites(t *testing.T) {
	t.Parallel()

	writer := &trackingResponseWriter{writeLimit: 1}
	err := webauthnhttp.WriteJSON(writer, http.StatusCreated, map[string]bool{"ok": true})
	if !errors.Is(err, webauthnhttp.ErrWriteResponse) || !writer.wroteHeader || !writer.wroteBody {
		t.Fatalf("WriteJSON() error = %v writer = %+v", err, writer)
	}
}

type trackingResponseWriter struct {
	header      http.Header
	status      int
	wroteHeader bool
	wroteBody   bool
	writeLimit  int
}

func (w *trackingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *trackingResponseWriter) WriteHeader(status int) {
	w.status = status
	w.wroteHeader = true
}

func (w *trackingResponseWriter) Write(data []byte) (int, error) {
	w.wroteBody = true
	if w.writeLimit > 0 && w.writeLimit < len(data) {
		return w.writeLimit, nil
	}
	return len(data), nil
}

func registrationResponseJSON() string {
	id := encode([]byte("credential-1"))
	return `{"id":"` + id + `","type":"public-key","rawId":"` + id + `","clientExtensionResults":{},"response":{"clientDataJSON":"` + encode([]byte("{}")) + `","authenticatorData":"` + encode(make([]byte, 37)) + `","transports":[],"publicKeyAlgorithm":-7,"attestationObject":"` + encode([]byte{0xa0}) + `"}}`
}

func authenticationResponseJSON() string {
	id := encode([]byte("credential-1"))
	return `{"id":"` + id + `","type":"public-key","rawId":"` + id + `","clientExtensionResults":{},"response":{"clientDataJSON":"` + encode([]byte("{}")) + `","authenticatorData":"` + encode(make([]byte, 37)) + `","signature":"` + encode([]byte("signature")) + `"}}`
}

func mustChallenge(t *testing.T, value []byte) protocol.Challenge {
	t.Helper()

	out, err := protocol.NewChallenge(value)
	if err != nil {
		t.Fatalf("NewChallenge() error = %v", err)
	}

	return out
}

func mustUserHandle(t *testing.T, value []byte) protocol.UserHandle {
	t.Helper()

	out, err := protocol.NewUserHandle(value)
	if err != nil {
		t.Fatalf("NewUserHandle() error = %v", err)
	}

	return out
}

func encode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
