package extension

import (
	"context"
	"unicode/utf8"

	"github.com/islishude/webauthn/protocol"
)

const (
	// IDRemoteClientDataJSON is the Editor's Draft remote client data extension
	// identifier. It is intentionally not included in Level3Handlers.
	IDRemoteClientDataJSON = "remoteClientDataJSON"
)

// RemoteClientDataJSONResult reports whether the client acted on the opt-in
// Editor's Draft extension.
type RemoteClientDataJSONResult struct {
	Used bool
}

// RemoteClientDataJSONHandler validates the opt-in Editor's Draft client-only
// extension. Callers must add it to a registry explicitly.
type RemoteClientDataJSONHandler struct{}

// ID returns "remoteClientDataJSON".
func (RemoteClientDataJSONHandler) ID() string {
	return IDRemoteClientDataJSON
}

// ValidateInput validates the remote serialized client data and ceremony type.
func (RemoteClientDataJSONHandler) ValidateInput(request InputRequest) (string, error) {
	if err := requireInputOperation(request, OperationRegistration, OperationAuthentication); err != nil {
		return "", err
	}
	input, ok := As[string](request.Input)
	if !ok || input == "" || !utf8.ValidString(input) {
		return "", invalidRequest("remoteClientDataJSON input must be a non-empty UTF-8 string")
	}
	raw, err := protocol.NewClientDataJSON([]byte(input))
	if err != nil {
		return "", invalidRequest("remoteClientDataJSON input is invalid")
	}
	clientData, err := protocol.ParseCollectedClientData(raw)
	if err != nil {
		return "", invalidRequest("remoteClientDataJSON input must contain valid client data")
	}
	expectedType := protocol.ClientDataTypeCreate
	if request.Operation == OperationAuthentication {
		expectedType = protocol.ClientDataTypeGet
	}
	if err := clientData.ValidateType(expectedType); err != nil {
		return "", invalidRequest("remoteClientDataJSON ceremony type is invalid")
	}
	return input, nil
}

// VerifyOutput requires the client-only output to be present and true.
func (RemoteClientDataJSONHandler) VerifyOutput(_ context.Context, request OutputRequest[string]) (Verification[RemoteClientDataJSONResult], error) {
	if err := requireOperation(request, OperationRegistration, OperationAuthentication); err != nil {
		return Verification[RemoteClientDataJSONResult]{}, err
	}
	if !request.Requested {
		return Verification[RemoteClientDataJSONResult]{}, invalidRequest("remoteClientDataJSON must be requested")
	}
	if hasAuthenticatorOutput(request) {
		return Verification[RemoteClientDataJSONResult]{}, invalidRequest("remoteClientDataJSON has no authenticator output")
	}
	if !hasClientOutput(request) {
		return Verification[RemoteClientDataJSONResult]{}, invalidRequest("remoteClientDataJSON client output must be true")
	}
	used, ok := As[bool](request.ClientOutput)
	if !ok || !used {
		return Verification[RemoteClientDataJSONResult]{}, invalidRequest("remoteClientDataJSON client output must be true")
	}
	return Verification[RemoteClientDataJSONResult]{
		Accepted: true,
		Output:   RemoteClientDataJSONResult{Used: true},
	}, nil
}

var _ Handler[string, RemoteClientDataJSONResult] = RemoteClientDataJSONHandler{}
