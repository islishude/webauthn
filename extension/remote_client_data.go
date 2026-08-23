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
func (RemoteClientDataJSONHandler) ValidateInput(request InputRequest) (any, error) {
	if err := requireInputOperation(request, OperationRegistration, OperationAuthentication); err != nil {
		return nil, err
	}
	input, ok := request.Input.(string)
	if !ok || input == "" || !utf8.ValidString(input) {
		return nil, invalidRequest("remoteClientDataJSON input must be a non-empty UTF-8 string")
	}
	raw, err := protocol.NewClientDataJSON([]byte(input))
	if err != nil {
		return nil, invalidRequest("remoteClientDataJSON input is invalid")
	}
	clientData, err := protocol.ParseCollectedClientData(raw)
	if err != nil {
		return nil, invalidRequest("remoteClientDataJSON input must contain valid client data")
	}
	expectedType := protocol.ClientDataTypeCreate
	if request.Operation == OperationAuthentication {
		expectedType = protocol.ClientDataTypeGet
	}
	if err := clientData.ValidateType(expectedType); err != nil {
		return nil, invalidRequest("remoteClientDataJSON ceremony type is invalid")
	}
	return input, nil
}

// VerifyOutput requires the client-only output to be present and true.
func (handler RemoteClientDataJSONHandler) VerifyOutput(_ context.Context, request OutputRequest) (Result, error) {
	if err := requireOperation(request, OperationRegistration, OperationAuthentication); err != nil {
		return Result{}, err
	}
	if !request.Requested {
		return Result{}, invalidRequest("remoteClientDataJSON must be requested")
	}
	if _, err := handler.ValidateInput(InputRequest{Operation: request.Operation, ID: request.ID, Input: request.ClientInput}); err != nil {
		return Result{}, err
	}
	if hasAuthenticatorOutput(request) {
		return Result{}, invalidRequest("remoteClientDataJSON has no authenticator output")
	}
	if !hasClientOutput(request) {
		return Result{}, invalidRequest("remoteClientDataJSON client output must be true")
	}
	used, ok := request.ClientOutput.(bool)
	if !ok || !used {
		return Result{}, invalidRequest("remoteClientDataJSON client output must be true")
	}
	return Result{
		ID:       IDRemoteClientDataJSON,
		Accepted: true,
		Outputs: map[string]any{
			IDRemoteClientDataJSON: RemoteClientDataJSONResult{Used: true},
		},
	}, nil
}

var _ Handler = RemoteClientDataJSONHandler{}
