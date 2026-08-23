// Package extension defines WebAuthn extension handler contracts and registry behavior.
package extension

import (
	"context"
	"errors"
	"fmt"

	"github.com/islishude/webauthn/internal/protocolidentifier"
)

var (
	// ErrInvalidID reports an empty extension identifier.
	ErrInvalidID = errors.New("extension id is empty")
	// ErrDuplicateID reports a duplicate registry entry.
	ErrDuplicateID = errors.New("extension id already registered")
	// ErrInvalidOperation reports an extension used with the wrong ceremony.
	ErrInvalidOperation = errors.New("extension operation is invalid")
	// ErrInvalidRequest reports malformed extension input or output values.
	ErrInvalidRequest = errors.New("extension request is invalid")
)

// Operation identifies the WebAuthn ceremony that produced an extension value.
type Operation string

const (
	// OperationRegistration identifies a credential creation ceremony.
	OperationRegistration Operation = "registration"
	// OperationAuthentication identifies an assertion ceremony.
	OperationAuthentication Operation = "authentication"
)

// InputRequest contains one extension input at ceremony start.
type InputRequest struct {
	Operation Operation
	ID        string
	Input     any
}

// OutputRequest contains extension input and output values routed to a handler
// after core ceremony verification succeeds.
type OutputRequest struct {
	Operation                  Operation
	ID                         string
	Requested                  bool
	ClientInput                any
	ClientOutput               any
	ClientOutputPresent        bool
	AuthenticatorOutput        any
	AuthenticatorOutputPresent bool
}

func hasClientOutput(request OutputRequest) bool {
	return request.ClientOutputPresent || request.ClientOutput != nil
}

func hasAuthenticatorOutput(request OutputRequest) bool {
	return request.AuthenticatorOutputPresent || request.AuthenticatorOutput != nil
}

// Result is the handler's interpretation of extension output.
type Result struct {
	ID         string
	Accepted   bool
	Deprecated bool
	Outputs    map[string]any
	Warnings   []string
}

// Handler validates input and interprets output for one exact extension identifier.
type Handler interface {
	ID() string
	ValidateInput(InputRequest) (any, error)
	VerifyOutput(context.Context, OutputRequest) (Result, error)
}

// Registry is a case-sensitive extension handler registry.
type Registry struct {
	handlers map[string]Handler
}

// NewRegistry builds a registry and rejects duplicate extension identifiers.
func NewRegistry(handlers ...Handler) (*Registry, error) {
	registry := &Registry{handlers: make(map[string]Handler, len(handlers))}
	for _, handler := range handlers {
		if handler == nil || !protocolidentifier.Valid(handler.ID()) {
			return nil, ErrInvalidID
		}
		id := handler.ID()
		if _, exists := registry.handlers[id]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateID, id)
		}
		registry.handlers[id] = handler
	}

	return registry, nil
}

// Lookup returns the handler for id.
func (r *Registry) Lookup(id string) (Handler, bool) {
	if r == nil || r.handlers == nil {
		return nil, false
	}

	handler, ok := r.handlers[id]
	return handler, ok
}
