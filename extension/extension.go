// Package extension defines WebAuthn extension handler contracts and registry behavior.
package extension

import (
	"context"
	"errors"
	"fmt"
)

var (
	// ErrInvalidID reports an empty extension identifier.
	ErrInvalidID = errors.New("extension id is empty")
	// ErrDuplicateID reports a duplicate registry entry.
	ErrDuplicateID = errors.New("extension id already registered")
)

// Request contains extension input and output values routed to a handler.
type Request struct {
	ID                  string
	Requested           bool
	ClientInput         any
	ClientOutput        any
	AuthenticatorOutput any
}

// Result is the handler's interpretation of extension output.
type Result struct {
	ID       string
	Accepted bool
	Outputs  map[string]any
	Warnings []string
}

// Handler validates and interprets one exact extension identifier.
type Handler interface {
	ID() string
	HandleExtension(context.Context, Request) (Result, error)
}

// Registry is a case-sensitive extension handler registry.
type Registry struct {
	handlers map[string]Handler
}

// NewRegistry builds a registry and rejects duplicate extension identifiers.
func NewRegistry(handlers ...Handler) (*Registry, error) {
	registry := &Registry{handlers: make(map[string]Handler, len(handlers))}
	for _, handler := range handlers {
		if err := registry.Register(handler); err != nil {
			return nil, err
		}
	}

	return registry, nil
}

// Register adds a handler. Duplicate identifiers fail by default.
func (r *Registry) Register(handler Handler) error {
	if handler == nil {
		return ErrInvalidID
	}

	id := handler.ID()
	if id == "" {
		return ErrInvalidID
	}

	if r.handlers == nil {
		r.handlers = make(map[string]Handler)
	}

	if _, exists := r.handlers[id]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateID, id)
	}

	r.handlers[id] = handler
	return nil
}

// Lookup returns the handler for id.
func (r *Registry) Lookup(id string) (Handler, bool) {
	if r == nil || r.handlers == nil {
		return nil, false
	}

	handler, ok := r.handlers[id]
	return handler, ok
}
