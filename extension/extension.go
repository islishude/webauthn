// Package extension defines WebAuthn extension handler contracts and registry behavior.
package extension

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/islishude/webauthn/internal/protocolidentifier"
	"github.com/islishude/webauthn/protocol"
)

var (
	// ErrInvalidID reports an empty extension identifier.
	ErrInvalidID = errors.New("extension id is empty")
	// ErrDuplicateID reports a duplicate registry entry.
	ErrDuplicateID = errors.New("extension id already registered")
	// ErrUnknownID reports an extension identifier absent from a registry.
	ErrUnknownID = errors.New("extension id is not registered")
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

// RawValue contains one defensively copied value at an untyped extension
// boundary. Its zero value represents an absent value; a present nil value
// represents an explicit null.
type RawValue struct {
	present bool
	value   any
}

// NewRawValue constructs a present raw value and defensively copies value.
func NewRawValue(value any) (RawValue, error) {
	cloned, err := CloneValue(value)
	if err != nil {
		return RawValue{}, err
	}
	return RawValue{present: true, value: cloned}, nil
}

// Present reports whether the extension member was present.
func (v RawValue) Present() bool {
	return v.present
}

// Null reports whether the extension member was present with an explicit null value.
func (v RawValue) Null() bool {
	return v.present && v.value == nil
}

// Clone returns a defensive copy of the underlying raw value.
func (v RawValue) Clone() (any, error) {
	if !v.present {
		return nil, nil
	}
	return CloneValue(v.value)
}

// As returns a defensive copy of value as T. It reports false for an absent,
// null, unsupported, or differently typed value.
func As[T any](value RawValue) (T, bool) {
	var zero T
	if !value.present || value.value == nil {
		return zero, false
	}
	cloned, err := CloneValue(value.value)
	if err != nil {
		return zero, false
	}
	typed, ok := cloned.(T)
	if !ok {
		return zero, false
	}
	return typed, true
}

// InputRequest contains one raw extension input at ceremony start.
type InputRequest struct {
	Operation Operation
	ID        string
	Input     RawValue
}

// OutputRequest contains a normalized extension input and raw output values
// routed to a handler after core ceremony verification succeeds.
type OutputRequest[I any] struct {
	Operation Operation
	ID        string
	Requested bool
	// SelectedCredentialID identifies the credential that produced an
	// authentication output. It is zero for registration outputs.
	SelectedCredentialID protocol.CredentialID
	ClientInput          I
	ClientOutput         RawValue
	AuthenticatorOutput  RawValue
}

func hasClientOutput[I any](request OutputRequest[I]) bool {
	return request.ClientOutput.Present()
}

func hasAuthenticatorOutput[I any](request OutputRequest[I]) bool {
	return request.AuthenticatorOutput.Present()
}

func rawValue(value RawValue) (any, error) {
	if !value.Present() {
		return nil, invalidRequest("extension value is absent")
	}
	return value.Clone()
}

// Verification is a handler's typed interpretation of extension output.
type Verification[O any] struct {
	Accepted   bool
	Deprecated bool
	Output     O
	Warnings   []string
}

// Handler validates input and interprets output for one exact extension
// identifier. Implementations must be deterministic and side-effect-free:
// VerifyOutput can run before caller-owned persistence and uniqueness decisions,
// and a ceremony can still fail after a handler returns.
type Handler[I, O any] interface {
	ID() string
	ValidateInput(InputRequest) (I, error)
	VerifyOutput(context.Context, OutputRequest[I]) (Verification[O], error)
}

// HandlerEntry is a type-erased handler accepted by Registry. Call Register to
// construct an entry; implementations outside this package cannot bypass the
// generic adapter.
type HandlerEntry interface {
	registeredHandler() erasedHandler
}

type handlerEntry[I, O any] struct {
	handler Handler[I, O]
}

func (entry handlerEntry[I, O]) registeredHandler() erasedHandler {
	return erasedAdapter[I, O](entry)
}

// Register adapts a typed handler for storage in a heterogeneous Registry.
func Register[I, O any](handler Handler[I, O]) HandlerEntry {
	return handlerEntry[I, O]{handler: handler}
}

type erasedHandler interface {
	ID() string
	Valid() bool
	ValidateInput(InputRequest) (RawValue, error)
	VerifyOutput(context.Context, RawOutputRequest) (Result, error)
}

type erasedAdapter[I, O any] struct {
	handler Handler[I, O]
}

func (adapter erasedAdapter[I, O]) ID() string {
	if !adapter.Valid() {
		return ""
	}
	return adapter.handler.ID()
}

func (adapter erasedAdapter[I, O]) Valid() bool {
	return !nilLike(adapter.handler)
}

func (adapter erasedAdapter[I, O]) ValidateInput(request InputRequest) (RawValue, error) {
	input, err := adapter.handler.ValidateInput(request)
	if err != nil {
		return RawValue{}, err
	}
	return NewRawValue(input)
}

func (adapter erasedAdapter[I, O]) VerifyOutput(ctx context.Context, request RawOutputRequest) (Result, error) {
	input, err := adapter.handler.ValidateInput(InputRequest{
		Operation: request.Operation,
		ID:        request.ID,
		Input:     request.ClientInput,
	})
	if err != nil {
		return Result{}, err
	}
	verification, err := adapter.handler.VerifyOutput(ctx, OutputRequest[I]{
		Operation:            request.Operation,
		ID:                   request.ID,
		Requested:            request.Requested,
		SelectedCredentialID: request.SelectedCredentialID,
		ClientInput:          input,
		ClientOutput:         request.ClientOutput,
		AuthenticatorOutput:  request.AuthenticatorOutput,
	})
	if err != nil {
		return Result{}, err
	}
	output, err := CloneValue(verification.Output)
	if err != nil {
		return Result{}, err
	}
	typed, ok := output.(O)
	if !ok {
		return Result{}, invalidRequest("handler output changed type while cloning")
	}
	return Result{
		ID:         request.ID,
		Accepted:   verification.Accepted,
		Deprecated: verification.Deprecated,
		Warnings:   slices.Clone(verification.Warnings),
		output:     typed,
	}, nil
}

// RawOutputRequest is the type-erased request accepted by Registry.VerifyOutput.
// Custom handlers receive its normalized input through OutputRequest[I].
type RawOutputRequest struct {
	Operation Operation
	ID        string
	Requested bool
	// SelectedCredentialID identifies the credential that produced an
	// authentication output. It is zero for registration outputs.
	SelectedCredentialID protocol.CredentialID
	ClientInput          RawValue
	ClientOutput         RawValue
	AuthenticatorOutput  RawValue
}

// Result contains extension result metadata. Use Find to retrieve a known
// handler's typed output or FindRaw to retrieve preserved raw values.
type Result struct {
	ID         string
	Accepted   bool
	Deprecated bool
	Warnings   []string
	output     any
	raw        bool
}

// Results is a deterministically ordered set of extension results.
type Results []Result

// TypedResult contains result metadata and a defensively copied typed output.
type TypedResult[O any] struct {
	ID         string
	Accepted   bool
	Deprecated bool
	Output     O
	Warnings   []string
}

// Find returns the result produced for handler with a typed, defensively copied output.
func Find[I, O any](results Results, handler Handler[I, O]) (TypedResult[O], bool) {
	var zero TypedResult[O]
	if nilLike(handler) {
		return zero, false
	}
	for _, result := range results {
		if result.ID != handler.ID() || result.raw {
			continue
		}
		output, err := CloneValue(result.output)
		if err != nil {
			return zero, false
		}
		typed, ok := output.(O)
		if !ok {
			return zero, false
		}
		return TypedResult[O]{
			ID:         result.ID,
			Accepted:   result.Accepted,
			Deprecated: result.Deprecated,
			Output:     typed,
			Warnings:   slices.Clone(result.Warnings),
		}, true
	}
	return zero, false
}

// RawResult contains preserved values for an unknown or unrequested extension.
type RawResult struct {
	Requested           bool
	ClientInput         RawValue
	ClientOutput        RawValue
	AuthenticatorOutput RawValue
}

// FindRaw returns a preserved raw result for id.
func FindRaw(results Results, id string) (TypedResult[RawResult], bool) {
	var zero TypedResult[RawResult]
	for _, result := range results {
		if result.ID != id || !result.raw {
			continue
		}
		raw, ok := result.output.(RawResult)
		if !ok {
			return zero, false
		}
		cloned, err := cloneRawResult(raw)
		if err != nil {
			return zero, false
		}
		return TypedResult[RawResult]{
			ID:         result.ID,
			Accepted:   result.Accepted,
			Deprecated: result.Deprecated,
			Output:     cloned,
			Warnings:   slices.Clone(result.Warnings),
		}, true
	}
	return zero, false
}

// PreserveRaw constructs an untrusted result for an unknown or unrequested extension.
func PreserveRaw(id string, raw RawResult, warnings ...string) (Result, error) {
	if !protocolidentifier.Valid(id) {
		return Result{}, ErrInvalidID
	}
	cloned, err := cloneRawResult(raw)
	if err != nil {
		return Result{}, err
	}
	return Result{ID: id, Warnings: slices.Clone(warnings), output: cloned, raw: true}, nil
}

func cloneRawResult(raw RawResult) (RawResult, error) {
	clientInput, err := cloneRawValue(raw.ClientInput)
	if err != nil {
		return RawResult{}, err
	}
	clientOutput, err := cloneRawValue(raw.ClientOutput)
	if err != nil {
		return RawResult{}, err
	}
	authenticatorOutput, err := cloneRawValue(raw.AuthenticatorOutput)
	if err != nil {
		return RawResult{}, err
	}
	return RawResult{
		Requested:           raw.Requested,
		ClientInput:         clientInput,
		ClientOutput:        clientOutput,
		AuthenticatorOutput: authenticatorOutput,
	}, nil
}

func cloneRawValue(value RawValue) (RawValue, error) {
	if !value.Present() {
		return RawValue{}, nil
	}
	cloned, err := value.Clone()
	if err != nil {
		return RawValue{}, err
	}
	return NewRawValue(cloned)
}

// Registry is a case-sensitive extension handler registry.
type Registry struct {
	handlers map[string]erasedHandler
}

// NewRegistry builds a registry and rejects duplicate extension identifiers.
func NewRegistry(entries ...HandlerEntry) (*Registry, error) {
	registry := &Registry{handlers: make(map[string]erasedHandler, len(entries))}
	for _, entry := range entries {
		if entry == nil {
			return nil, ErrInvalidID
		}
		handler := entry.registeredHandler()
		if handler == nil || !handler.Valid() || !protocolidentifier.Valid(handler.ID()) {
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

// Contains reports whether id has a registered handler.
func (r *Registry) Contains(id string) bool {
	if r == nil || r.handlers == nil {
		return false
	}
	_, ok := r.handlers[id]
	return ok
}

// ValidateInput validates and normalizes one registered extension input.
func (r *Registry) ValidateInput(request InputRequest) (RawValue, error) {
	handler, ok := r.lookup(request.ID)
	if !ok {
		return RawValue{}, fmt.Errorf("%w: %s", ErrUnknownID, request.ID)
	}
	return handler.ValidateInput(request)
}

// VerifyOutput verifies one registered extension output.
func (r *Registry) VerifyOutput(ctx context.Context, request RawOutputRequest) (Result, error) {
	handler, ok := r.lookup(request.ID)
	if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrUnknownID, request.ID)
	}
	return handler.VerifyOutput(ctx, request)
}

func (r *Registry) lookup(id string) (erasedHandler, bool) {
	if r == nil || r.handlers == nil {
		return nil, false
	}
	handler, ok := r.handlers[id]
	return handler, ok
}

func nilLike(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
