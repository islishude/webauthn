// This example integrates existing application accounts and sessions with
// WebAuthn. Run go test ./examples/integration for the complete signed flows.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/browser"
	"github.com/islishude/webauthn/protocol"
	storagejson "github.com/islishude/webauthn/storage/json"
)

var (
	errDenied    = errors.New("application: request denied")
	errRisk      = errors.New("application: additional authentication required")
	errDuplicate = errors.New("application: credential already registered")
)

type accountStore interface {
	// EnrollmentUser checks current authorization, including at finish time.
	EnrollmentUser(context.Context, string) (protocol.UserEntity, error)
	UserByName(context.Context, string) (protocol.UserEntity, error)
}

type ceremonyKind string

const (
	registration   ceremonyKind = "registration"
	authentication ceremonyKind = "authentication"
)

type savedCeremony struct {
	kind    ceremonyKind
	session string
	account protocol.UserHandle
	expires time.Time
	payload []byte
}

type ceremonyStore interface {
	Save(context.Context, string, savedCeremony) error
	// Consume checks expiry, session, kind and, when supplied, account under
	// one lock/transaction. A successful consume removes even malformed payloads.
	Consume(context.Context, string, string, ceremonyKind, *protocol.UserHandle) (savedCeremony, error)
}

type credentialSnapshot struct {
	record  webauthn.CredentialRecord
	version uint64
}

type credentialStore interface {
	List(context.Context, protocol.UserHandle) ([]protocol.CredentialDescriptor, error)
	Lookup(context.Context, protocol.RawID, protocol.UserHandle) (credentialSnapshot, error)
	Insert(context.Context, webauthn.CredentialRecord) error
	Update(context.Context, webauthn.CredentialUpdate, uint64) error
}

type sessionStore interface {
	Create(context.Context, protocol.UserHandle) (string, error)
}

type application struct {
	rp          *webauthn.RelyingParty
	accounts    accountStore
	ceremonies  ceremonyStore
	credentials credentialStore
	sessions    sessionStore
}

func ceremonyID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (a *application) beginEnrollment(ctx context.Context, session string) (string, browser.CredentialCreationOptionsJSON, error) {
	user, err := a.accounts.EnrollmentUser(ctx, session)
	if err != nil {
		return "", browser.CredentialCreationOptionsJSON{}, err
	}
	credentials, err := a.credentials.List(ctx, user.ID)
	if err != nil {
		return "", browser.CredentialCreationOptionsJSON{}, err
	}
	start, err := a.rp.StartRegistration(ctx, webauthn.RegistrationRequest{User: user, ExcludeCredentials: credentials})
	if err != nil {
		return "", browser.CredentialCreationOptionsJSON{}, err
	}
	dto, err := browser.CredentialCreationOptionsFromProtocol(start.Options)
	if err != nil {
		return "", browser.CredentialCreationOptionsJSON{}, err
	}
	payload, err := storagejson.MarshalRegistrationState(start.State)
	if err != nil {
		return "", browser.CredentialCreationOptionsJSON{}, err
	}
	id, err := a.save(ctx, savedCeremony{kind: registration, session: session, account: user.ID, expires: start.State.ExpiresAt, payload: payload})
	if err != nil {
		return "", browser.CredentialCreationOptionsJSON{}, err
	}
	return id, dto, nil
}

func (a *application) finishEnrollment(ctx context.Context, session, id string, body []byte) error {
	user, err := a.accounts.EnrollmentUser(ctx, session)
	if err != nil {
		return err
	}
	saved, err := a.ceremonies.Consume(ctx, id, session, registration, &user.ID)
	if err != nil {
		return err
	}
	state, err := storagejson.UnmarshalRegistrationState(saved.payload)
	if err != nil {
		return err
	}
	if !state.UserHandle.Equal(saved.account) || !state.ExpiresAt.Equal(saved.expires) {
		return webauthn.ErrInvalidCeremonyState
	}
	response, err := browser.RegistrationResponseFromJSON(body)
	if err != nil {
		return err
	}
	result, err := a.rp.FinishRegistration(ctx, webauthn.RegistrationVerification{State: state, Response: response})
	if err != nil {
		return err
	}
	return a.credentials.Insert(ctx, result.Credential)
}

// Empty username selects discoverable login. session identifies the initiating
// browser session, even before it has authenticated an account.
func (a *application) beginLogin(ctx context.Context, session, username string) (string, browser.CredentialRequestOptionsJSON, error) {
	request := webauthn.AuthenticationRequest{}
	if username != "" {
		user, err := a.accounts.UserByName(ctx, username)
		if err != nil {
			return "", browser.CredentialRequestOptionsJSON{}, err
		}
		request.ExpectedUserHandle = user.ID
		request.AllowCredentials, err = a.credentials.List(ctx, user.ID)
		if err != nil {
			return "", browser.CredentialRequestOptionsJSON{}, err
		}
		if len(request.AllowCredentials) == 0 {
			return "", browser.CredentialRequestOptionsJSON{}, errDenied
		}
	}
	start, err := a.rp.StartAuthentication(ctx, request)
	if err != nil {
		return "", browser.CredentialRequestOptionsJSON{}, err
	}
	dto, err := browser.CredentialRequestOptionsFromProtocol(start.Options)
	if err != nil {
		return "", browser.CredentialRequestOptionsJSON{}, err
	}
	payload, err := storagejson.MarshalAuthenticationState(start.State)
	if err != nil {
		return "", browser.CredentialRequestOptionsJSON{}, err
	}
	id, err := a.save(ctx, savedCeremony{kind: authentication, session: session, account: start.State.ExpectedUserHandle, expires: start.State.ExpiresAt, payload: payload})
	if err != nil {
		return "", browser.CredentialRequestOptionsJSON{}, err
	}
	return id, dto, nil
}

func (a *application) save(ctx context.Context, saved savedCeremony) (string, error) {
	if saved.session == "" {
		return "", errDenied
	}
	id, err := ceremonyID()
	if err != nil {
		return "", err
	}
	if err = a.ceremonies.Save(ctx, id, saved); err != nil {
		return "", err
	}
	return id, nil
}

func (a *application) finishLogin(ctx context.Context, session, id string, body []byte) (string, error) {
	saved, err := a.ceremonies.Consume(ctx, id, session, authentication, nil)
	if err != nil {
		return "", err
	}
	state, err := storagejson.UnmarshalAuthenticationState(saved.payload)
	if err != nil {
		return "", err
	}
	if !state.ExpectedUserHandle.Equal(saved.account) || !state.ExpiresAt.Equal(saved.expires) {
		return "", webauthn.ErrInvalidCeremonyState
	}
	response, err := browser.AuthenticationResponseFromJSON(body)
	if err != nil {
		return "", err
	}
	lookupUser := state.ExpectedUserHandle
	if lookupUser.Len() == 0 {
		lookupUser = response.UserHandle
	}
	if lookupUser.Len() == 0 {
		return "", errDenied
	}
	stored, err := a.credentials.Lookup(ctx, response.RawID, lookupUser)
	if err != nil {
		return "", err
	}
	result, err := a.rp.FinishAuthentication(ctx, webauthn.AuthenticationVerification{State: state, Response: response, Credential: stored.record})
	if err != nil {
		return "", err
	}
	if result.Counter.CloneRisk || result.UVInitializationPending {
		return "", errRisk
	}
	if err = a.credentials.Update(ctx, result.Update, stored.version); err != nil {
		return "", err
	}
	return a.sessions.Create(ctx, result.AuthenticatedAs)
}

func main() {}
