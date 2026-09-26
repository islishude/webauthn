package webauthn_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/browser"
	"github.com/islishude/webauthn/internal/testceremony"
	"github.com/islishude/webauthn/protocol"
)

func TestSelectionValidationAtEveryEntry(t *testing.T) {
	for _, field := range []string{"authenticatorAttachment", "residentKey", "userVerification"} {
		t.Run(field, func(t *testing.T) {
			config := rpConfig(t)
			selection := config.Registration.AuthenticatorSelection
			switch field {
			case "authenticatorAttachment":
				selection.AuthenticatorAttachment = "typo"
			case "residentKey":
				selection.ResidentKey = "typo"
			case "userVerification":
				selection.UserVerification = "typo"
			}
			config.ChallengeGenerator = webauthn.ChallengeGeneratorFunc(func(context.Context) (protocol.Challenge, error) {
				t.Fatal("invalid configuration generated a challenge")
				return protocol.Challenge{}, nil
			})
			config.Now = func() time.Time { t.Fatal("invalid configuration read clock"); return time.Time{} }
			_, err := webauthn.New(config)
			if !errors.Is(err, webauthn.ErrInvalidConfiguration) {
				t.Fatal(err)
			}
			var value protocol.ValueError
			if !errors.As(err, &value) || value.Field != field {
				t.Fatalf("missing field error: %v", err)
			}
			_, err = webauthn.StartRegistration(context.Background(), webauthn.RegistrationStartOptions{
				RP: config.RP, OriginPolicy: config.OriginPolicy, User: protocol.UserEntity{ID: mustUserHandle(t, []byte("user")), Name: "user"},
				AuthenticatorSelection: selection, ChallengeGenerator: config.ChallengeGenerator, Now: config.Now,
			})
			if !errors.Is(err, webauthn.ErrInvalidConfiguration) {
				t.Fatal(err)
			}
			options := protocol.PublicKeyCredentialCreationOptions{AuthenticatorSelection: selection}
			if err = options.Validate(); !errors.As(err, &value) || value.Field != field {
				t.Fatal(err)
			}
			if _, err = browser.CredentialCreationOptionsFromProtocol(options); !errors.Is(err, browser.ErrInvalidProtocolValue) || !errors.As(err, &value) {
				t.Fatal(err)
			}
		})
	}
	for _, selection := range []*protocol.AuthenticatorSelectionCriteria{nil, {},
		{RequireResidentKey: true},
		{AuthenticatorAttachment: protocol.AuthenticatorAttachmentPlatform, ResidentKey: protocol.ResidentKeyRequired, UserVerification: protocol.UserVerificationRequired},
		{AuthenticatorAttachment: protocol.AuthenticatorAttachmentCrossPlatform, ResidentKey: protocol.ResidentKeyPreferred, UserVerification: protocol.UserVerificationPreferred},
		{ResidentKey: protocol.ResidentKeyDiscouraged, UserVerification: protocol.UserVerificationDiscouraged},
	} {
		if err := selection.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStoredCredentialErrorParity(t *testing.T) {
	for _, mutate := range []func(*webauthn.CredentialRecord){
		func(r *webauthn.CredentialRecord) { *r = webauthn.CredentialRecord{} },
		func(r *webauthn.CredentialRecord) { r.Type = "" },
		func(r *webauthn.CredentialRecord) { r.RPID = "" },
		func(r *webauthn.CredentialRecord) { r.PublicKey.Algorithm = 0 },
		func(r *webauthn.CredentialRecord) { r.BackupState = true; r.BackupEligible = false },
		func(r *webauthn.CredentialRecord) { r.AttestationType = "invalid" },
		func(r *webauthn.CredentialRecord) { r.AuthenticatorAttachment = "invalid" },
	} {
		config := rpConfig(t)
		rp, err := webauthn.New(config)
		if err != nil {
			t.Fatal(err)
		}
		start, err := rp.StartAuthentication(context.Background(), webauthn.AuthenticationRequest{})
		if err != nil {
			t.Fatal(err)
		}
		f := testceremony.New(t, config.RP.ID, mustUserHandle(t, []byte("user")))
		response, err := browser.AuthenticationResponseFromJSON(f.AuthenticationJSON(t, start.State))
		if err != nil {
			t.Fatal(err)
		}
		mutate(&f.Record)
		_, high := rp.FinishAuthentication(context.Background(), webauthn.AuthenticationVerification{State: start.State, Response: response, Credential: f.Record})
		_, low := webauthn.FinishAuthentication(context.Background(), webauthn.AuthenticationFinishOptions{State: start.State, Response: response, Credential: f.Record, SignatureVerifier: config.SignatureVerifier})
		for _, err := range []error{high, low} {
			if !errors.Is(err, webauthn.ErrInvalidCredentialRecord) || errors.Is(err, webauthn.ErrUnsupportedAlgorithm) || errors.Is(err, webauthn.ErrCredentialNotAllowed) {
				t.Fatalf("wrong classification: %v", err)
			}
		}
	}
}

func TestCredentialDataHelpers(t *testing.T) {
	f := testceremony.New(t, "example.com", mustUserHandle(t, []byte("user")))
	record := f.Record
	record.BackupEligible = true
	record.Transports = []protocol.AuthenticatorTransport{protocol.TransportUSB}
	descriptor := record.Descriptor()
	descriptor.Transports[0] = protocol.TransportNFC
	if record.Transports[0] != protocol.TransportUSB || !descriptor.ID.Equal(record.ID) {
		t.Fatal("descriptor aliased or changed identity")
	}
	original := record.Clone()
	update := webauthn.CredentialUpdate{ID: record.ID, PreviousUVInitialized: true, BackupState: true, BackupStateChanged: true, AuthenticatorAttachment: protocol.AuthenticatorAttachmentPlatform, AuthenticatorAttachmentChanged: true}
	next, err := update.ApplyTo(record)
	if err != nil || !next.BackupState || next.AuthenticatorAttachment != protocol.AuthenticatorAttachmentPlatform {
		t.Fatalf("apply: %v", err)
	}
	next.Transports[0] = protocol.TransportNFC
	if !reflect.DeepEqual(record, original) {
		t.Fatal("apply mutated input")
	}
	for _, mutate := range []func(*webauthn.CredentialUpdate){
		func(u *webauthn.CredentialUpdate) { u.ID = mustCredentialID(t, []byte("different")) },
		func(u *webauthn.CredentialUpdate) { u.PreviousSignCount = 1 },
		func(u *webauthn.CredentialUpdate) { u.PreviousBackupState = true },
		func(u *webauthn.CredentialUpdate) { u.PreviousUVInitialized = false },
		func(u *webauthn.CredentialUpdate) {
			u.PreviousAuthenticatorAttachment = protocol.AuthenticatorAttachmentPlatform
		},
	} {
		conflicting := update
		mutate(&conflicting)
		got, err := conflicting.ApplyTo(record)
		if !errors.Is(err, webauthn.ErrCredentialUpdateConflict) || !reflect.DeepEqual(got, webauthn.CredentialRecord{}) {
			t.Fatal("conflict returned a record")
		}
	}
	update.AuthenticatorAttachment = "invalid"
	if got, err := update.ApplyTo(record); !errors.Is(err, webauthn.ErrInvalidCredentialUpdate) || !errors.Is(err, webauthn.ErrInvalidCredentialRecord) || !reflect.DeepEqual(got, webauthn.CredentialRecord{}) {
		t.Fatal("invalid update accepted")
	}
	if _, err := update.ApplyTo(webauthn.CredentialRecord{}); !errors.Is(err, webauthn.ErrInvalidCredentialRecord) || errors.Is(err, webauthn.ErrInvalidCredentialUpdate) {
		t.Fatal("invalid source misclassified")
	}
	noChange := webauthn.CredentialUpdate{ID: record.ID, PreviousUVInitialized: true, SignCount: 999, AuthenticatorAttachment: "ignored"}
	next, err = noChange.ApplyTo(record)
	if err != nil || !reflect.DeepEqual(next, record) {
		t.Fatal("unchanged fields applied")
	}
	if _, err = noChange.ApplyTo(next); err != nil {
		t.Fatal("value comparison became a version lock")
	}
	fixture := newAuthenticationFixture(t, true)
	options := fixture.finishOptions()
	options.Response.AuthenticatorData = mustAuthenticatorData(t, authenticationAuthenticatorData(t, "example.com", authenticationFlagUP, 2, nil))
	options.CounterPolicy.UpdateOnCloneRisk = true
	result, err := webauthn.FinishAuthentication(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	next, err = result.Update.ApplyTo(options.Credential)
	if err != nil || next.SignCount != 2 {
		t.Fatalf("explicit rollback policy broken: %v", err)
	}
}
