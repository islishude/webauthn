package webauthn_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	"github.com/islishude/webauthn/crypto/standard"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/preset"
	"github.com/islishude/webauthn/protocol"
	storagejson "github.com/islishude/webauthn/storage/json"
)

func rpConfig(t *testing.T) webauthn.Config {
	t.Helper()
	c, err := preset.PasskeyConfig(protocol.RPEntity{ID: "example.com", Name: "Example"}, webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRelyingPartyConfiguration(t *testing.T) {
	t.Parallel()
	var decoder *codeccbor.Decoder
	var verifier *standard.Verifier
	for name, mutate := range map[string]func(*webauthn.Config){
		"rp":                  func(c *webauthn.Config) { c.RP.ID = "https://example.com" },
		"origin":              func(c *webauthn.Config) { c.OriginPolicy.AllowedOrigins[0] = "https://other.com" },
		"missing decoder":     func(c *webauthn.Config) { c.AttestationObjectDecoder = nil },
		"typed nil decoder":   func(c *webauthn.Config) { c.ExtensionMapDecoder = decoder },
		"missing key decoder": func(c *webauthn.Config) { c.CredentialPublicKeyDecoder = nil },
		"verifier":            func(c *webauthn.Config) { c.SignatureVerifier = verifier },
		"policy":              func(c *webauthn.Config) { c.AlgorithmPolicy = nil },
		"typed policy":        func(c *webauthn.Config) { c.AlgorithmPolicy = verifier },
		"trust":               func(c *webauthn.Config) { c.AttestationTrustPolicy = nil },
		"registry":            func(c *webauthn.Config) { c.AttestationRegistry = nil },
		"generator":           func(c *webauthn.Config) { c.ChallengeGenerator = webauthn.ChallengeGeneratorFunc(nil) },
		"algorithm":           func(c *webauthn.Config) { c.PubKeyCredParams[0].Algorithm = protocol.AlgorithmEd448 },
		"negative time":       func(c *webauthn.Config) { c.Timeout = -time.Second },
		"ttl":                 func(c *webauthn.Config) { c.StateTTL = time.Second },
		"counter": func(c *webauthn.Config) {
			c.Authentication.CounterPolicy = webauthn.CounterPolicy{RejectCloneRisk: true, UpdateOnCloneRisk: true}
		},
		"uv":              func(c *webauthn.Config) { c.Authentication.UserVerification = "invalid" },
		"registration uv": func(c *webauthn.Config) { c.Registration.AuthenticatorSelection.UserVerification = "invalid" },
		"format":          func(c *webauthn.Config) { c.Registration.AttestationFormats = []string{"invalid format"} },
		"conveyance":      func(c *webauthn.Config) { c.Registration.Attestation = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			c := rpConfig(t)
			c.ChallengeGenerator = webauthn.ChallengeGeneratorFunc(func(context.Context) (protocol.Challenge, error) {
				t.Fatal("New generated a challenge")
				return protocol.Challenge{}, nil
			})
			c.Now = func() time.Time { t.Fatal("New invoked clock"); return time.Time{} }
			mutate(&c)
			if _, err := webauthn.New(c); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	for _, rp := range []*webauthn.RelyingParty{nil, {}} {
		_, e1 := rp.StartRegistration(context.Background(), webauthn.RegistrationRequest{})
		_, e2 := rp.StartAuthentication(context.Background(), webauthn.AuthenticationRequest{})
		_, e3 := rp.FinishRegistration(context.Background(), webauthn.RegistrationVerification{})
		_, e4 := rp.FinishAuthentication(context.Background(), webauthn.AuthenticationVerification{})
		for _, err := range []error{e1, e2, e3, e4} {
			if !errors.Is(err, webauthn.ErrInvalidConfiguration) {
				t.Fatal(err)
			}
		}
	}
}

func TestRelyingPartyRegistrationParityAndBinding(t *testing.T) {
	t.Parallel()
	f := newRegistrationFixture(t)
	c := rpConfig(t)
	c.PubKeyCredParams = f.start.Options.PubKeyCredParams
	c.Registration.AuthenticatorSelection = nil
	c.ChallengeGenerator = webauthn.ChallengeGeneratorFunc(func(context.Context) (protocol.Challenge, error) { return f.challenge, nil })
	rp, err := webauthn.New(c)
	if err != nil {
		t.Fatal(err)
	}
	start, err := rp.StartRegistration(context.Background(), webauthn.RegistrationRequest{User: f.start.Options.User, Extensions: protocol.ExtensionInputs{extension.IDCredProps: true}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := storagejson.MarshalRegistrationState(start.State)
	if err != nil {
		t.Fatal(err)
	}
	state, err := storagejson.UnmarshalRegistrationState(encoded)
	if err != nil {
		t.Fatal(err)
	}
	input := webauthn.RegistrationVerification{State: state, Response: f.response}
	got, err := rp.FinishRegistration(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	low := f.finishOptions()
	low.State = state
	low.ExtensionRegistry = c.ExtensionRegistry
	want, err := webauthn.FinishRegistration(context.Background(), low)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("parity: %v", err)
	}
	for name, mutate := range map[string]func(*webauthn.RegistrationState){
		"rp":     func(s *webauthn.RegistrationState) { s.RPID = "other.com" },
		"origin": func(s *webauthn.RegistrationState) { s.OriginPolicy.AllowedOrigins = []string{"https://other.com"} },
		"top origin": func(s *webauthn.RegistrationState) {
			s.OriginPolicy.AllowedTopOrigins = []string{"https://top.example.com"}
		},
		"related":      func(s *webauthn.RegistrationState) { s.OriginPolicy.AllowRelatedOrigins = true },
		"cross origin": func(s *webauthn.RegistrationState) { s.OriginPolicy.AllowCrossOriginWithoutTopOrigin = true },
		"uv":           func(s *webauthn.RegistrationState) { s.RequestedUserVerification = protocol.UserVerificationRequired },
		"algorithms": func(s *webauthn.RegistrationState) {
			s.AllowedAlgorithms = []protocol.COSEAlgorithmIdentifier{protocol.AlgorithmRS256}
		},
		"conveyance": func(s *webauthn.RegistrationState) { s.Attestation = protocol.AttestationDirect },
		"binding":    func(s *webauthn.RegistrationState) { s.ExtensionBindings = nil },
	} {
		t.Run(name, func(t *testing.T) {
			s := state
			mutate(&s)
			if _, err := rp.FinishRegistration(context.Background(), webauthn.RegistrationVerification{State: s, Response: f.response}); !errors.Is(err, webauthn.ErrInvalidCeremonyState) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	input.Response.Type = "invalid"
	if _, err := rp.FinishRegistration(context.Background(), input); !errors.Is(err, webauthn.ErrMalformedResponse) {
		t.Fatal(err)
	}
}

func TestRelyingPartyAuthenticationParity(t *testing.T) {
	t.Parallel()
	f := newAuthenticationFixture(t, false)
	c := rpConfig(t)
	c.Authentication.UserVerification = protocol.UserVerificationPreferred
	c.SignatureVerifier = acceptingSignatureVerifier{}
	c.ChallengeGenerator = webauthn.ChallengeGeneratorFunc(func(context.Context) (protocol.Challenge, error) { return f.challenge, nil })
	rp, err := webauthn.New(c)
	if err != nil {
		t.Fatal(err)
	}
	start, err := rp.StartAuthentication(context.Background(), webauthn.AuthenticationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := storagejson.MarshalAuthenticationState(start.State)
	if err != nil {
		t.Fatal(err)
	}
	state, err := storagejson.UnmarshalAuthenticationState(encoded)
	if err != nil {
		t.Fatal(err)
	}
	input := webauthn.AuthenticationVerification{State: state, Response: f.response, Credential: f.credential}
	got, err := rp.FinishAuthentication(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	low := f.finishOptions()
	low.State = state
	want, err := webauthn.FinishAuthentication(context.Background(), low)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("parity: %v", err)
	}
	input.State.RequestedUserVerification = protocol.UserVerificationRequired
	if _, err := rp.FinishAuthentication(context.Background(), input); !errors.Is(err, webauthn.ErrInvalidCeremonyState) {
		t.Fatal(err)
	}
	input.State = state
	input.Credential.PublicKey.Algorithm = protocol.AlgorithmEd448
	if _, err := rp.FinishAuthentication(context.Background(), input); !errors.Is(err, webauthn.ErrUnsupportedAlgorithm) {
		t.Fatal(err)
	}
}

func TestRelyingPartyCopiesConfigAndConcurrentUse(t *testing.T) {
	t.Parallel()
	c := rpConfig(t)
	c.Registration.AttestationFormats = []string{"none"}
	rp, err := webauthn.New(c)
	if err != nil {
		t.Fatal(err)
	}
	c.OriginPolicy.AllowedOrigins[0] = "https://other.com"
	c.PubKeyCredParams[0].Algorithm = protocol.AlgorithmEd448
	c.Registration.AttestationFormats[0] = "packed"
	c.Registration.AuthenticatorSelection.UserVerification = protocol.UserVerificationDiscouraged
	user := protocol.UserEntity{ID: mustUserHandle(t, []byte("account")), Name: "account"}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			r, err := rp.StartRegistration(context.Background(), webauthn.RegistrationRequest{User: user})
			if err != nil {
				t.Error(err)
				return
			}
			if r.State.OriginPolicy.AllowedOrigins[0] != "https://example.com" || r.State.AllowedAlgorithms[0] != protocol.AlgorithmEdDSA || r.State.RequestedUserVerification != protocol.UserVerificationRequired || r.Options.AttestationFormats[0] != "none" {
				t.Error("configuration was aliased")
			}
		})
	}
	wg.Wait()
}

func TestPasskeyPresetPolicies(t *testing.T) {
	t.Parallel()
	c := rpConfig(t)
	if c.Registration.AuthenticatorSelection.ResidentKey != protocol.ResidentKeyRequired || c.Registration.AuthenticatorSelection.AuthenticatorAttachment != "" || c.ExtensionRegistry.Contains(extension.IDUVM) {
		t.Fatal("incorrect preset")
	}
	for _, p := range c.PubKeyCredParams {
		if !c.AlgorithmPolicy.AcceptsAlgorithm(p.Algorithm) {
			t.Fatal("algorithm divergence")
		}
	}
	rp, err := webauthn.New(c)
	if err != nil {
		t.Fatal(err)
	}
	f := newRegistrationFixture(t)
	f.start.State.AllowedAlgorithms = []protocol.COSEAlgorithmIdentifier{protocol.AlgorithmEdDSA, protocol.AlgorithmES256, protocol.AlgorithmRS256}
	f.start.State.RequestedUserVerification = protocol.UserVerificationRequired
	input := webauthn.RegistrationVerification{State: f.start.State, Response: f.response}
	if _, err := rp.FinishRegistration(context.Background(), input); !errors.Is(err, webauthn.ErrUserVerificationRequired) {
		t.Fatal(err)
	}
	input.Response.AttestationObject = f.attestationObject(t, "none", "example.com", registrationFlagUP|registrationFlagUV|registrationFlagAT, nil, map[string]any{})
	result, err := rp.FinishRegistration(context.Background(), input)
	if err != nil || result.Credential.AttestationType != attestation.TypeNone {
		t.Fatal(err)
	}
	input.Response.AttestationObject = f.attestationObject(t, "packed", "example.com", registrationFlagUP|registrationFlagUV|registrationFlagAT, nil, map[string]any{})
	if _, err := rp.FinishRegistration(context.Background(), input); !errors.Is(err, webauthn.ErrUnsupportedAttestationFormat) {
		t.Fatal(err)
	}
}

func ExampleNew() {
	config, err := preset.PasskeyConfig(protocol.RPEntity{ID: "example.com", Name: "Example"}, webauthn.OriginPolicy{AllowedOrigins: []string{"https://example.com"}})
	if err != nil {
		panic(err)
	}
	rp, err := webauthn.New(config)
	if err != nil {
		panic(err)
	}
	start, err := rp.StartAuthentication(context.Background(), webauthn.AuthenticationRequest{})
	if err != nil {
		panic(err)
	}
	fmt.Println(start.Options.UserVerification, len(start.Options.AllowCredentials))
	// Output: required 0
}
