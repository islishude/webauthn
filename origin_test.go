package webauthn_test

import (
	"context"
	"errors"
	"testing"

	webauthn "github.com/islishude/webauthn"
)

func TestStartAuthenticationValidatesOriginAndRPIDRelationship(t *testing.T) {
	t.Parallel()

	base := webauthn.AuthenticationStartOptions{
		RPID:         "example.com",
		OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{"https://login.example.com"}},
	}
	if _, err := webauthn.StartAuthentication(context.Background(), base); err != nil {
		t.Fatalf("valid StartAuthentication() error = %v", err)
	}

	for _, test := range []struct {
		name   string
		rpID   string
		origin string
	}{
		{name: "rp id contains scheme", rpID: "https://example.com", origin: "https://example.com"},
		{name: "rp id is not canonical", rpID: "Example.com", origin: "https://example.com"},
		{name: "origin contains path", rpID: "example.com", origin: "https://example.com/"},
		{name: "origin is insecure", rpID: "example.com", origin: "http://example.com"},
		{name: "origin host is not canonical", rpID: "example.com", origin: "https://EXAMPLE.com"},
		{name: "origin default port is not canonical", rpID: "example.com", origin: "https://example.com:443"},
		{name: "origin port has leading zeroes", rpID: "example.com", origin: "https://example.com:08443"},
		{name: "origin port is out of range", rpID: "example.com", origin: "https://example.com:65536"},
		{name: "origin host has trailing dot", rpID: "example.com", origin: "https://example.com."},
		{name: "rp id label is too long", rpID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example", origin: "https://example.com"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := base
			options.RPID = test.rpID
			options.OriginPolicy = webauthn.OriginPolicy{AllowedOrigins: []string{test.origin}}
			if _, err := webauthn.StartAuthentication(context.Background(), options); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
				t.Fatalf("StartAuthentication() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func TestStartAuthenticationRequiresExplicitRelatedOriginPolicy(t *testing.T) {
	t.Parallel()

	options := webauthn.AuthenticationStartOptions{
		RPID:         "example.com",
		OriginPolicy: webauthn.OriginPolicy{AllowedOrigins: []string{"https://related.example"}},
	}
	if _, err := webauthn.StartAuthentication(context.Background(), options); !errors.Is(err, webauthn.ErrInvalidConfiguration) {
		t.Fatalf("unrelated origin error = %v, want ErrInvalidConfiguration", err)
	}
	options.OriginPolicy.AllowRelatedOrigins = true
	if _, err := webauthn.StartAuthentication(context.Background(), options); err != nil {
		t.Fatalf("explicit related origin error = %v", err)
	}

	options.RPID = "localhost"
	options.OriginPolicy = webauthn.OriginPolicy{AllowedOrigins: []string{"http://localhost:8080"}}
	if _, err := webauthn.StartAuthentication(context.Background(), options); err != nil {
		t.Fatalf("loopback origin error = %v", err)
	}
}
