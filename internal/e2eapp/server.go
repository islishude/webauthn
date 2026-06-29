package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"time"

	webauthn "github.com/islishude/webauthn"
	"github.com/islishude/webauthn/attestation"
	attnone "github.com/islishude/webauthn/attestation/none"
	"github.com/islishude/webauthn/codec"
	codeccbor "github.com/islishude/webauthn/codec/cbor"
	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/extension"
	"github.com/islishude/webauthn/protocol"
	webauthnhttp "github.com/islishude/webauthn/transport/http"
)

const (
	registrationCookie   = "e2e_registration"
	authenticationCookie = "e2e_authentication"
	sessionCookie        = "e2e_session"
)

type app struct {
	rpID       string
	origin     string
	store      *store
	decoder    *codeccbor.Decoder
	attesters  *attestation.Registry
	extensions *extension.Registry
}

func newApp(host string) (*app, error) {
	decoder, err := codeccbor.NewDecoder()
	if err != nil {
		return nil, err
	}
	attesters, err := attestation.NewRegistry(attnone.New())
	if err != nil {
		return nil, err
	}
	extensions, err := extension.NewLevel3RegistryWithDeprecated()
	if err != nil {
		return nil, err
	}
	return &app{
		rpID:       host,
		origin:     "https://" + host + ":8443",
		store:      newStore(),
		decoder:    decoder,
		attesters:  attesters,
		extensions: extensions,
	}, nil
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.healthz)
	mux.HandleFunc("POST /register/options", a.registerOptions)
	mux.HandleFunc("POST /register/finish", a.registerFinish)
	mux.HandleFunc("POST /login/options", a.loginOptions)
	mux.HandleFunc("POST /login/finish", a.loginFinish)
	mux.HandleFunc("GET /me", a.me)
	mux.HandleFunc("POST /logout", a.logout)
	mux.HandleFunc("GET /debug/credential", a.debugCredential)
	static, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(static)))
	return mux
}

func (a *app) healthz(response http.ResponseWriter, _ *http.Request) {
	_ = webauthnhttp.WriteJSON(response, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) originPolicy() webauthn.OriginPolicy {
	return webauthn.OriginPolicy{AllowedOrigins: []string{a.origin}}
}

func (a *app) cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (a *app) clearCookie(name string) *http.Cookie {
	return a.cookie(name, "", -1)
}

func (a *app) setSession(response http.ResponseWriter, handle protocol.UserHandle) error {
	sessionID, err := a.store.createSession(handle)
	if err != nil {
		return err
	}
	http.SetCookie(response, a.cookie(sessionCookie, sessionID, 3600))
	return nil
}

func selfSignedTLSConfig(host string) (*tls.Config, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}}}, nil
}

type signatureVerifier struct {
	publicKey codec.CredentialPublicKey
}

func (v signatureVerifier) VerifySignature(_ context.Context, input webcrypto.SignatureInput) error {
	material := v.publicKey.PublicKeyMaterial()
	switch {
	case material.EC2 != nil:
		curve, hashFactory, err := ec2CurveAndHash(input.Algorithm, material.EC2.Curve)
		if err != nil {
			return err
		}
		publicKey := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(material.EC2.X),
			Y:     new(big.Int).SetBytes(material.EC2.Y),
		}
		if _, err := publicKey.ECDH(); err != nil {
			return fmt.Errorf("invalid EC2 coordinates: %w", err)
		}
		digest := digest(input.Signed, hashFactory)
		if !ecdsa.VerifyASN1(publicKey, digest, input.Signature.Bytes()) {
			return errors.New("ECDSA signature rejected")
		}
		return nil
	default:
		return fmt.Errorf("unsupported algorithm %d", input.Algorithm)
	}
}

func digest(signed []byte, hashFactory func() hash.Hash) []byte {
	hash := hashFactory()
	_, _ = hash.Write(signed)
	return hash.Sum(nil)
}

func ec2CurveAndHash(algorithm protocol.COSEAlgorithmIdentifier, curveName string) (elliptic.Curve, func() hash.Hash, error) {
	switch {
	case algorithm == protocol.AlgorithmES256 && curveName == codec.EC2CurveP256:
		return elliptic.P256(), sha256.New, nil
	case algorithm == protocol.AlgorithmES384 && curveName == codec.EC2CurveP384:
		return elliptic.P384(), sha512.New384, nil
	case algorithm == protocol.AlgorithmES512 && curveName == codec.EC2CurveP521:
		return elliptic.P521(), sha512.New, nil
	default:
		return nil, nil, fmt.Errorf("unsupported EC2 algorithm %d with curve %s", algorithm, curveName)
	}
}

func writeGenericError(response http.ResponseWriter, status int) {
	_ = webauthnhttp.WriteJSON(response, status, map[string]any{"ok": false, "error": http.StatusText(status)})
}

func decodeJSON(request *http.Request, target any) error {
	defer func() {
		_ = request.Body.Close()
	}()
	return json.NewDecoder(request.Body).Decode(target)
}
