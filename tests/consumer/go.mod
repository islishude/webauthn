module example.com/webauthn-consumer

go 1.25.0

require github.com/islishude/webauthn v0.0.0

require (
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/ldclabs/cose v1.4.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace github.com/islishude/webauthn => ../..
