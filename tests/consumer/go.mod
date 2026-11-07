module example.com/webauthn-consumer

go 1.27.0

require github.com/islishude/webauthn v0.0.0

require (
	github.com/fxamacker/cbor/v2 v2.10.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)

replace github.com/islishude/webauthn => ../..
