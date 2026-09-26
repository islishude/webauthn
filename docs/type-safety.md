# Type safety and raw boundaries

Application-facing ceremony inputs and verified evidence use domain types.
Unknown wire formats remain explicitly raw. These are pre-v1 source-breaking
changes; the JSON storage envelope remains v3 with the same handler revisions
and validation rules. No dependency or package direction changes are required.

## Extension inputs

`protocol.ExtensionInputs` is `map[string]protocol.ExtensionInput`. An input
implements `CloneExtensionInput() (protocol.ExtensionInput, error)`, which must
copy all mutable fields. Boolean/string inputs use `protocol.BoolInput` and
`protocol.StringInput`; structured built-ins use `extension.PRFInput` and
`extension.LargeBlobInput`.

Prefer `extension.SetInput(inputs, handler, value)` when constructing inputs:
it infers the input type from `Handler[I, O]`, copies it, and selects the
handler's ID. For example, `SetInput(inputs, extension.CredPropsHandler{}, true)`
is valid; passing a string to that handler does not compile. The independent
consumer module exercises the public API.

Direct map literals remain supported with explicit input types. A typed value
still needs semantic validation: for example, a largeBlob write must be bound to
exactly one allowed credential. Start/finish validation and exact handler
revision bindings remain mandatory.

Unknown or restored values use `extension.NewRawInput(value)` explicitly.
`NormalizeInput` and `InputValue` are adapter/registry operations for crossing
that raw boundary. Typed strings, including pointer forms, obey the same 1 MiB
default byte budget as raw strings at extension input boundaries. Raw copying
also counts them against custom and aggregate byte budgets. The exact limit
is accepted; exceeding it fails before ceremony start succeeds.
A nil typed input is rejected; `NewRawInput(nil)` represents
an explicit null. Custom typed inputs may implement the copy contract, or
custom handlers may use a raw adapter for their normalized types. Custom clone
implementations are trusted application code and must bound their own work.

## Client outputs and browser JSON

Core responses carry `extension.ClientOutputs`, a map of `extension.RawValue`.
Construct entries with `NewRawValue`, or use `ClientOutputsFromRaw` in a
transport adapter. The constructor copies and bounds raw values. A missing key
is absent; a constructed nil is explicit null; inserting a zero `RawValue` into
a present map entry is rejected. Copying is not verification: only registered
handlers produce typed, verified `extension.Results` accessed with `Find`.

Browser DTO extension fields use `browser.ExtensionJSON`, a map of
`json.RawMessage`. Known PRF and largeBlob input dictionaries have concrete
`PRFInputJSON`, `PRFValuesJSON`, and `LargeBlobInputJSON` types. Optional pointers
retain explicit false, empty writes, and empty `evalByCredential` objects.
The core still receives bytes rather than browser base64url strings.

Both `CredentialCreationOptionsFromProtocol` and
`CredentialRequestOptionsFromProtocol` return `(DTO, error)`. An uncopyable or
unencodable extension fails conversion; it is never silently omitted. HTTP
option writers propagate the error before writing a response.

## Attestation and crypto

`attestation.Evidence` requires `CloneEvidence() Evidence`. Each optional format
owns its concrete type, including `androidsafetynet.Evidence` and
`compound.Evidence`. `EvidenceAs[T]` retrieves a defensively copied typed value.
Metadata and certificate-status hooks receive the same copyable contract.
Custom evidence implementations must copy all mutable fields.

Compound sub-results live in `TrustPath.Statements` with `TrustPathCompound`.
Other raw paths use `[]byte` in `TrustPath.Raw`. Nested statements and built-in
evidence are copied recursively. Format verification still does not establish
RP trust; compound callers must evaluate sub-statement trust explicitly.

`CertificateVerificationContext.Roots` is a `CertificateChain` of immutable DER
wrappers. The untyped `Policy` field is removed: implementation-specific policy
belongs to the injected verifier's own configuration. The unused
`JWSVerification.ProtectedHeader` is removed; the JWS adapter remains responsible
for signature, algorithm, and protected-header validation before returning the
verified payload and certificate chain.

## Deliberately retained dynamic values

The remaining `any` uses have distinct roles:

- Generic constraints such as `Handler[I, O any]` describe statically typed
  APIs and do not make their parameters untyped.
- Registry internals erase heterogeneous handler types and recover them only
  through typed, revision-bound lookup.
- CBOR/COSE decoding and format statement parsing inspect heterogeneous wire
  dictionaries. The concrete codec remains optional; no new general-purpose
  value system or codec is implemented.
- Raw extension adapters, defensive copying, and storage wire-tree encoding
  handle unknown formats. Known domain types do not require caller assertions.
- Standard JSON/X.509 adapters and independently generated malformed-input
  fixtures use dynamic values at their natural boundaries.

Do not replace `any` with a differently named empty interface or an alias to
make a source count look smaller. New fixed-schema data should be a struct;
new extension points should have a behavioral contract or an explicit raw
encoding boundary.
