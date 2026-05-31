package attestation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	webcrypto "github.com/islishude/webauthn/crypto"
	"github.com/islishude/webauthn/protocol"
)

var (
	// ErrTrustPolicyConfiguration reports an unusable built-in trust policy.
	ErrTrustPolicyConfiguration = errors.New("attestation trust policy configuration invalid")
)

// MetadataRequest is the lookup input for caller-owned authenticator metadata.
type MetadataRequest struct {
	Format    string
	Type      Type
	AAGUID    protocol.AAGUID
	TrustPath TrustPath
	Evidence  map[string]any
}

// MetadataResult is the caller-owned metadata decision for attestation trust.
type MetadataResult struct {
	Found    bool
	Trusted  bool
	Reason   string
	Warnings []string
}

// MetadataProvider looks up caller-managed metadata for attestation evidence.
type MetadataProvider interface {
	LookupAttestationMetadata(context.Context, MetadataRequest) (MetadataResult, error)
}

// CertificateStatus identifies certificate status as reported by caller policy.
type CertificateStatus string

const (
	// CertificateStatusGood means the checked certificate path is acceptable.
	CertificateStatusGood CertificateStatus = "good"
	// CertificateStatusRevoked means at least one relevant certificate is revoked.
	CertificateStatusRevoked CertificateStatus = "revoked"
	// CertificateStatusUnknown means status could not be proven good or revoked.
	CertificateStatusUnknown CertificateStatus = "unknown"
	// CertificateStatusUnavailable means the status source was unavailable.
	CertificateStatusUnavailable CertificateStatus = "unavailable"
)

// CertificateStatusRequest is the certificate status check input.
type CertificateStatusRequest struct {
	Format       string
	Type         Type
	AAGUID       protocol.AAGUID
	TrustPath    TrustPath
	Certificates webcrypto.CertificateChain
	Evidence     map[string]any
}

// CertificateStatusResult is the caller-owned certificate status decision.
type CertificateStatusResult struct {
	Status   CertificateStatus
	Reason   string
	Warnings []string
}

// CertificateStatusProvider checks status for attestation certificate paths.
type CertificateStatusProvider interface {
	CheckCertificateStatus(context.Context, CertificateStatusRequest) (CertificateStatusResult, error)
}

// AcceptNone returns a policy that accepts only none attestation.
func AcceptNone() TrustPolicy {
	return allowTypesPolicy{
		allowed:      typeSet(TypeNone),
		acceptReason: "none attestation accepted by policy",
		rejectReason: "none attestation required by policy",
	}
}

// RejectNone returns a policy that rejects none attestation and accepts others.
func RejectNone() TrustPolicy {
	return rejectTypesPolicy{
		rejected:     typeSet(TypeNone),
		acceptReason: "non-none attestation accepted by policy",
		rejectReason: "none attestation rejected by policy",
	}
}

// AcceptSelf returns a policy that accepts only self attestation.
func AcceptSelf() TrustPolicy {
	return allowTypesPolicy{
		allowed:      typeSet(TypeSelf),
		acceptReason: "self attestation accepted by policy",
		rejectReason: "self attestation required by policy",
	}
}

// RejectSelf returns a policy that rejects self attestation and accepts others.
func RejectSelf() TrustPolicy {
	return rejectTypesPolicy{
		rejected:     typeSet(TypeSelf),
		acceptReason: "non-self attestation accepted by policy",
		rejectReason: "self attestation rejected by policy",
	}
}

// AllowTypes returns a policy that accepts only the listed attestation types.
func AllowTypes(types ...Type) TrustPolicy {
	return allowTypesPolicy{
		allowed:      typeSet(types...),
		acceptReason: "attestation type accepted by policy",
		rejectReason: "attestation type rejected by policy",
	}
}

// AllowFormats returns a policy that accepts only the listed format identifiers.
func AllowFormats(formats ...string) TrustPolicy {
	return allowFormatsPolicy{
		allowed:      formatSet(formats...),
		acceptReason: "attestation format accepted by policy",
		rejectReason: "attestation format rejected by policy",
	}
}

// RequireAAGUID returns a policy that accepts only the listed AAGUID values.
func RequireAAGUID(aaguids ...protocol.AAGUID) TrustPolicy {
	return aaguidPolicy{allowed: aaguidSet(aaguids...)}
}

// RequireTrustedRoots returns a policy that accepts trusted x5c trust paths.
func RequireTrustedRoots(verifier webcrypto.CertificateVerifier, verificationContext webcrypto.CertificateVerificationContext) TrustPolicy {
	return trustRootsPolicy{verifier: verifier, verificationContext: verificationContext}
}

// RequireTrustedMetadata returns a policy that accepts metadata marked trusted
// by the caller-provided metadata provider.
func RequireTrustedMetadata(provider MetadataProvider) TrustPolicy {
	return metadataPolicy{provider: provider}
}

// RequireCertificateStatus returns a policy that accepts allowed certificate
// status values. When no allowed statuses are provided, only good is accepted.
func RequireCertificateStatus(provider CertificateStatusProvider, allowed ...CertificateStatus) TrustPolicy {
	if len(allowed) == 0 {
		allowed = []CertificateStatus{CertificateStatusGood}
	}

	return certificateStatusPolicy{
		provider: provider,
		allowed:  certificateStatusSet(allowed...),
	}
}

// AllOf returns a policy that accepts only when every child policy accepts.
func AllOf(policies ...TrustPolicy) TrustPolicy {
	return allOfPolicy{policies: slices.Clone(policies)}
}

// AnyOf returns a policy that accepts when the first child policy accepts.
func AnyOf(policies ...TrustPolicy) TrustPolicy {
	return anyOfPolicy{policies: slices.Clone(policies)}
}

type allowTypesPolicy struct {
	allowed      map[Type]struct{}
	acceptReason string
	rejectReason string
}

func (p allowTypesPolicy) EvaluateAttestationTrust(_ context.Context, request TrustRequest) (TrustResult, error) {
	if _, ok := p.allowed[request.Result.Type]; !ok {
		return rejected(p.rejectReason), nil
	}

	return accepted(p.acceptReason), nil
}

type rejectTypesPolicy struct {
	rejected     map[Type]struct{}
	acceptReason string
	rejectReason string
}

func (p rejectTypesPolicy) EvaluateAttestationTrust(_ context.Context, request TrustRequest) (TrustResult, error) {
	if _, ok := p.rejected[request.Result.Type]; ok {
		return rejected(p.rejectReason), nil
	}

	return accepted(p.acceptReason), nil
}

type allowFormatsPolicy struct {
	allowed      map[string]struct{}
	acceptReason string
	rejectReason string
}

func (p allowFormatsPolicy) EvaluateAttestationTrust(_ context.Context, request TrustRequest) (TrustResult, error) {
	if _, ok := p.allowed[request.Format]; !ok {
		return rejected(p.rejectReason), nil
	}

	return accepted(p.acceptReason), nil
}

type aaguidPolicy struct {
	allowed map[protocol.AAGUID]struct{}
}

func (p aaguidPolicy) EvaluateAttestationTrust(_ context.Context, request TrustRequest) (TrustResult, error) {
	if _, ok := p.allowed[request.AAGUID]; !ok {
		return rejected("aaguid rejected by policy"), nil
	}

	return accepted("aaguid accepted by policy"), nil
}

type trustRootsPolicy struct {
	verifier            webcrypto.CertificateVerifier
	verificationContext webcrypto.CertificateVerificationContext
}

func (p trustRootsPolicy) EvaluateAttestationTrust(ctx context.Context, request TrustRequest) (TrustResult, error) {
	if p.verifier == nil {
		return TrustResult{}, ErrTrustPolicyConfiguration
	}
	if request.Result.TrustPath.Kind != TrustPathX509 || len(request.Result.TrustPath.Certificates) == 0 {
		return rejected("x5c trust path required by policy"), nil
	}

	verification, err := p.verifier.VerifyCertificateChain(normalizeContext(ctx), slices.Clone(request.Result.TrustPath.Certificates), p.verificationContext)
	if err != nil {
		return TrustResult{}, err
	}
	if !verification.Trusted {
		return trustResult(false, "x5c trust path rejected by policy", verification.Warnings), nil
	}

	return trustResult(true, "x5c trust path accepted by policy", verification.Warnings), nil
}

type metadataPolicy struct {
	provider MetadataProvider
}

func (p metadataPolicy) EvaluateAttestationTrust(ctx context.Context, request TrustRequest) (TrustResult, error) {
	if p.provider == nil {
		return TrustResult{}, ErrTrustPolicyConfiguration
	}

	metadata, err := p.provider.LookupAttestationMetadata(normalizeContext(ctx), MetadataRequest{
		Format:    request.Format,
		Type:      request.Result.Type,
		AAGUID:    request.AAGUID,
		TrustPath: cloneTrustPath(request.Result.TrustPath),
		Evidence:  maps.Clone(request.Result.Evidence),
	})
	if err != nil {
		return TrustResult{}, err
	}
	if !metadata.Found {
		return trustResult(false, reasonOrDefault(metadata.Reason, "attestation metadata not found"), metadata.Warnings), nil
	}
	if !metadata.Trusted {
		return trustResult(false, reasonOrDefault(metadata.Reason, "attestation metadata rejected by policy"), metadata.Warnings), nil
	}

	return trustResult(true, reasonOrDefault(metadata.Reason, "attestation metadata accepted by policy"), metadata.Warnings), nil
}

type certificateStatusPolicy struct {
	provider CertificateStatusProvider
	allowed  map[CertificateStatus]struct{}
}

func (p certificateStatusPolicy) EvaluateAttestationTrust(ctx context.Context, request TrustRequest) (TrustResult, error) {
	if p.provider == nil {
		return TrustResult{}, ErrTrustPolicyConfiguration
	}
	if request.Result.TrustPath.Kind != TrustPathX509 || len(request.Result.TrustPath.Certificates) == 0 {
		return rejected("x5c trust path required by policy"), nil
	}

	trustPath := cloneTrustPath(request.Result.TrustPath)
	result, err := p.provider.CheckCertificateStatus(normalizeContext(ctx), CertificateStatusRequest{
		Format:       request.Format,
		Type:         request.Result.Type,
		AAGUID:       request.AAGUID,
		TrustPath:    trustPath,
		Certificates: slices.Clone(trustPath.Certificates),
		Evidence:     maps.Clone(request.Result.Evidence),
	})
	if err != nil {
		return TrustResult{}, err
	}

	status := result.Status
	if status == "" {
		status = CertificateStatusUnknown
	}
	if _, ok := p.allowed[status]; !ok {
		return trustResult(false, reasonOrDefault(result.Reason, fmt.Sprintf("certificate status %q rejected by policy", status)), result.Warnings), nil
	}

	return trustResult(true, reasonOrDefault(result.Reason, fmt.Sprintf("certificate status %q accepted by policy", status)), result.Warnings), nil
}

type allOfPolicy struct {
	policies []TrustPolicy
}

func (p allOfPolicy) EvaluateAttestationTrust(ctx context.Context, request TrustRequest) (TrustResult, error) {
	if len(p.policies) == 0 {
		return TrustResult{}, fmt.Errorf("%w: all-of policy requires at least one child policy", ErrTrustPolicyConfiguration)
	}

	warnings := []string{}
	for index, policy := range p.policies {
		if policy == nil {
			return TrustResult{}, fmt.Errorf("%w: nil policy at index %d", ErrTrustPolicyConfiguration, index)
		}

		result, err := policy.EvaluateAttestationTrust(ctx, request)
		if err != nil {
			return TrustResult{}, err
		}
		warnings = append(warnings, result.Warnings...)
		if !result.Accepted {
			result.Warnings = warnings
			return result, nil
		}
	}

	return trustResult(true, "all trust policies accepted", warnings), nil
}

type anyOfPolicy struct {
	policies []TrustPolicy
}

func (p anyOfPolicy) EvaluateAttestationTrust(ctx context.Context, request TrustRequest) (TrustResult, error) {
	warnings := []string{}
	for index, policy := range p.policies {
		if policy == nil {
			return TrustResult{}, fmt.Errorf("%w: nil policy at index %d", ErrTrustPolicyConfiguration, index)
		}

		result, err := policy.EvaluateAttestationTrust(ctx, request)
		if err != nil {
			return TrustResult{}, err
		}
		if result.Accepted {
			return result, nil
		}
		warnings = append(warnings, result.Warnings...)
	}

	return trustResult(false, "no trust policy accepted attestation", warnings), nil
}

func accepted(reason string) TrustResult {
	return trustResult(true, reason, nil)
}

func rejected(reason string) TrustResult {
	return trustResult(false, reason, nil)
}

func trustResult(accepted bool, reason string, warnings []string) TrustResult {
	return TrustResult{
		Accepted: accepted,
		Reason:   reason,
		Warnings: slices.Clone(warnings),
	}
}

func reasonOrDefault(reason string, fallback string) string {
	if reason != "" {
		return reason
	}

	return fallback
}

func cloneTrustPath(path TrustPath) TrustPath {
	path.Certificates = slices.Clone(path.Certificates)

	return path
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}

	return ctx
}

func typeSet(types ...Type) map[Type]struct{} {
	out := make(map[Type]struct{}, len(types))
	for _, typ := range types {
		out[typ] = struct{}{}
	}

	return out
}

func formatSet(formats ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(formats))
	for _, format := range formats {
		out[format] = struct{}{}
	}

	return out
}

func aaguidSet(aaguids ...protocol.AAGUID) map[protocol.AAGUID]struct{} {
	out := make(map[protocol.AAGUID]struct{}, len(aaguids))
	for _, aaguid := range aaguids {
		out[aaguid] = struct{}{}
	}

	return out
}

func certificateStatusSet(statuses ...CertificateStatus) map[CertificateStatus]struct{} {
	out := make(map[CertificateStatus]struct{}, len(statuses))
	for _, status := range statuses {
		out[status] = struct{}{}
	}

	return out
}
