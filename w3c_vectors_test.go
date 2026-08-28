package webauthn_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const (
	w3cVectorDirectory = "testdata/w3c/webauthn-level3"
	w3cRecommendation  = "https://www.w3.org/TR/2026/REC-webauthn-3-20260825/"
	w3cVectorLicense   = "W3C permissive document license"
)

type w3cVectorMetadata struct {
	Source      string `json:"source"`
	SourceURL   string `json:"sourceURL"`
	License     string `json:"license"`
	Sensitivity string `json:"sensitivity"`
}

type w3cCeremonyFixture struct {
	w3cVectorMetadata
	RPID                       string              `json:"rpId"`
	Origin                     string              `json:"origin"`
	TopOrigin                  string              `json:"topOrigin"`
	AttestationRootCertificate string              `json:"attestationRootCertificate"`
	Vectors                    []w3cCeremonyVector `json:"vectors"`
}

type w3cCeremonyVector struct {
	Section                      string `json:"section"`
	Name                         string `json:"name"`
	RegistrationCaseID           string `json:"registrationCaseId"`
	AuthenticationCaseID         string `json:"authenticationCaseId"`
	Algorithm                    int64  `json:"algorithm"`
	Format                       string `json:"format"`
	ExpectedAttestationType      string `json:"expectedAttestationType"`
	RegistrationExpectation      string `json:"registrationExpectation"`
	RegistrationChallenge        string `json:"registrationChallenge"`
	CredentialID                 string `json:"credentialId"`
	RegistrationClientDataJSON   string `json:"registrationClientDataJSON"`
	AttestationObject            string `json:"attestationObject"`
	AuthenticationChallenge      string `json:"authenticationChallenge"`
	AuthenticationClientDataJSON string `json:"authenticationClientDataJSON"`
	AuthenticatorData            string `json:"authenticatorData"`
	Signature                    string `json:"signature"`
}

type w3cPRFAPIFixture struct {
	w3cVectorMetadata
	Notes string          `json:"notes"`
	Cases []w3cPRFAPICase `json:"cases"`
}

type w3cPRFAPICase struct {
	ID                 string              `json:"id"`
	Operation          string              `json:"operation"`
	Input              w3cPRFInputFixture  `json:"input"`
	AllowCredentials   []string            `json:"allowCredentials"`
	SelectedCredential string              `json:"selectedCredential"`
	Output             w3cPRFOutputFixture `json:"output"`
}

type w3cPRFInputFixture struct {
	Eval             *w3cPRFValuesFixture           `json:"eval"`
	EvalByCredential map[string]w3cPRFValuesFixture `json:"evalByCredential"`
}

type w3cPRFValuesFixture struct {
	First  string `json:"first"`
	Second string `json:"second"`
}

type w3cPRFOutputFixture struct {
	EnabledPresent bool                      `json:"enabledPresent"`
	Enabled        bool                      `json:"enabled"`
	ResultsPresent bool                      `json:"resultsPresent"`
	Results        w3cPRFOutputValuesFixture `json:"results"`
}

type w3cPRFOutputValuesFixture struct {
	FirstPresent  bool   `json:"firstPresent"`
	SecondPresent bool   `json:"secondPresent"`
	FirstHex      string `json:"firstHex"`
	SecondHex     string `json:"secondHex"`
}

type w3cPRFCTAPFixture struct {
	w3cVectorMetadata
	Scope                               string           `json:"scope"`
	Seed                                string           `json:"seed"`
	PlatformKeyAgreementPrivateKey      string           `json:"platformKeyAgreementPrivateKey"`
	AuthenticatorKeyAgreementPublicKeyX string           `json:"authenticatorKeyAgreementPublicKeyX"`
	AuthenticatorKeyAgreementPublicKeyY string           `json:"authenticatorKeyAgreementPublicKeyY"`
	AuthenticatorCredRandom             string           `json:"authenticatorCredRandom"`
	Cases                               []w3cPRFCTAPCase `json:"cases"`
}

type w3cPRFCTAPCase struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	PINProtocol            int    `json:"pinProtocol"`
	PRFEvalFirst           string `json:"prfEvalFirst"`
	PRFEvalSecond          string `json:"prfEvalSecond"`
	SharedSecret           string `json:"sharedSecret"`
	Salt1                  string `json:"salt1"`
	Salt2                  string `json:"salt2"`
	SaltEnc                string `json:"saltEnc"`
	Output1                string `json:"output1"`
	Output2                string `json:"output2"`
	OutputEnc              string `json:"outputEnc"`
	PRFResultsFirst        string `json:"prfResultsFirst"`
	PRFResultsSecond       string `json:"prfResultsSecond"`
	SaltIVDerivationByte   int    `json:"saltIVDerivationByte"`
	OutputIVDerivationByte int    `json:"outputIVDerivationByte"`
}

type w3cCoverageFixture struct {
	w3cVectorMetadata
	ExpectedCount  int               `json:"expectedCount"`
	CategoryCounts map[string]int    `json:"categoryCounts"`
	Cases          []w3cCoverageCase `json:"cases"`
}

type w3cCoverageCase struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Expectation string `json:"expectation"`
}

func TestW3CLevel3VectorInventory(t *testing.T) {
	t.Parallel()

	coverage := loadW3CFixture[w3cCoverageFixture](t, "coverage.json")
	ceremonies := loadW3CFixture[w3cCeremonyFixture](t, "ceremonies.json")
	prfAPI := loadW3CFixture[w3cPRFAPIFixture](t, "prf-api.json")
	prfCTAP := loadW3CFixture[w3cPRFCTAPFixture](t, "prf-ctap.json")
	for _, metadata := range []w3cVectorMetadata{
		coverage.w3cVectorMetadata,
		ceremonies.w3cVectorMetadata,
		prfAPI.w3cVectorMetadata,
		prfCTAP.w3cVectorMetadata,
	} {
		if !strings.HasPrefix(metadata.SourceURL, w3cRecommendation) || metadata.License != w3cVectorLicense {
			t.Fatalf("fixture provenance = %+v", metadata)
		}
	}

	discovered := make(map[string]string, coverage.ExpectedCount)
	discoveredCategoryCounts := make(map[string]int, len(coverage.CategoryCounts))
	add := func(id, category string) {
		t.Helper()
		if id == "" {
			t.Fatal("empty W3C vector case ID")
		}
		if previous, exists := discovered[id]; exists {
			t.Fatalf("duplicate W3C vector case ID %q in %s and %s", id, previous, category)
		}
		discovered[id] = category
		discoveredCategoryCounts[category]++
	}
	for _, vector := range ceremonies.Vectors {
		add(vector.RegistrationCaseID, "ceremony-registration")
		add(vector.AuthenticationCaseID, "ceremony-authentication")
	}
	for _, vector := range prfAPI.Cases {
		add(vector.ID, "prf-web-api")
	}
	for _, vector := range prfCTAP.Cases {
		add(vector.ID, "prf-ctap")
	}

	if coverage.ExpectedCount != 45 || len(coverage.Cases) != coverage.ExpectedCount || len(discovered) != coverage.ExpectedCount {
		t.Fatalf("W3C vector count: expected=%d manifest=%d discovered=%d, want 45", coverage.ExpectedCount, len(coverage.Cases), len(discovered))
	}
	wantCategoryCounts := map[string]int{
		"ceremony-registration":   15,
		"ceremony-authentication": 15,
		"prf-web-api":             12,
		"prf-ctap":                3,
	}
	for category, want := range wantCategoryCounts {
		if coverage.CategoryCounts[category] != want || discoveredCategoryCounts[category] != want {
			t.Fatalf("category %q count: manifest=%d discovered=%d, want %d", category, coverage.CategoryCounts[category], discoveredCategoryCounts[category], want)
		}
	}
	rejected := 0
	for _, vector := range coverage.Cases {
		category, ok := discovered[vector.ID]
		if !ok {
			t.Fatalf("manifest case %q is not backed by a fixture", vector.ID)
		}
		if category != vector.Category {
			t.Fatalf("manifest case %q category = %q, fixture = %q", vector.ID, vector.Category, category)
		}
		switch vector.Expectation {
		case "accept":
		case "reject-nonconformant-tpm-der":
			rejected++
			if vector.ID != "16.13-registration" {
				t.Fatalf("unexpected strict-rejection case %q", vector.ID)
			}
		default:
			t.Fatalf("manifest case %q has unknown expectation %q", vector.ID, vector.Expectation)
		}
		delete(discovered, vector.ID)
	}
	if rejected != 1 {
		t.Fatalf("strict-rejection cases = %d, want 1", rejected)
	}
	if len(discovered) != 0 {
		t.Fatalf("fixture cases missing from manifest: %v", discovered)
	}
}

func loadW3CFixture[T any](t *testing.T, name string) T {
	t.Helper()
	data, err := os.ReadFile(w3cVectorDirectory + "/" + name) //nolint:gosec // Test-internal callers supply fixed fixture filenames.
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", name, err)
	}
	var fixture T
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", name, err)
	}
	return fixture
}

func decodeW3CHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}
	return decoded
}
