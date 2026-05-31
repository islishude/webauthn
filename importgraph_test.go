package webauthn_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRootPackageImportGraphExcludesOptionalPackages(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "list", "-deps", ".")
	cmd.Env = append(os.Environ(), "GOWORK=off")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, output)
	}

	forbiddenExact := map[string]struct{}{
		"net/http": {},
	}
	forbiddenPrefixes := []string{
		"github.com/islishude/webauthn/attestation/",
		"github.com/islishude/webauthn/transport",
		"github.com/islishude/webauthn/browser",
		"github.com/islishude/webauthn/http",
	}

	for dep := range strings.FieldsSeq(string(output)) {
		if _, forbidden := forbiddenExact[dep]; forbidden {
			t.Fatalf("root package must not import %s", dep)
		}
		for _, prefix := range forbiddenPrefixes {
			if strings.HasPrefix(dep, prefix) {
				t.Fatalf("root package must not import optional package %s", dep)
			}
		}
	}
}
