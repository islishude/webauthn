// Command checkinstall verifies a fixed published revision from a fresh consumer
// module. It is an explicitly network-dependent release check, outside make ci.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

const modulePath = "github.com/islishude/webauthn"

var fixedVersion = regexp.MustCompile(`^(?:[0-9a-f]{40}|v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)$`)

func main() {
	if err := check(os.Getenv("RELEASE_VERSION")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func check(version string) (resultErr error) {
	if !fixedVersion.MatchString(version) {
		return errors.New("RELEASE_VERSION must be an exact vX.Y.Z version (optional prerelease/pseudo-version) or a full lowercase 40-character commit ID")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	temp, err := os.MkdirTemp("", "webauthn-release-install-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(temp)) }()
	consumer := filepath.Join(temp, "tests", "consumer")
	if err = os.MkdirAll(consumer, 0o700); err != nil {
		return err
	}
	for _, name := range []string{"tests/consumer/consumer_test.go", "tests/consumer/lifecycle_test.go", "testdata/browser/virtual-authenticator/fixtures.json"} {
		data, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // Only the fixed repository-relative fixture/test paths above are read.
		if err != nil {
			return err
		}
		target := filepath.Join(temp, name)
		if err = os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err = os.WriteFile(target, data, 0o600); err != nil { //nolint:gosec // Target joins a fresh private temp directory with a fixed relative path.
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	run := func(args ...string) error {
		cmd := exec.CommandContext(ctx, "go", args...) //nolint:gosec // Fixed executable and arguments; revision is strictly validated, no shell.
		cmd.Dir = consumer
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	if err = run("mod", "init", "example.com/webauthn-release-consumer"); err != nil {
		return err
	}
	if err = run("get", modulePath+"@"+version); err != nil {
		return err
	}
	requested, err := resolve(ctx, consumer)
	if err != nil {
		return err
	}
	if err = run("mod", "tidy"); err != nil {
		return err
	}
	resolved, err := resolve(ctx, consumer)
	if err != nil {
		return err
	}
	if resolved.Version != requested.Version {
		return fmt.Errorf("requested revision resolved to %s but consumer dependencies selected %s", requested.Version, resolved.Version)
	}
	fmt.Printf("release-install-check: %s@%s\n", resolved.Path, resolved.Version)
	return run("test", "-mod=readonly", "-count=1", "./...")
}

type moduleResolution struct {
	Path    string
	Version string
	Replace json.RawMessage
}

func resolve(ctx context.Context, consumer string) (moduleResolution, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-json", modulePath)
	cmd.Dir = consumer
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	output, err := cmd.Output()
	if err != nil {
		return moduleResolution{}, err
	}
	var resolved moduleResolution
	if err = json.Unmarshal(output, &resolved); err != nil {
		return moduleResolution{}, err
	}
	if resolved.Path != modulePath || resolved.Version == "" || len(resolved.Replace) != 0 {
		return moduleResolution{}, errors.New("release dependency must resolve to a version without replace")
	}
	return resolved, nil
}
