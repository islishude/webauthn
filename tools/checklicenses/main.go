package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

type manifest struct {
	Modules []manifestModule `json:"modules"`
}

type manifestModule struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	License string `json:"license"`
	Scope   string `json:"scope"`
	Notes   string `json:"notes"`
}

type listedModule struct {
	Path    string
	Version string
	Main    bool
}

func main() {
	manifestPath := flag.String("manifest", "docs/dependencies.json", "dependency license manifest path")
	flag.Parse()

	if err := run(*manifestPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(manifestPath string) error {
	declared, err := readManifest(manifestPath)
	if err != nil {
		return err
	}
	modules, err := goListModules()
	if err != nil {
		return err
	}

	seen := make(map[string]struct{})
	for _, module := range modules {
		if module.Main {
			continue
		}
		entry, ok := declared[module.Path]
		if !ok {
			return fmt.Errorf("license manifest missing module %s %s", module.Path, module.Version)
		}
		if entry.Version != module.Version {
			return fmt.Errorf("license manifest version mismatch for %s: manifest %s, go list %s", module.Path, entry.Version, module.Version)
		}
		if entry.License == "" || entry.Scope == "" {
			return fmt.Errorf("license manifest entry for %s must include license and scope", module.Path)
		}
		seen[module.Path] = struct{}{}
	}

	for path, entry := range declared {
		if _, ok := seen[path]; !ok {
			return fmt.Errorf("license manifest contains stale module %s %s", path, entry.Version)
		}
	}

	fmt.Printf("license-check: %d dependency modules covered by %s\n", len(seen), manifestPath)
	return nil
}

func readManifest(path string) (map[string]manifestModule, error) {
	// #nosec G304 -- the manifest path is an explicit local developer/CI input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var decoded manifest
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, err
	}

	out := make(map[string]manifestModule, len(decoded.Modules))
	for _, module := range decoded.Modules {
		if module.Path == "" || module.Version == "" {
			return nil, errors.New("license manifest entries must include path and version")
		}
		if _, exists := out[module.Path]; exists {
			return nil, fmt.Errorf("license manifest duplicates module %s", module.Path)
		}
		out[module.Path] = module
	}

	return out, nil
}

func goListModules() ([]listedModule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-json", "all")
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("go list -m -json all failed: %w\n%s", err, exitErr.Stderr)
		}

		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(output))
	var modules []listedModule
	for {
		var module listedModule
		if err := decoder.Decode(&module); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, err
		}
		modules = append(modules, module)
	}

	return modules, nil
}
