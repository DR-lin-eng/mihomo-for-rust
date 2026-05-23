//go:build !legacy_go_runtime
// +build !legacy_go_runtime

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func main() {
	runtimePath, err := resolveRustRuntime()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	command := exec.Command(runtimePath, os.Args[1:]...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = os.Environ()
	if err := command.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "failed to launch Rust runtime %q: %v\n", runtimePath, err)
		os.Exit(1)
	}
}

func resolveRustRuntime() (string, error) {
	if explicit := os.Getenv("MIHOMO_RUST_BINARY"); explicit != "" {
		if path, ok := firstExecutableCandidate([]string{explicit}); ok {
			return path, nil
		}
		return "", fmt.Errorf("MIHOMO_RUST_BINARY points to a missing or non-executable file: %s", explicit)
	}

	var searchRoots []string
	if cwd, err := os.Getwd(); err == nil {
		searchRoots = append(searchRoots, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		searchRoots = append(searchRoots, exeDir, filepath.Dir(exeDir))
	}

	executableName := "mihomo"
	if runtime.GOOS == "windows" {
		executableName += ".exe"
	}

	for _, root := range searchRoots {
		candidates := []string{
			filepath.Join(root, "bin", executableName),
			filepath.Join(root, "rust", "target", "release", executableName),
			filepath.Join(root, "rust", "target-docker-build", "release", executableName),
			filepath.Join(root, "rust", "target-docker-release", "x86_64-unknown-linux-gnu", "release", executableName),
		}
		if path, ok := firstExecutableCandidate(candidates); ok {
			return path, nil
		}
	}

	return "", fmt.Errorf(
		"the default mihomo runtime has moved to Rust, but no built Rust binary was found; run `make build` or `cargo build --manifest-path rust/Cargo.toml -p mihomo-app --bin mihomo --release`, or set MIHOMO_RUST_BINARY explicitly",
	)
}

func firstExecutableCandidate(candidates []string) (string, bool) {
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		if runtime.GOOS == "windows" || info.Mode()&0o111 != 0 {
			return candidate, true
		}
	}
	return "", false
}
