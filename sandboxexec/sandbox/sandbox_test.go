// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sandbox_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

func TestMain(m *testing.M) {
	if path, err := testutil.FindFile("runsc/runsc"); err == nil {
		os.Setenv("RUNSC_PATH", path)
	}
	os.Exit(m.Run())
}

func TestExecDmesg(t *testing.T) {
	ctx := context.Background()

	enableNetworking := os.Geteuid() == 0
	// Create the background sandbox via subprocess
	sb, err := sandbox.New(ctx, sandbox.WithNetworking(enableNetworking))
	if err != nil {
		t.Fatalf("failed to create sandbox: %v", err)
	}

	defer func() {
		if err := sb.Close(ctx); err != nil {
			t.Fatalf("failed to clean up sandbox: %v", err)
		}
	}()

	// Execute dmesg in the gVisor sandbox.
	output, _, err := sb.Exec(ctx, "dmesg")
	if err != nil {
		t.Fatalf("failed to execute command in sandbox: %v", err)
	}

	if !strings.Contains(output, "Starting gVisor") {
		t.Errorf("Exec(\"dmesg\") =  %v; wanted: %v", output, "Starting gVisor")
	}
}

func TestSandboxOptions(t *testing.T) {
	ctx := context.Background()
	runtimeDir := t.TempDir()
	id := "iwillbeasandbox"
	enableNetworking := os.Geteuid() == 0

	opts := []sandbox.Option{
		sandbox.WithID(id),
		sandbox.WithRuntimeDir(runtimeDir),
		sandbox.WithNetworking(enableNetworking),
	}

	sb, err := sandbox.New(ctx, opts...)
	if err != nil {
		t.Fatalf("failed to create sandbox: %v", err)
	}

	defer func() {
		if err := sb.Close(ctx); err != nil {
			t.Fatalf("failed to clean up sandbox: %v", err)
		}
	}()

	if got := sb.Bundle(); !strings.HasPrefix(got, runtimeDir) {
		t.Errorf("sb.Bundle() = %v; want prefix %v", got, runtimeDir)
	}
}

func TestNonRootNetworkingError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("Skipping test: this test must be run as non-root")
	}

	ctx := context.Background()
	_, err := sandbox.New(ctx, sandbox.WithNetworking(true))
	if err == nil {
		t.Fatalf("sandbox.New succeeded as non-root with networking enabled; want error")
	}

	expectedErr := "enabling networking requires running as root"
	if !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("sandbox.New error = %v; want error containing %q", err, expectedErr)
	}
}

func TestCustomBindMount(t *testing.T) {
	ctx := context.Background()
	tempHostDir := t.TempDir()

	// Write witness file on host
	witnessFile := filepath.Join(tempHostDir, "witness.txt")
	expectedContent := "hello-mount"
	if err := os.WriteFile(witnessFile, []byte(expectedContent), 0644); err != nil {
		t.Fatalf("failed to write witness file: %v", err)
	}

	sb, err := sandbox.New(ctx,
		sandbox.WithNetworking(false),
		sandbox.WithBindMount(tempHostDir, "/mnt/host_share", true),
	)
	if err != nil {
		t.Fatalf("failed to start sandbox: %v", err)
	}
	defer func() {
		if err := sb.Close(ctx); err != nil {
			t.Fatalf("failed to clean up sandbox: %v", err)
		}
	}()

	// Read witness inside container
	output, _, err := sb.Exec(ctx, "cat", "/mnt/host_share/witness.txt")
	if err != nil {
		t.Fatalf("failed to exec read in sandbox: %v", err)
	}
	if strings.TrimSpace(output) != expectedContent {
		t.Errorf("got %q, want %q", output, expectedContent)
	}
}

func TestCustomTmpfsMount(t *testing.T) {
	ctx := context.Background()

	sb, err := sandbox.New(ctx,
		sandbox.WithNetworking(false),
		sandbox.WithTmpfsMount("/mnt/scratch"),
	)
	if err != nil {
		t.Fatalf("failed to start sandbox: %v", err)
	}
	defer func() {
		if err := sb.Close(ctx); err != nil {
			t.Fatalf("failed to clean up sandbox: %v", err)
		}
	}()

	// Write file to scratch space and cat it back
	_, _, err = sb.Exec(ctx, "sh", "-c", "echo hello-tmpfs > /mnt/scratch/tmp.txt")
	if err != nil {
		t.Fatalf("failed to write inside tmpfs: %v", err)
	}

	output, _, err := sb.Exec(ctx, "cat", "/mnt/scratch/tmp.txt")
	if err != nil {
		t.Fatalf("failed to read from tmpfs: %v", err)
	}
	if strings.TrimSpace(output) != "hello-tmpfs" {
		t.Errorf("got %q, want %q", output, "hello-tmpfs")
	}
}

func TestCustomBindMountWrite(t *testing.T) {
	ctx := context.Background()
	tempHostDir := t.TempDir()

	sb, err := sandbox.New(ctx,
		sandbox.WithNetworking(false),
		sandbox.WithBindMount(tempHostDir, "/mnt/host_share", false),
	)
	if err != nil {
		t.Fatalf("failed to start sandbox: %v", err)
	}
	defer func() {
		if err := sb.Close(ctx); err != nil {
			t.Fatalf("failed to clean up sandbox: %v", err)
		}
	}()

	// Write file inside container
	_, _, err = sb.Exec(ctx, "sh", "-c", "echo hello-write > /mnt/host_share/file.txt")
	if err != nil {
		t.Fatalf("failed to write inside sandbox: %v", err)
	}

	// Verify file was written to the host
	hostFile := filepath.Join(tempHostDir, "file.txt")
	data, err := os.ReadFile(hostFile)
	if err != nil {
		t.Fatalf("failed to read witness file on host: %v", err)
	}

	if got, want := strings.TrimSpace(string(data)), "hello-write"; got != want {
		t.Errorf("ReadFile(%q) = %q, want %q", hostFile, got, want)
	}
}

func TestSandboxEnv(t *testing.T) {
	ctx := context.Background()

	sb, err := sandbox.New(ctx,
		sandbox.WithNetworking(false),
		sandbox.WithEnv(
			"TEST_VAR=value1",
			"TEST_VAR=value2", // Duplicate var to test append behavior
			"ANOTHER_VAR=abc",
		),
	)
	if err != nil {
		t.Fatalf("failed to start sandbox: %v", err)
	}
	defer func() {
		if err := sb.Close(ctx); err != nil {
			t.Fatalf("failed to clean up sandbox: %v", err)
		}
	}()

	// Read environment in the sandbox
	output, _, err := sb.Exec(ctx, "env")
	if err != nil {
		t.Fatalf("failed to exec env in sandbox: %v", err)
	}

	lines := strings.Split(output, "\n")
	envMap := make(map[string]string)
	for _, l := range lines {
		if l == "" {
			continue
		}
		parts := strings.SplitN(l, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// Verify duplicated variable is handled correctly (typically last value wins in most systems)
	if got, want := envMap["TEST_VAR"], "value2"; got != want {
		t.Errorf("TEST_VAR = %v, want %v", got, want)
	}

	// Verify normal variable injection
	if got, want := envMap["ANOTHER_VAR"], "abc"; got != want {
		t.Errorf("ANOTHER_VAR = %v, want %v", got, want)
	}

	// Verify default env vars
	if _, ok := envMap["PATH"]; !ok {
		t.Errorf("PATH is missing but no unset was requested")
	}
}

func TestSandboxInvalidEnvFormat(t *testing.T) {
	ctx := context.Background()

	_, err := sandbox.New(ctx,
		sandbox.WithNetworking(false),
		sandbox.WithEnv("MALFORMED_INPUT_NO_EQUALS"),
	)
	if err == nil {
		t.Fatalf("sandbox.New succeeded with malformed environment variable; want error")
	}
	if !strings.Contains(err.Error(), "invalid environment variable format") {
		t.Errorf("sandbox.New error = %v; want error containing %q", err, "invalid environment variable format")
	}
}

func TestRootfsTarSnapshot(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	storageDir := filepath.Join(tempDir, "storage")
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		t.Fatalf("failed to create storage dir: %v", err)
	}
	storage, err := sandbox.NewFilesystemStorage(storageDir)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	runtimeDirA := filepath.Join(tempDir, "runtime-a")
	enableNetworking := os.Geteuid() == 0
	sbA, err := sandbox.New(ctx,
		sandbox.WithRuntimeDir(runtimeDirA),
		sandbox.WithNetworking(enableNetworking),
	)
	if err != nil {
		t.Fatalf("failed to start sandbox A: %v", err)
	}
	defer sbA.Close(ctx)

	_, _, err = sbA.Exec(ctx, "sh", "-c", "echo 'hello' > /test.txt")
	if err != nil {
		t.Fatalf("failed to create file in sandbox A: %v", err)
	}

	snapshot, err := sbA.Snapshot(ctx, sandbox.RootfsTarSnapshot, storage)
	if err != nil {
		t.Fatalf("failed to take snapshot: %v", err)
	}

	runtimeDirB := filepath.Join(tempDir, "runtime-b")
	sbB, err := sandbox.New(ctx,
		sandbox.WithRuntimeDir(runtimeDirB),
		sandbox.WithNetworking(enableNetworking),
		sandbox.WithSnapshot(snapshot),
	)
	if err != nil {
		t.Fatalf("failed to start sandbox B: %v", err)
	}
	defer sbB.Close(ctx)

	outB, _, err := sbB.Exec(ctx, "cat", "/test.txt")
	if err != nil {
		t.Fatalf("failed to cat file in sandbox B: %v", err)
	}
	if strings.TrimSpace(outB) != "hello" {
		t.Errorf("unexpected content in B: got %q, want %q", outB, "hello")
	}
}

func TestNoSnapshotStorageError(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	runtimeDir := filepath.Join(tempDir, "runtime")
	enableNetworking := os.Geteuid() == 0
	_, err := sandbox.New(ctx,
		sandbox.WithRuntimeDir(runtimeDir),
		sandbox.WithNetworking(enableNetworking),
		sandbox.WithSnapshot(&sandbox.Snapshot{ID: "some-snapshot-id"}),
	)
	if err == nil {
		t.Fatalf("expected error when starting sandbox with SnapshotID but no SnapshotStore or default storage configured, got nil")
	}
	expectedErrSubstr := "no snapshot storage configured for restore"
	if !strings.Contains(err.Error(), expectedErrSubstr) {
		t.Errorf("unexpected error: %v, want it to contain %q", err, expectedErrSubstr)
	}
}

func TestSandboxWorkingDir(t *testing.T) {
	ctx := context.Background()

	sb, err := sandbox.New(ctx,
		sandbox.WithNetworking(false),
		sandbox.WithWorkingDir("tmp/custom"),
	)
	if err != nil {
		t.Fatalf("failed to start sandbox: %v", err)
	}
	defer sb.Close(ctx)

	configPath := filepath.Join(sb.Bundle(), "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config.json: %v", err)
	}

	// Because of relative dir sanitization, it should be /tmp/custom
	if !strings.Contains(string(data), `cwd": "/tmp/custom"`) {
		t.Errorf("config.json does not contain custom working directory. got: %s", string(data))
	}
}

func TestSandboxBadWorkingDir(t *testing.T) {
	ctx := context.Background()

	_, err := sandbox.New(ctx,
		sandbox.WithNetworking(false),
		sandbox.WithWorkingDir(""),
	)
	if err == nil {
		t.Fatalf("sandbox.New succeeded with empty working directory; want error")
	}
	if !strings.Contains(err.Error(), "working directory cannot be empty") {
		t.Errorf("sandbox.New error = %v; want error containing %q", err, "working directory cannot be empty")
	}
}
