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
	sandbox.SetDefaultSnapshotStorage(storage)
	defer sandbox.SetDefaultSnapshotStorage(nil)

	runtimeDirA := filepath.Join(tempDir, "runtime-a")
	enableNetworking := os.Geteuid() == 0
	sbA, err := sandbox.New(ctx,
		sandbox.WithRuntimeDir(runtimeDirA),
		sandbox.WithNetworking(enableNetworking),
		sandbox.WithWritableRootfs(true),
	)
	if err != nil {
		t.Fatalf("failed to start sandbox A: %v", err)
	}
	defer sbA.Close(ctx)

	// Create a file inside Sandbox A.
	_, _, err = sbA.Exec(ctx, "sh", "-c", "echo 'hello' > /test.txt")
	if err != nil {
		t.Fatalf("failed to create file in sandbox A: %v", err)
	}

	// Verify the file was created in A.
	out, _, err := sbA.Exec(ctx, "cat", "/test.txt")
	if err != nil {
		t.Fatalf("failed to cat file in sandbox A: %v", err)
	}
	if strings.TrimSpace(out) != "hello" {
		t.Fatalf("unexpected content in A: %q", out)
	}

	// Take a RootfsTarSnapshot.
	snapshotID, err := sbA.Snapshot(ctx, sandbox.RootfsTarSnapshot, storage)
	if err != nil {
		t.Fatalf("failed to take snapshot: %v", err)
	}

	// Start Sandbox B restoring from the snapshot.
	runtimeDirB := filepath.Join(tempDir, "runtime-b")
	sbB, err := sandbox.New(ctx,
		sandbox.WithRuntimeDir(runtimeDirB),
		sandbox.WithNetworking(enableNetworking),
		sandbox.WithSnapshotID(snapshotID),
		sandbox.WithWritableRootfs(true),
	)
	if err != nil {
		t.Fatalf("failed to start sandbox B: %v", err)
	}
	defer sbB.Close(ctx)

	// Verify the file exists in Sandbox B.
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

	// Ensure default storage is nil.
	sandbox.SetDefaultSnapshotStorage(nil)

	runtimeDir := filepath.Join(tempDir, "runtime")
	enableNetworking := os.Geteuid() == 0
	_, err := sandbox.New(ctx,
		sandbox.WithRuntimeDir(runtimeDir),
		sandbox.WithNetworking(enableNetworking),
		sandbox.WithSnapshotID("some-snapshot-id"),
		sandbox.WithWritableRootfs(true),
	)
	if err == nil {
		t.Fatalf("expected error when starting sandbox with SnapshotID but no SnapshotStore or default storage configured, got nil")
	}
	expectedErrSubstr := "no snapshot storage configured for restore"
	if !strings.Contains(err.Error(), expectedErrSubstr) {
		t.Errorf("unexpected error: %v, want it to contain %q", err, expectedErrSubstr)
	}
}

func TestRestoreReadOnlyRootfsError(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	runtimeDir := filepath.Join(tempDir, "runtime")
	enableNetworking := os.Geteuid() == 0
	_, err := sandbox.New(ctx,
		sandbox.WithRuntimeDir(runtimeDir),
		sandbox.WithNetworking(enableNetworking),
		sandbox.WithSnapshotID("some-snapshot-id"),
	)
	if err == nil {
		t.Fatalf("expected error when restoring sandbox with read-only rootfs, got nil")
	}
	expectedErrSubstr := "rootfs must be writable when restoring from snapshot"
	if !strings.Contains(err.Error(), expectedErrSubstr) {
		t.Errorf("unexpected error: %v, want it to contain %q", err, expectedErrSubstr)
	}
}
