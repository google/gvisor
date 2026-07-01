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

// TestCheckpointRestore verifies that the sandbox state can be saved to a
// checkpoint and restored later.
//
// We use a tmpfs mount to verify memory restoration. Because each Exec call
// runs in a new process, we cannot use process-local state (like environment
// variables) to verify restoration across Exec calls. Instead, we use tmpfs,
// which is an in-memory filesystem managed by the sandbox sentry. Files in
// tmpfs reside entirely in the sandbox's memory, so verifying they survive
// restore confirms that the sandbox memory state was correctly restored.
func TestCheckpointRestore(t *testing.T) {
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
		sandbox.WithTmpfsMount("/mnt/scratch"),
	)
	if err != nil {
		t.Fatalf("failed to start sandbox A: %v", err)
	}
	defer sbA.Close(ctx)

	// Write to tmpfs (in-memory filesystem)
	_, _, err = sbA.Exec(ctx, "sh", "-c", "echo 'memory-file-value' > /mnt/scratch/state.txt")
	if err != nil {
		t.Fatalf("failed to write to tmpfs in A: %v", err)
	}

	// Take a checkpoint snapshot.
	snapshot, err := sbA.Snapshot(ctx, sandbox.CheckpointRestore, storage)
	if err != nil {
		t.Fatalf("failed to take checkpoint: %v", err)
	}

	runtimeDirB := filepath.Join(tempDir, "runtime-b")
	sbB, err := sandbox.New(ctx,
		sandbox.WithRuntimeDir(runtimeDirB),
		sandbox.WithNetworking(enableNetworking),
		sandbox.WithSnapshot(snapshot),
		sandbox.WithTmpfsMount("/mnt/scratch"), // Must match A
	)
	if err != nil {
		t.Fatalf("failed to restore sandbox B: %v", err)
	}
	defer sbB.Close(ctx)

	// Verify tmpfs state is restored.
	outB, _, err := sbB.Exec(ctx, "cat", "/mnt/scratch/state.txt")
	if err != nil {
		t.Fatalf("failed to read tmpfs in B: %v", err)
	}
	if got, want := strings.TrimSpace(outB), "memory-file-value"; got != want {
		t.Fatalf("tmpfs content in B = %q, want %q", got, want)
	}
}

func TestCheckpointRestoreMultiple(t *testing.T) {
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
		sandbox.WithTmpfsMount("/mnt/scratch"),
	)
	if err != nil {
		t.Fatalf("failed to start sandbox A: %v", err)
	}
	defer sbA.Close(ctx)

	_, _, err = sbA.Exec(ctx, "sh", "-c", "echo 'val1' > /mnt/scratch/file1.txt")
	if err != nil {
		t.Fatalf("failed to write file1 in A: %v", err)
	}

	// Checkpoint at sandbox A for snapshot1.
	snapshot1, err := sbA.Snapshot(ctx, sandbox.CheckpointRestore, storage)
	if err != nil {
		t.Fatalf("failed to take checkpoint 1: %v", err)
	}

	// Restore at sandbox B from snapshot1.
	runtimeDirB := filepath.Join(tempDir, "runtime-b")
	sbB, err := sandbox.New(ctx,
		sandbox.WithRuntimeDir(runtimeDirB),
		sandbox.WithNetworking(enableNetworking),
		sandbox.WithSnapshot(snapshot1),
		sandbox.WithTmpfsMount("/mnt/scratch"),
	)
	if err != nil {
		t.Fatalf("failed to restore sandbox B: %v", err)
	}
	defer sbB.Close(ctx)

	outB, _, err := sbB.Exec(ctx, "cat", "/mnt/scratch/file1.txt")
	if err != nil {
		t.Fatalf("failed to read file1 in B: %v", err)
	}
	if got, want := strings.TrimSpace(outB), "val1"; got != want {
		t.Fatalf("file1 content in B = %q, want %q", got, want)
	}

	_, _, err = sbB.Exec(ctx, "sh", "-c", "echo 'val2' > /mnt/scratch/file2.txt")
	if err != nil {
		t.Fatalf("failed to write file2 in B: %v", err)
	}

	// Checkpoint at sandbox B for snapshot2.
	snapshot2, err := sbB.Snapshot(ctx, sandbox.CheckpointRestore, storage)
	if err != nil {
		t.Fatalf("failed to take checkpoint 2: %v", err)
	}

	// Restore sandbox C from snapshot2
	runtimeDirC := filepath.Join(tempDir, "runtime-c")
	sbC, err := sandbox.New(ctx,
		sandbox.WithRuntimeDir(runtimeDirC),
		sandbox.WithNetworking(enableNetworking),
		sandbox.WithSnapshot(snapshot2),
		sandbox.WithTmpfsMount("/mnt/scratch"),
	)
	if err != nil {
		t.Fatalf("failed to restore sandbox C: %v", err)
	}
	defer sbC.Close(ctx)

	// Verify file1 and file2 in C
	outC1, _, err := sbC.Exec(ctx, "cat", "/mnt/scratch/file1.txt")
	if err != nil {
		t.Fatalf("failed to read file1 in C: %v", err)
	}
	if got, want := strings.TrimSpace(outC1), "val1"; got != want {
		t.Fatalf("file1 content in C = %q, want %q", got, want)
	}

	outC2, _, err := sbC.Exec(ctx, "cat", "/mnt/scratch/file2.txt")
	if err != nil {
		t.Fatalf("failed to read file2 in C: %v", err)
	}
	if got, want := strings.TrimSpace(outC2), "val2"; got != want {
		t.Fatalf("file2 content in C = %q, want %q", got, want)
	}
}

func TestCheckpointRestoreCorrupted(t *testing.T) {
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
		sandbox.WithTmpfsMount("/mnt/scratch"),
	)
	if err != nil {
		t.Fatalf("failed to start sandbox A: %v", err)
	}
	defer sbA.Close(ctx)

	_, _, err = sbA.Exec(ctx, "sh", "-c", "echo 'hello' > /mnt/scratch/state.txt")
	if err != nil {
		t.Fatalf("failed to write to tmpfs in A: %v", err)
	}

	snapshot, err := sbA.Snapshot(ctx, sandbox.CheckpointRestore, storage)
	if err != nil {
		t.Fatalf("failed to take checkpoint: %v", err)
	}

	// List assets and delete one that is NOT metadata.json.
	assets, err := storage.ListAssets(ctx, snapshot.ID)
	if err != nil {
		t.Fatalf("failed to list assets: %v", err)
	}
	corrupted := false
	for _, asset := range assets {
		if asset != sandbox.MetadataAsset {
			// Overwrite the asset with empty content to corrupt it.
			writer, err := storage.PutWriter(ctx, snapshot.ID, asset)
			if err != nil {
				t.Fatalf("failed to get writer to corrupt asset %q: %v", asset, err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("failed to close writer for corrupted asset %q: %v", asset, err)
			}
			corrupted = true
			break
		}
	}
	if !corrupted {
		t.Fatalf("no asset found to corrupt other than metadata.json")
	}

	// Try to restore, it should fail.
	runtimeDirB := filepath.Join(tempDir, "runtime-b")
	_, err = sandbox.New(ctx,
		sandbox.WithRuntimeDir(runtimeDirB),
		sandbox.WithNetworking(enableNetworking),
		sandbox.WithSnapshot(snapshot),
		sandbox.WithTmpfsMount("/mnt/scratch"),
	)
	if err == nil {
		t.Fatalf("expected restore to fail with corrupted snapshot, got nil")
	}
}
