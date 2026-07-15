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
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

func createTestSnapshot(ctx context.Context, t *testing.T, storage sandbox.SnapshotStorage, id sandbox.SnapshotID) {
	t.Helper()
	writer, err := storage.PutWriter(ctx, id, sandbox.MetadataAsset)
	if err != nil {
		t.Fatalf("failed to create test metadata: %v", err)
	}
	defer writer.Close()
	meta := sandbox.SnapshotMetadata{
		Type:      sandbox.CheckpointRestore,
		CreatedAt: "2026-05-15T12:00:00Z",
	}
	if err := json.NewEncoder(writer).Encode(&meta); err != nil {
		t.Fatalf("failed to encode metadata: %v", err)
	}

	checkpointWriter, err := storage.PutWriter(ctx, id, sandbox.CheckpointAsset)
	if err != nil {
		t.Fatalf("failed to create test checkpoint: %v", err)
	}
	defer checkpointWriter.Close()
	if _, err := checkpointWriter.Write([]byte("dummy checkpoint data")); err != nil {
		t.Fatalf("failed to write dummy checkpoint data: %v", err)
	}
}

func TestFilesystemStorage(t *testing.T) {
	ctx := context.Background()

	t.Run("Put and Read", func(t *testing.T) {
		tempDir := t.TempDir()
		storage, err := sandbox.NewFilesystemStorage(tempDir)
		if err != nil {
			t.Fatalf("failed to create FilesystemStorage: %v", err)
		}

		snapshotID := sandbox.SnapshotID("test-snapshot-123")
		createTestSnapshot(ctx, t, storage, snapshotID)

		// Verify metadata.
		reader, err := storage.GetReader(ctx, snapshotID, sandbox.MetadataAsset)
		if err != nil {
			t.Fatalf("GetReader failed: %v", err)
		}
		defer reader.Close()

		var readMeta sandbox.SnapshotMetadata
		if err := json.NewDecoder(reader).Decode(&readMeta); err != nil {
			t.Fatalf("failed to decode read metadata: %v", err)
		}

		if readMeta.Type != sandbox.CheckpointRestore {
			t.Errorf("readMeta.Type = %v, want %v", readMeta.Type, sandbox.CheckpointRestore)
		}
		if readMeta.CreatedAt != "2026-05-15T12:00:00Z" {
			t.Errorf("readMeta.CreatedAt = %q, want %q", readMeta.CreatedAt, "2026-05-15T12:00:00Z")
		}

		// Verify content
		reader2, err := storage.GetReader(ctx, snapshotID, sandbox.CheckpointAsset)
		if err != nil {
			t.Fatalf("GetReader failed: %v", err)
		}
		defer reader2.Close()

		gotContent, err := io.ReadAll(reader2)
		if err != nil {
			t.Fatalf("failed to read fake content: %v", err)
		}
		if string(gotContent) != "dummy checkpoint data" {
			t.Errorf("got content %q, want %q", string(gotContent), "dummy checkpoint data")
		}
	})

	t.Run("List", func(t *testing.T) {
		tempDir := t.TempDir()
		storage, err := sandbox.NewFilesystemStorage(tempDir)
		if err != nil {
			t.Fatalf("failed to create FilesystemStorage: %v", err)
		}

		snapshots, err := storage.List(ctx)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		if len(snapshots) != 0 {
			t.Errorf("expected empty list, got %v", snapshots)
		}

		snapshotID := sandbox.SnapshotID("test-snapshot-123")
		createTestSnapshot(ctx, t, storage, snapshotID)

		snapshots, err = storage.List(ctx)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		if len(snapshots) != 1 || snapshots[0] != snapshotID {
			t.Errorf("got snapshots %v, want [%s]", snapshots, snapshotID)
		}
	})

	t.Run("Lookup", func(t *testing.T) {
		tempDir := t.TempDir()
		storage, err := sandbox.NewFilesystemStorage(tempDir)
		if err != nil {
			t.Fatalf("failed to create FilesystemStorage: %v", err)
		}

		snapshotID := sandbox.SnapshotID("test-snapshot-123")

		// Lookup non-existent
		_, err = storage.Lookup(ctx, snapshotID)
		if !errors.Is(err, sandbox.ErrSnapshotNotFound) {
			t.Errorf("Lookup on non-existent snapshot returned error %v, want %v", err, sandbox.ErrSnapshotNotFound)
		}

		createTestSnapshot(ctx, t, storage, snapshotID)

		// Lookup existent
		snap, err := storage.Lookup(ctx, snapshotID)
		if err != nil {
			t.Fatalf("Lookup failed: %v", err)
		}
		if snap.ID != snapshotID {
			t.Errorf("Lookup returned snapshot with wrong ID: got %s, want %s", snap.ID, snapshotID)
		}
		if snap.Storage != storage {
			t.Errorf("Lookup returned snapshot with wrong storage")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		tempDir := t.TempDir()
		storage, err := sandbox.NewFilesystemStorage(tempDir)
		if err != nil {
			t.Fatalf("failed to create FilesystemStorage: %v", err)
		}

		snapshotID := sandbox.SnapshotID("test-snapshot-123")
		createTestSnapshot(ctx, t, storage, snapshotID)

		if err := storage.Delete(ctx, snapshotID); err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		_, err = storage.Lookup(ctx, snapshotID)
		if !errors.Is(err, sandbox.ErrSnapshotNotFound) {
			t.Errorf("Lookup after delete returned error %v, want %v", err, sandbox.ErrSnapshotNotFound)
		}
	})
}

func TestNewFilesystemStorage(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "file.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	tests := []struct {
		name    string
		rootDir string
	}{
		{
			name:    "non-existent directory",
			rootDir: filepath.Join(tempDir, "does-not-exist"),
		},
		{
			name:    "path is a file",
			rootDir: filePath,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sandbox.NewFilesystemStorage(tc.rootDir)
			if err == nil {
				t.Errorf("NewFilesystemStorage(%q) succeeded, want error", tc.rootDir)
			}
		})
	}
}

func TestFilesystemStoragePathTraversal(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	storage, err := sandbox.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("failed to create FilesystemStorage: %v", err)
	}

	// These cannot be sanitized to a safe name and must fail.
	invalidSnapshotIDs := []sandbox.SnapshotID{
		"..",
		".",
		"/",
		"",
	}

	for _, badID := range invalidSnapshotIDs {
		t.Run("invalid_snapshot_id_"+string(badID), func(t *testing.T) {
			if _, err := storage.PutWriter(ctx, badID, sandbox.MetadataAsset); err == nil {
				t.Errorf("PutWriter with invalid snapshot ID %q succeeded, want error", badID)
			}
			if _, err := storage.GetReader(ctx, badID, sandbox.MetadataAsset); err == nil {
				t.Errorf("GetReader with invalid snapshot ID %q succeeded, want error", badID)
			}
			if err := storage.Delete(ctx, badID); err == nil {
				t.Errorf("Delete with invalid snapshot ID %q succeeded, want error", badID)
			}
			if _, err := storage.Lookup(ctx, badID); err == nil {
				t.Errorf("Lookup with invalid snapshot ID %q succeeded, want error", badID)
			}
		})
	}

	// These should be sanitized and succeed, but they must NOT escape root.
	// They should resolve to "escaped" under rootDir.
	sanitizableSnapshotIDs := []sandbox.SnapshotID{
		"../escaped",
		"../../escaped",
		"sub/../../escaped",
	}

	for _, id := range sanitizableSnapshotIDs {
		t.Run("sanitizable_snapshot_id_"+string(id), func(t *testing.T) {
			writer, err := storage.PutWriter(ctx, id, sandbox.MetadataAsset)
			if err != nil {
				t.Fatalf("PutWriter failed for sanitizable ID %q: %v", id, err)
			}
			writer.Close()

			// Verify it was written to f.rootDir/escaped/metadata.json
			expectedPath := filepath.Join(tempDir, "escaped", string(sandbox.MetadataAsset))
			if _, err := os.Stat(expectedPath); err != nil {
				t.Errorf("Expected file at %q to exist, but got error: %v", expectedPath, err)
			}

			// Verify we can read it back using the sanitized ID
			reader, err := storage.GetReader(ctx, id, sandbox.MetadataAsset)
			if err != nil {
				t.Errorf("GetReader failed: %v", err)
			} else {
				reader.Close()
			}

			// Clean up
			if err := storage.Delete(ctx, id); err != nil {
				t.Errorf("Delete failed: %v", err)
			}

			// Verify it is gone
			if _, err := os.Stat(expectedPath); !os.IsNotExist(err) {
				t.Errorf("Expected file at %q to be deleted, but it still exists", expectedPath)
			}
		})
	}

	// Test asset name sanitization
	goodSnapshotID := sandbox.SnapshotID("good-snap")

	invalidAssets := []sandbox.Asset{
		"..",
		".",
		"/",
		"",
	}
	for _, badAsset := range invalidAssets {
		t.Run("invalid_asset_"+string(badAsset), func(t *testing.T) {
			if _, err := storage.PutWriter(ctx, goodSnapshotID, badAsset); err == nil {
				t.Errorf("PutWriter with invalid asset %q succeeded, want error", badAsset)
			}
		})
	}

	sanitizableAssets := []sandbox.Asset{
		"../escaped-asset",
		"../../escaped-asset",
	}
	for _, asset := range sanitizableAssets {
		t.Run("sanitizable_asset_"+string(asset), func(t *testing.T) {
			writer, err := storage.PutWriter(ctx, goodSnapshotID, asset)
			if err != nil {
				t.Fatalf("PutWriter failed: %v", err)
			}
			writer.Close()

			expectedPath := filepath.Join(tempDir, "good-snap", "escaped-asset")
			if _, err := os.Stat(expectedPath); err != nil {
				t.Errorf("Expected file at %q to exist, but got error: %v", expectedPath, err)
			}
		})
	}
}
