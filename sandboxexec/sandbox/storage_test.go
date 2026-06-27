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

func TestFilesystemStorage(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	storage, err := sandbox.NewFilesystemStorage(tempDir)
	if err != nil {
		t.Fatalf("failed to create FilesystemStorage: %v", err)
	}

	snapshotID := sandbox.SnapshotID("test-snapshot-123")

	writer, err := storage.PutWriter(ctx, snapshotID, sandbox.MetadataAsset)
	if err != nil {
		t.Fatalf("PutWriter failed: %v", err)
	}

	meta := sandbox.SnapshotMetadata{
		Type:      sandbox.CheckpointRestore,
		CreatedAt: "2026-05-15T12:00:00Z",
	}

	if err := json.NewEncoder(writer).Encode(&meta); err != nil {
		t.Fatalf("failed to encode metadata: %v", err)
	}
	writer.Close()

	dummyWriter, err := storage.PutWriter(ctx, snapshotID, sandbox.CheckpointAsset)
	if err != nil {
		t.Fatalf("PutWriter failed: %v", err)
	}
	if _, err := io.WriteString(dummyWriter, "dummy checkpoint data"); err != nil {
		t.Fatalf("failed to write dummy data: %v", err)
	}
	dummyWriter.Close()

	snapshots, err := storage.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(snapshots) != 1 || snapshots[0] != snapshotID {
		t.Errorf("List returned unexpected snapshots: got %v, want [%s]", snapshots, snapshotID)
	}

	assets, err := storage.ListAssets(ctx, snapshotID)
	if err != nil {
		t.Fatalf("ListAssets failed: %v", err)
	}
	expectedAssets := map[sandbox.Asset]bool{sandbox.MetadataAsset: true, sandbox.CheckpointAsset: true}
	if len(assets) != len(expectedAssets) {
		t.Errorf("ListAssets returned wrong number of assets: got %v, want %v", assets, expectedAssets)
	}
	for _, a := range assets {
		if !expectedAssets[a] {
			t.Errorf("ListAssets returned unexpected asset: %s", a)
		}
	}

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

	if err := storage.Delete(ctx, snapshotID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	snapshotsAfterDelete, err := storage.List(ctx)
	if err != nil {
		t.Fatalf("List after delete failed: %v", err)
	}
	if len(snapshotsAfterDelete) != 0 {
		t.Errorf("List after delete should be empty, got: %v", snapshotsAfterDelete)
	}

	_, err = storage.ListAssets(ctx, snapshotID)
	if !errors.Is(err, sandbox.ErrSnapshotNotFound) {
		t.Errorf("ListAssets on non-existent snapshot returned error %v, want %v", err, sandbox.ErrSnapshotNotFound)
	}
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
