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

package sandbox

import (
	"context"
	"io"
	"os"
	"path/filepath"
)

// SnapshotType defines the type of snapshot.
type SnapshotType string

const (
	// CheckpointRestore represents a full process state checkpoint and restore.
	CheckpointRestore SnapshotType = "CheckpointRestore"

	// FilesystemSnapshot represents a snapshot of the container's filesystems.
	FilesystemSnapshot SnapshotType = "FilesystemSnapshot"

	// RootfsTarSnapshot represents a tar file snapshot of rootfs changes.
	RootfsTarSnapshot SnapshotType = "RootfsTarSnapshot"
)

// SnapshotMetadata stores the metadata of a snapshot.
type SnapshotMetadata struct {
	Type      SnapshotType `json:"type"`
	CreatedAt string       `json:"created_at"`
}

// SnapshotStorage defines a pluggable storage interface for snapshots.
type SnapshotStorage interface {
	// PutWriter returns a WriteCloser to write a file asset of a snapshot.
	PutWriter(ctx context.Context, snapshotID string, assetName string) (io.WriteCloser, error)

	// GetReader returns a ReadCloser to read a file asset of a snapshot.
	GetReader(ctx context.Context, snapshotID string, assetName string) (io.ReadCloser, error)

	// Delete deletes all assets associated with a snapshot ID.
	Delete(ctx context.Context, snapshotID string) error

	// List returns all snapshot IDs known to this storage.
	List(ctx context.Context) ([]string, error)

	// ListAssets returns all asset names associated with a snapshot ID.
	ListAssets(ctx context.Context, snapshotID string) ([]string, error)
}

// FilesystemStorage implements SnapshotStorage using a local directory.
type FilesystemStorage struct {
	rootDir string
}

// NewFilesystemStorage creates a new FilesystemStorage at the given root directory.
func NewFilesystemStorage(rootDir string) (*FilesystemStorage, error) {
	if err := os.MkdirAll(rootDir, 0755); err != nil {
		return nil, err
	}
	return &FilesystemStorage{rootDir: rootDir}, nil
}

// PutWriter returns a WriteCloser to write a file asset of a snapshot.
func (f *FilesystemStorage) PutWriter(ctx context.Context, snapshotID string, assetName string) (io.WriteCloser, error) {
	path := filepath.Join(f.rootDir, snapshotID, assetName)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	return os.Create(path)
}

// GetReader returns a ReadCloser to read a file asset of a snapshot.
func (f *FilesystemStorage) GetReader(ctx context.Context, snapshotID string, assetName string) (io.ReadCloser, error) {
	path := filepath.Join(f.rootDir, snapshotID, assetName)
	return os.Open(path)
}

// Delete deletes all assets associated with a snapshot ID.
func (f *FilesystemStorage) Delete(ctx context.Context, snapshotID string) error {
	path := filepath.Join(f.rootDir, snapshotID)
	return os.RemoveAll(path)
}

// List returns all snapshot IDs known to this storage.
func (f *FilesystemStorage) List(ctx context.Context) ([]string, error) {
	entries, err := os.ReadDir(f.rootDir)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() {
			ids = append(ids, entry.Name())
		}
	}
	return ids, nil
}

// ListAssets returns all asset names associated with a snapshot ID.
func (f *FilesystemStorage) ListAssets(ctx context.Context, snapshotID string) ([]string, error) {
	dir := filepath.Join(f.rootDir, snapshotID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var assets []string
	for _, entry := range entries {
		if !entry.IsDir() {
			assets = append(assets, entry.Name())
		}
	}
	return assets, nil
}
