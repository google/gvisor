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
	"errors"
	"fmt"
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

// SnapshotID defines the type for snapshot IDs.
type SnapshotID string

// SnapshotMetadata stores the metadata of a snapshot.
type SnapshotMetadata struct {
	Type      SnapshotType `json:"type"`
	CreatedAt string       `json:"created_at"`
}

// Asset defines the type for snapshot asset names.
type Asset string

const (
	// MetadataAsset is the name of the metadata file.
	MetadataAsset Asset = "metadata.json"
	// RootfsAsset is the name of the rootfs tarball (if using RootfsTarSnapshot).
	RootfsAsset Asset = "rootfs.tar"
	// CheckpointAsset is the main checkpoint state file.
	CheckpointAsset Asset = "checkpoint.img"
	// PagesAsset is the memory pages file.
	PagesAsset Asset = "pages.img"
	// PagesMetaAsset is the memory pages metadata file.
	PagesMetaAsset Asset = "pages_meta.img"
)

// SnapshotStorage defines a pluggable storage interface for snapshots.
type SnapshotStorage interface {
	// PutWriter returns a WriteCloser to write a file asset of a snapshot.
	PutWriter(ctx context.Context, snapshotID SnapshotID, assetName Asset) (io.WriteCloser, error)

	// GetReader returns a ReadCloser to read a file asset of a snapshot.
	GetReader(ctx context.Context, snapshotID SnapshotID, assetName Asset) (io.ReadCloser, error)

	// Delete deletes all assets associated with a snapshot ID.
	Delete(ctx context.Context, snapshotID SnapshotID) error

	// List returns all snapshot IDs known to this storage.
	List(ctx context.Context) ([]SnapshotID, error)

	// ListAssets returns all asset names associated with a snapshot ID.
	// If the snapshot ID is not found, it returns ErrSnapshotNotFound.
	ListAssets(ctx context.Context, snapshotID SnapshotID) ([]Asset, error)
}

// ErrSnapshotNotFound is returned when the snapshot ID is not found.
var ErrSnapshotNotFound = errors.New("snapshot not found")

// FilesystemStorage implements SnapshotStorage using a local directory.
type FilesystemStorage struct {
	rootDir string
}

// NewFilesystemStorage creates a new FilesystemStorage at the given root directory.
// The root directory must already exist.
func NewFilesystemStorage(rootDir string) (*FilesystemStorage, error) {
	fi, err := os.Stat(rootDir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("root directory %q is not a directory", rootDir)
	}
	return &FilesystemStorage{rootDir: rootDir}, nil
}

// PutWriter returns a WriteCloser to write a file asset of a snapshot.
func (f *FilesystemStorage) PutWriter(ctx context.Context, snapshotID SnapshotID, assetName Asset) (io.WriteCloser, error) {
	path := filepath.Join(f.rootDir, string(snapshotID), string(assetName))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	return os.Create(path)
}

// GetReader returns a ReadCloser to read a file asset of a snapshot.
func (f *FilesystemStorage) GetReader(ctx context.Context, snapshotID SnapshotID, assetName Asset) (io.ReadCloser, error) {
	path := filepath.Join(f.rootDir, string(snapshotID), string(assetName))
	return os.Open(path)
}

// Delete deletes all assets associated with a snapshot ID.
func (f *FilesystemStorage) Delete(ctx context.Context, snapshotID SnapshotID) error {
	path := filepath.Join(f.rootDir, string(snapshotID))
	return os.RemoveAll(path)
}

// List returns all snapshot IDs known to this storage.
func (f *FilesystemStorage) List(ctx context.Context) ([]SnapshotID, error) {
	entries, err := os.ReadDir(f.rootDir)
	if err != nil {
		return nil, err
	}
	ids := make([]SnapshotID, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			ids = append(ids, SnapshotID(entry.Name()))
		}
	}
	return ids, nil
}

// ListAssets returns all asset names associated with a snapshot ID.
func (f *FilesystemStorage) ListAssets(ctx context.Context, snapshotID SnapshotID) ([]Asset, error) {
	dir := filepath.Join(f.rootDir, string(snapshotID))
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrSnapshotNotFound
		}
		return nil, err
	}
	assets := make([]Asset, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			assets = append(assets, Asset(entry.Name()))
		}
	}
	return assets, nil
}
