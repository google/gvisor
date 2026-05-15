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

// Package sandbox provides a simple Go API for creating gVisor sandbox
// and executing commands in the sandbox.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Options holds the configuration for a Sandbox.
type Options struct {
	runtimeDir   string
	id           string
	restoreID    string
	restoreStore SnapshotStorage
}

// Option configures the Options struct.
type Option func(*Options)

// WithRuntimeDir sets a custom runtime directory where bundle and state files are written.
func WithRuntimeDir(runtimeDir string) Option {
	return func(o *Options) {
		o.runtimeDir = runtimeDir
	}
}

// WithID sets a specific sandbox ID. If not set, a unique ID will be generated automatically.
func WithID(id string) Option {
	return func(o *Options) {
		o.id = id
	}
}

// WithRestore configures the sandbox to restore state from the given storage and snapshot ID.
// The sandbox automatically reads the snapshot metadata to determine if it is a
// full Checkpoint/Restore, Filesystem snapshot, or Rootfs Tar snapshot.
func WithRestore(snapshotID string, storage SnapshotStorage) Option {
	return func(o *Options) {
		o.restoreID = snapshotID
		o.restoreStore = storage
	}
}

// Sandbox represents a running gVisor sandbox where applications
// run inside.
type Sandbox struct {
	id        string
	bundleDir string
	runscPath string
	rootState string
}

// newID returns a unique ID for the sandbox.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// rand.Read never returns an error, and always fills b entirely.
		panic(fmt.Sprintf("failed to generate random bytes for sandbox ID: %v", err))
	}
	return fmt.Sprintf("%x", b)
}

// Look for runsc binary from the environment variable RUNSC_PATH,
// then in system PATH.
func runscPath() string {
	if path := os.Getenv("RUNSC_PATH"); path != "" {
		return path
	}
	path, err := exec.LookPath("runsc")
	if err == nil {
		return path
	}
	panic("runsc binary is not found")
}

// New spawns a new sandbox as a subprocess, the sandbox
// will be started and running in detached mode.
func New(ctx context.Context, opts ...Option) (*Sandbox, error) {
	options := Options{}
	for _, o := range opts {
		o(&options)
	}

	if options.runtimeDir == "" {
		dir, err := os.MkdirTemp("", "gvisor-sandbox-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create runtime directory: %v", err)
		}
		options.runtimeDir = dir
	}

	if options.id == "" {
		options.id = newID()
	}

	runDir := options.runtimeDir
	stateDir := filepath.Join(runDir, "state")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create sandbox state directory: %v", err)
	}
	// Verify that the state directory actually has 0700 permissions.
	fi, err := os.Stat(stateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to stat sandbox state directory: %v", err)
	}
	if fi.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("sandbox state directory has incorrect permissions: got %v, want %v", fi.Mode().Perm(), os.FileMode(0700))
	}

	var annotations map[string]string
	var extraArgs []string
	var isCheckpointRestore bool
	var checkpointRestoreDir string

	if options.restoreID != "" && options.restoreStore != nil {
		// 1. Fetch metadata.json from store.
		metaReader, err := options.restoreStore.GetReader(ctx, options.restoreID, "metadata.json")
		if err != nil {
			return nil, fmt.Errorf("failed to read snapshot metadata: %w", err)
		}
		defer metaReader.Close()

		var meta SnapshotMetadata
		if err := json.NewDecoder(metaReader).Decode(&meta); err != nil {
			return nil, fmt.Errorf("failed to parse snapshot metadata: %w", err)
		}

		// 2. Perform restore based on Type.
		switch meta.Type {
		case RootfsTarSnapshot:
			// Skeleton: Download rootfs.tar from store to a local temp file under stateDir.
			tarPath := filepath.Join(stateDir, "rootfs.tar")
			// skeleton: download asset "rootfs.tar" from restoreStore to tarPath...
			annotations = map[string]string{
				"dev.gvisor.tar.rootfs.upper": tarPath,
			}
			extraArgs = append(extraArgs, "--allow-rootfs-tar-annotation")

		case FilesystemSnapshot:
			// Skeleton: Download all assets to a local directory under stateDir.
			fsRestoreDir := filepath.Join(stateDir, "fs-restore")
			if err := os.MkdirAll(fsRestoreDir, 0755); err != nil {
				return nil, err
			}
			// skeleton: download all assets from restoreStore to fsRestoreDir...
			extraArgs = append(extraArgs, fmt.Sprintf("--fs-restore-image-path=%s", fsRestoreDir))

		case CheckpointRestore:
			// Skeleton: Download all assets to a local directory under stateDir.
			checkpointRestoreDir = filepath.Join(stateDir, "checkpoint-restore")
			if err := os.MkdirAll(checkpointRestoreDir, 0755); err != nil {
				return nil, err
			}
			// skeleton: download all assets from restoreStore to checkpointRestoreDir...
			isCheckpointRestore = true
		}
	}

	bundleDir, err := NewBundle(options.id, runDir, annotations)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI bundle: %v", err)
	}

	sb := &Sandbox{
		id:        options.id,
		bundleDir: bundleDir,
		runscPath: runscPath(),
		rootState: stateDir,
	}

	// Launch the sandbox in detached mode via os/exec.
	var cmd *exec.Cmd
	if isCheckpointRestore {
		// Use runsc restore for CheckpointRestore.
		args := []string{"--root", sb.rootState, "restore", "--image-path", checkpointRestoreDir, "--detach", sb.id}
		cmd = exec.CommandContext(ctx, sb.runscPath, args...)
	} else {
		// Use runsc run with optional extra arguments (e.g. tar annotation or filesystem snapshot path).
		args := append([]string{"--root", sb.rootState, "run", "--bundle", sb.bundleDir, "--detach"}, extraArgs...)
		args = append(args, sb.id)
		cmd = exec.CommandContext(ctx, sb.runscPath, args...)
	}

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to create sandbox via subprocess: %v", err)
	}

	return sb, nil
}

// Exec runs the given command inside the running sandbox and returns the output.
func (s *Sandbox) Exec(ctx context.Context, cmd string, opts ...string) (stdout string, stderr string, err error) {
	args := append([]string{"--root", s.rootState, "exec", s.id, cmd}, opts...)

	commandContext := exec.CommandContext(ctx, s.runscPath, args...)

	var stdoutBuf, stderrBuf bytes.Buffer

	commandContext.Stdout = io.MultiWriter(&stdoutBuf)
	commandContext.Stderr = io.MultiWriter(&stderrBuf)

	err = commandContext.Run()
	if err != nil {
		return "", stderrBuf.String(), fmt.Errorf("exec failed: %v", err)
	}

	return stdoutBuf.String(), stderrBuf.String(), err
}

// Close kills the sandbox processes and cleans up the state directory.
func (s *Sandbox) Close(ctx context.Context) error {
	killArgs := []string{"--root", s.rootState, "kill", s.id, "SIGKILL"}
	_ = exec.CommandContext(ctx, s.runscPath, killArgs...).Run()

	deleteArgs := []string{"--root", s.rootState, "delete", "--force", s.id}
	if err := exec.CommandContext(ctx, s.runscPath, deleteArgs...).Run(); err != nil {
		return fmt.Errorf("failed to clean up sandbox state: %v", err)
	}

	if err := os.RemoveAll(s.bundleDir); err != nil {
		return fmt.Errorf("failed to clean up sandbox bundle directory: %v", err)
	}

	return nil
}

// Bundle returns the path to the OCI bundle directory for this sandbox.
func (s *Sandbox) Bundle() string {
	return s.bundleDir
}

// SaveOptions holds configuration for saving a snapshot.
type SaveOptions struct {
	LeaveRunning bool
}

// SaveOption configures SaveOptions.
type SaveOption func(*SaveOptions)

// WithLeaveRunning keeps the sandbox running after taking the snapshot.
func WithLeaveRunning(leaveRunning bool) SaveOption {
	return func(o *SaveOptions) {
		o.LeaveRunning = leaveRunning
	}
}

// SaveSnapshot serializes and saves the sandbox state to storage.
// Depending on the snapshotType, it will perform a full Checkpoint, a Filesystem Snapshot, or a Rootfs Tar Snapshot.
// It also automatically generates and writes "metadata.json" into the storage.
func (s *Sandbox) SaveSnapshot(ctx context.Context, snapshotID string, snapshotType SnapshotType, storage SnapshotStorage, opts ...SaveOption) error {
	options := SaveOptions{
		LeaveRunning: false, // Default is false.
	}
	for _, o := range opts {
		o(&options)
	}

	// 1. Write the metadata file to the storage.
	meta := SnapshotMetadata{
		Type:      snapshotType,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	metaWriter, err := storage.PutWriter(ctx, snapshotID, "metadata.json")
	if err != nil {
		return fmt.Errorf("failed to create metadata.json in storage: %w", err)
	}
	defer metaWriter.Close()

	if err := json.NewEncoder(metaWriter).Encode(&meta); err != nil {
		return fmt.Errorf("failed to write metadata.json to storage: %w", err)
	}

	// 2. Perform the actual snapshot action.
	switch snapshotType {
	case RootfsTarSnapshot:
		// Skeleton:
		// Run `runsc tar rootfs-upper --file=<localTempTar> <sandboxID>`.
		// Upload `<localTempTar>` to storage with asset name "rootfs.tar".

	case FilesystemSnapshot:
		// Skeleton:
		// Run `runsc fscheckpoint --image-path=<localTempDir> [--leave-running] <sandboxID>`.
		// Walk `<localTempDir>` and upload each file to storage.

	case CheckpointRestore:
		// Skeleton:
		// Run `runsc checkpoint --image-path=<localTempDir> [--leave-running] <sandboxID>`.
		// Walk `<localTempDir>` and upload each file to storage.
	}

	return nil
}
