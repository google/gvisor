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
	"strings"
	"time"
)

// Options holds the configuration for a Sandbox.
type Options struct {
	runtimeDir       string
	id               string
	enableNetworking bool
	mounts           []Mount
	snapshot         *Snapshot
	env              []string
	err              error
}

// Option configures the Options struct.
type Option func(*Options)

// MountType represents the type of a mount point inside the sandbox.
type MountType int

const (
	// MountTypeBind represents a host bind mount.
	MountTypeBind MountType = iota
	// MountTypeTmpfs represents an in-memory tmpfs mount.
	MountTypeTmpfs
)

// Mount holds settings for a custom host bind directory or in-memory mount.
type Mount struct {
	Source      string
	Destination string
	Type        MountType
	ReadOnly    bool
}

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

// WithNetworking configures whether networking is enabled inside the sandbox.
func WithNetworking(enabled bool) Option {
	return func(o *Options) {
		o.enableNetworking = enabled
	}
}

// WithBindMount adds a custom bind mount from host's source path to the sandbox's destination path.
func WithBindMount(source, destination string, readOnly bool) Option {
	return func(o *Options) {
		o.mounts = append(o.mounts, Mount{
			Source:      filepath.Clean(source),
			Destination: filepath.Clean(destination),
			Type:        MountTypeBind,
			ReadOnly:    readOnly,
		})
	}
}

// WithTmpfsMount adds an in-memory tmpfs filesystem at the destination path inside the sandbox.
func WithTmpfsMount(destination string) Option {
	return func(o *Options) {
		o.mounts = append(o.mounts, Mount{
			Destination: filepath.Clean(destination),
			Type:        MountTypeTmpfs,
		})
	}
}

// WithSnapshot configures the sandbox to restore state from the given snapshot.
// The sandbox automatically reads the snapshot metadata to determine if it is a
// full Checkpoint/Restore, Filesystem snapshot, or Rootfs Tar snapshot.
func WithSnapshot(snapshot *Snapshot) Option {
	return func(o *Options) {
		o.snapshot = snapshot
	}
}

// WithEnv sets one or more environment variables in the sandbox process.
// Each env string must be in the "KEY=VALUE" format.
func WithEnv(envs ...string) Option {
	return func(o *Options) {
		for _, env := range envs {
			if !strings.Contains(env, "=") {
				o.err = fmt.Errorf("invalid environment variable format, expected KEY=VALUE: %q", env)
				return
			}
		}
		o.env = append(o.env, envs...)
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
	options := Options{
		enableNetworking: true,
	}
	for _, o := range opts {
		o(&options)
	}

	if options.err != nil {
		return nil, options.err
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

	if os.Geteuid() != 0 && options.enableNetworking {
		return nil, fmt.Errorf("enabling networking requires running as root")
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
	var globalFlags []string
	var runFlags []string
	var isCheckpointRestore bool
	var checkpointRestoreDir string

	if options.snapshot != nil {
		store := options.snapshot.Storage
		snapshotID := options.snapshot.ID
		if store == nil {
			return nil, fmt.Errorf("no snapshot storage configured for restore")
		}

		// Fetch metadata.json from store.
		metaReader, err := store.GetReader(ctx, snapshotID, MetadataAsset)
		if err != nil {
			return nil, fmt.Errorf("failed to read snapshot metadata: %w", err)
		}
		defer metaReader.Close()

		var meta SnapshotMetadata
		if err := json.NewDecoder(metaReader).Decode(&meta); err != nil {
			return nil, fmt.Errorf("failed to parse snapshot metadata: %w", err)
		}

		// Perform restore based on type.
		switch meta.Type {
		case RootfsTarSnapshot:
			tarPath, err := readRootfsTar(ctx, snapshotID, store)
			if err != nil {
				return nil, err
			}
			defer os.Remove(tarPath)

			annotations = map[string]string{
				"dev.gvisor.tar.rootfs.upper": tarPath,
			}
			globalFlags = append(globalFlags, "--allow-rootfs-tar-annotation")

		case FilesystemSnapshot:
			fsRestoreDir := filepath.Join(stateDir, "fs-restore")
			if err := os.MkdirAll(fsRestoreDir, 0700); err != nil {
				return nil, err
			}
			// TODO: List assets in store and download all filesystem image assets to fsRestoreDir.
			runFlags = append(runFlags, fmt.Sprintf("--fs-restore-image-path=%s", fsRestoreDir))

		case CheckpointRestore:
			checkpointRestoreDir = filepath.Join(stateDir, "checkpoint-restore")
			if err := os.MkdirAll(checkpointRestoreDir, 0700); err != nil {
				return nil, err
			}
			// TODO: List assets in store and download all checkpoint image assets to checkpointRestoreDir.
			isCheckpointRestore = true
		}
	}
	bundleDir, err := NewBundle(BundleConfig{
		ID:               options.id,
		RuntimeDir:       runDir,
		EnableNetworking: options.enableNetworking,
		Mounts:           options.mounts,
		Env:              options.env,
		Annotations:      annotations,
	})
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
	args := []string{"--root", sb.rootState}
	if os.Geteuid() != 0 {
		args = append(args, "--ignore-cgroups")
	}
	if !options.enableNetworking {
		args = append(args, "--network=none")
	}
	args = append(args, globalFlags...)

	if isCheckpointRestore {
		args = append(args, "restore", "--image-path", checkpointRestoreDir, "--detach", sb.id)
	} else {
		args = append(args, "run")
		args = append(args, runFlags...)
		args = append(args, "--bundle", sb.bundleDir, "--detach", sb.id)
	}
	cmd := exec.CommandContext(ctx, sb.runscPath, args...)
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

	if err := os.RemoveAll(s.rootState); err != nil {
		return fmt.Errorf("failed to clean up sandbox state directory: %v", err)
	}

	return nil
}

// Bundle returns the path to the OCI bundle directory for this sandbox.
func (s *Sandbox) Bundle() string {
	return s.bundleDir
}

// SnapshotOptions holds configuration for taking a snapshot.
type SnapshotOptions struct {
	LeaveRunning bool
}

// SnapshotOption configures SnapshotOptions.
type SnapshotOption func(*SnapshotOptions)

// WithLeaveRunning keeps the sandbox running after taking the snapshot.
func WithLeaveRunning(leaveRunning bool) SnapshotOption {
	return func(o *SnapshotOptions) {
		o.LeaveRunning = leaveRunning
	}
}

func newSnapshotID() SnapshotID {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes for snapshot ID: %v", err))
	}
	return SnapshotID(fmt.Sprintf("snap-%x", b))
}

// Snapshot serializes and saves the sandbox state to storage, returning the generated snapshot.
// Depending on the snapshotType, it will perform a full Checkpoint, a Filesystem Snapshot, or a Rootfs Tar Snapshot.
// It also automatically generates and writes "metadata.json" into the storage.
func (s *Sandbox) Snapshot(ctx context.Context, snapshotType SnapshotType, storage SnapshotStorage, opts ...SnapshotOption) (*Snapshot, error) {
	options := SnapshotOptions{
		LeaveRunning: false, // Default is false.
	}
	for _, o := range opts {
		o(&options)
	}

	snapshotID := newSnapshotID()

	switch snapshotType {
	case RootfsTarSnapshot:
		if err := s.snapshotRootfsTar(ctx, snapshotID, storage); err != nil {
			return nil, err
		}

	case FilesystemSnapshot:
		// TODO: Run `runsc fscheckpoint --image-path=<localTempDir> [--leave-running] <sandboxID>`.
		// TODO: Walk `<localTempDir>` and upload each file to storage.

	case CheckpointRestore:
		// TODO: Run `runsc checkpoint --image-path=<localTempDir> [--leave-running] <sandboxID>`.
		// TODO: Walk `<localTempDir>` and upload each file to storage.
	}

	meta := SnapshotMetadata{
		Type:      snapshotType,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	metaWriter, err := storage.PutWriter(ctx, snapshotID, MetadataAsset)
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata.json in storage: %w", err)
	}
	defer metaWriter.Close()

	if err := json.NewEncoder(metaWriter).Encode(&meta); err != nil {
		return nil, fmt.Errorf("failed to write metadata.json to storage: %w", err)
	}

	return &Snapshot{
		ID:      snapshotID,
		Storage: storage,
	}, nil
}

func (s *Sandbox) snapshotRootfsTar(ctx context.Context, snapshotID SnapshotID, storage SnapshotStorage) error {
	tarFile, err := os.CreateTemp(os.TempDir(), "rootfs-*.tar")
	if err != nil {
		return fmt.Errorf("failed to create temp tar file: %w", err)
	}
	tarPath := tarFile.Name()
	tarFile.Close()
	defer os.Remove(tarPath)

	cmd := exec.CommandContext(ctx, s.runscPath, "--root", s.rootState, "tar", "rootfs-upper", "--file", tarPath, s.id)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("runsc tar failed: %v (stderr: %q)", err, stderr.String())
	}

	localFile, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("failed to open temp tar file: %w", err)
	}
	defer localFile.Close()

	storageWriter, err := storage.PutWriter(ctx, snapshotID, RootfsAsset)
	if err != nil {
		return fmt.Errorf("failed to create storage writer: %w", err)
	}
	defer storageWriter.Close()

	if _, err := io.Copy(storageWriter, localFile); err != nil {
		return fmt.Errorf("failed to upload rootfs tar: %w", err)
	}
	return nil
}

func readRootfsTar(ctx context.Context, snapshotID SnapshotID, store SnapshotStorage) (string, error) {
	tarFile, err := os.CreateTemp(os.TempDir(), "rootfs-*.tar")
	if err != nil {
		return "", fmt.Errorf("failed to create temp tar file: %w", err)
	}
	tarPath := tarFile.Name()
	defer tarFile.Close()

	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tarPath)
		}
	}()

	storageReader, err := store.GetReader(ctx, snapshotID, RootfsAsset)
	if err != nil {
		return "", fmt.Errorf("failed to get rootfs reader from storage: %w", err)
	}
	defer storageReader.Close()

	if _, err := io.Copy(tarFile, storageReader); err != nil {
		return "", fmt.Errorf("failed to download rootfs asset: %w", err)
	}

	cleanup = false
	return tarPath, nil
}
