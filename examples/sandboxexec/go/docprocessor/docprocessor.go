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

// Package docprocessor demonstrates how to use the gVisor SandboxExec Go
// bindings to safely process untrusted documents and data files inside an
// isolated sandbox.
package docprocessor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

// tmpfsMount is an in-memory /tmp for scratch files. The default sandbox
// mounts do not include /tmp.
var tmpfsMount = sandbox.Mount{Type: sandbox.MountTypeTmpfs, Source: "tmpfs", Destination: "/tmp"}

// ProcessConfig holds the runtime configuration for a document transformation run.
type ProcessConfig struct {
	InputDir    string        // Host directory mounted read-only at /input.
	OutputDir   string        // Host directory mounted read-write at /output.
	Command     string        // Shell command to run (default: uppercase each input file).
	Timeout     time.Duration // Time limit. The sandbox is killed when it expires.
	Network     string        // Network mode: "none" (default), "host", or "sandbox".
	WorkingDir  string        // Working directory inside the sandbox (default: /).
	SnapshotDir string        // Directory that holds one pre-warmed snapshot to restore.
}

// ProcessDocuments runs cfg.Command in a new gVisor sandbox. The input
// directory is mounted read-only, so untrusted commands cannot change the
// source data, and the network is off unless cfg.Network enables it.
func ProcessDocuments(ctx context.Context, cfg ProcessConfig) error {
	// The timeout guarantees that the sandbox never hangs.
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	opts := []sandbox.Option{sandbox.WithMount(tmpfsMount)}
	if cfg.WorkingDir != "" {
		opts = append(opts, sandbox.WithWorkingDir(cfg.WorkingDir))
	}

	// NetworkModeNone is the safest default for untrusted data.
	switch strings.ToLower(cfg.Network) {
	case "host":
		opts = append(opts, sandbox.WithNetwork(sandbox.NetworkModeHost))
	case "sandbox":
		opts = append(opts, sandbox.WithNetwork(sandbox.NetworkModeSandbox))
	default:
		opts = append(opts, sandbox.WithNetwork(sandbox.NetworkModeNone))
	}

	if cfg.OutputDir != "" {
		if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
			return fmt.Errorf("failed to create host output directory: %w", err)
		}
	}
	for _, m := range []sandbox.Mount{
		{Type: sandbox.MountTypeBind, Source: cfg.InputDir, Destination: "/input", ReadOnly: true},
		{Type: sandbox.MountTypeBind, Source: cfg.OutputDir, Destination: "/output"},
	} {
		if m.Source == "" {
			continue
		}
		abs, err := filepath.Abs(m.Source)
		if err != nil {
			return fmt.Errorf("failed to resolve %q: %w", m.Source, err)
		}
		m.Source = abs
		opts = append(opts, sandbox.WithMount(m))
	}

	// Restoring a pre-warmed snapshot reuses initialized files instantly.
	if cfg.SnapshotDir != "" {
		storage, err := sandbox.NewFilesystemStorage(cfg.SnapshotDir)
		if err != nil {
			return fmt.Errorf("failed to open snapshot storage: %w", err)
		}
		ids, err := storage.List(ctx)
		if err != nil {
			return fmt.Errorf("failed to list snapshots: %w", err)
		}
		// List does not sort by creation time, so require exactly one snapshot.
		if len(ids) != 1 {
			return fmt.Errorf("found %d snapshots in %s, want exactly 1", len(ids), cfg.SnapshotDir)
		}
		snap, err := storage.Lookup(ctx, ids[0])
		if err != nil {
			return fmt.Errorf("failed to lookup snapshot: %w", err)
		}
		opts = append(opts, sandbox.WithSnapshot(snap))
	}

	sb, err := sandbox.New(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create sandbox: %w", err)
	}
	defer sb.Close(context.Background())
	// Exec does not return while the sandbox holds the command's output pipes,
	// so kill the sandbox as soon as the timeout expires.
	stop := context.AfterFunc(ctx, func() { _ = sb.Close(context.Background()) })
	defer stop()

	command := cfg.Command
	if command == "" {
		command = `for f in /input/*; do [ -f "$f" ] && tr '[:lower:]' '[:upper:]' < "$f" > "/output/$(basename "$f")"; done`
	}
	res, err := sb.Exec(ctx, []string{"/bin/sh", "-c", command})
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return fmt.Errorf("execution timed out after %v", cfg.Timeout)
	case err != nil:
		return fmt.Errorf("command execution failed: %w", err)
	case res.ExitCode != 0:
		return fmt.Errorf("command exited with code %d: %s", res.ExitCode, res.Stderr)
	}
	fmt.Print(res.Stdout)
	return nil
}

// WarmSnapshot initializes a base sandbox, populates template assets, and saves
// a RootfsTarSnapshot to storageDir for instant restoration.
func WarmSnapshot(ctx context.Context, storageDir string) error {
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return err
	}
	storage, err := sandbox.NewFilesystemStorage(storageDir)
	if err != nil {
		return fmt.Errorf("failed to create snapshot storage: %w", err)
	}

	sb, err := sandbox.New(ctx, sandbox.WithMount(tmpfsMount))
	if err != nil {
		return fmt.Errorf("failed to launch base sandbox: %w", err)
	}
	defer sb.Close(context.Background())

	// Write base templates into the sandbox rootfs.
	setupCmd := `mkdir -p /opt/templates && echo "=== Generated by gVisor Snapshot ===" > /opt/templates/header.txt`
	res, err := sb.Exec(ctx, []string{"/bin/sh", "-c", setupCmd})
	if err != nil {
		return fmt.Errorf("failed to setup base rootfs: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("failed to setup base rootfs: exit code %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	snap, err := sb.Snapshot(ctx, sandbox.RootfsTarSnapshot, storage)
	if err != nil {
		return fmt.Errorf("failed to capture snapshot: %w", err)
	}
	fmt.Printf("Successfully created pre-warmed snapshot: %s\n", snap.ID)
	return nil
}
