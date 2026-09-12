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

// Package main demonstrates how to use the gVisor SandboxExec Go bindings
// to safely process untrusted documents and data files inside an isolated sandbox.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

// ProcessConfig holds the runtime configuration for a document transformation run.
type ProcessConfig struct {
	// InputDir is the host path mounted read-only to /input inside the sandbox.
	InputDir string

	// OutputDir is the host path mounted read-write to /output inside the sandbox.
	OutputDir string

	// Command is the shell command or pipeline to execute in the sandbox.
	Command string

	// Timeout is the maximum execution time allowed before cancelling the process.
	Timeout time.Duration

	// Network specifies the network isolation mode ("none", "host", or "sandbox").
	Network string

	// WorkingDir specifies the initial working directory inside the sandbox.
	WorkingDir string

	// SnapshotDir points to local storage holding pre-warmed snapshot images.
	SnapshotDir string
}

// ProcessDocuments creates an isolated gVisor sandbox and executes the command.
//
// How it works:
// 1. Mounts the input directory as READ-ONLY so untrusted scripts cannot tamper with source data.
// 2. Mounts the output directory as READ-WRITE to safely capture generated results.
// 3. Allocates an in-memory tmpfs at /tmp for scratch files.
// 4. Enforces strict network isolation (NetworkModeNone by default) to prevent data exfiltration.
// 5. Restores from a pre-warmed rootfs snapshot if SnapshotDir is specified.
func ProcessDocuments(ctx context.Context, cfg ProcessConfig) error {
	// 1. Create a timeout context to guarantee the sandbox never hangs indefinitely.
	execCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	// 2. Configure sandbox isolation options.
	var opts []sandbox.Option

	// Set working directory inside the container (defaults to /).
	if cfg.WorkingDir != "" {
		opts = append(opts, sandbox.WithWorkingDir(cfg.WorkingDir))
	}

	// In-memory scratch space (/tmp) - fast, isolated, automatically wiped on exit.
	opts = append(opts, sandbox.WithMount(sandbox.Mount{
		Type:        sandbox.MountTypeTmpfs,
		Source:      "tmpfs",
		Destination: "/tmp",
	}))

	// Set network mode. NetworkModeNone is the safest default for untrusted data.
	switch strings.ToLower(cfg.Network) {
	case "host":
		opts = append(opts, sandbox.WithNetwork(sandbox.NetworkModeHost))
	case "sandbox":
		opts = append(opts, sandbox.WithNetwork(sandbox.NetworkModeSandbox))
	default:
		opts = append(opts, sandbox.WithNetwork(sandbox.NetworkModeNone))
	}

	// Mount input directory as READ-ONLY (readonly = true).
	if cfg.InputDir != "" {
		absInput, err := filepath.Abs(cfg.InputDir)
		if err != nil {
			return fmt.Errorf("failed to resolve input directory: %w", err)
		}
		opts = append(opts, sandbox.WithMount(sandbox.Mount{
			Type:        sandbox.MountTypeBind,
			Source:      absInput,
			Destination: "/input",
			ReadOnly:    true,
		}))
	}

	// Mount output directory as READ-WRITE (readonly = false).
	if cfg.OutputDir != "" {
		absOutput, err := filepath.Abs(cfg.OutputDir)
		if err != nil {
			return fmt.Errorf("failed to resolve output directory: %w", err)
		}
		if err := os.MkdirAll(absOutput, 0755); err != nil {
			return fmt.Errorf("failed to create host output directory: %w", err)
		}
		opts = append(opts, sandbox.WithMount(sandbox.Mount{
			Type:        sandbox.MountTypeBind,
			Source:      absOutput,
			Destination: "/output",
			ReadOnly:    false,
		}))
	}

	// 3. Restore pre-warmed snapshot if configured.
	// Snapshot restoration lets you reuse initialized libraries/templates instantly.
	if cfg.SnapshotDir != "" {
		storage, err := sandbox.NewFilesystemStorage(cfg.SnapshotDir)
		if err != nil {
			return fmt.Errorf("failed to open snapshot storage: %w", err)
		}
		snapshots, err := storage.List(execCtx)
		if err != nil {
			return fmt.Errorf("failed to list snapshots: %w", err)
		}
		if len(snapshots) > 0 {
			// Restore the latest available snapshot.
			snap, err := storage.Lookup(execCtx, snapshots[len(snapshots)-1])
			if err != nil {
				return fmt.Errorf("failed to lookup snapshot: %w", err)
			}
			opts = append(opts, sandbox.WithSnapshot(snap))
		}
	}

	// 4. Start the gVisor sandbox instance.
	sb, err := sandbox.New(execCtx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create sandbox: %w", err)
	}
	// Always ensure the sandbox is closed and resources are released.
	defer sb.Close(context.Background())

	// Start a background watcher to immediately terminate the sandbox if the timeout expires.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-execCtx.Done():
			_ = sb.Close(context.Background())
		case <-done:
		}
	}()

	// 5. Execute the transformation command inside the sandbox.
	cmdToRun := cfg.Command
	if cmdToRun == "" {
		// Default pipeline: convert all .txt files in /input to uppercase in /output.
		cmdToRun = `for f in /input/*; do [ -f "$f" ] && tr '[:lower:]' '[:upper:]' < "$f" > "/output/$(basename "$f")"; done`
	}

	res, err := sb.Exec(execCtx, []string{"/bin/sh", "-c", cmdToRun})
	if err != nil {
		if execCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("execution timed out after %v: %w", cfg.Timeout, err)
		}
		return fmt.Errorf("command execution failed: %w", err)
	}
	if execCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("execution timed out after %v (stderr: %s)", cfg.Timeout, res.Stderr)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("command exited with code %d: %s", res.ExitCode, res.Stderr)
	}

	if res.Stdout != "" {
		fmt.Print(res.Stdout)
	}
	return nil
}

// WarmSnapshot initializes a base sandbox, populates template assets,
// and saves a RootfsTarSnapshot to disk for instant restoration.
func WarmSnapshot(ctx context.Context, storageDir string) error {
	absDir, err := filepath.Abs(storageDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(absDir, 0755); err != nil {
		return err
	}

	storage, err := sandbox.NewFilesystemStorage(absDir)
	if err != nil {
		return fmt.Errorf("failed to create snapshot storage: %w", err)
	}

	// Create a base sandbox with tmpfs scratch.
	sb, err := sandbox.New(ctx, sandbox.WithMount(sandbox.Mount{
		Type:        sandbox.MountTypeTmpfs,
		Source:      "tmpfs",
		Destination: "/tmp",
	}))
	if err != nil {
		return fmt.Errorf("failed to launch base sandbox: %w", err)
	}
	defer sb.Close(context.Background())

	// Write base templates into the container's rootfs.
	setupCmd := `mkdir -p /opt/templates && echo "=== Generated by gVisor Snapshot ===" > /opt/templates/header.txt`
	res, err := sb.Exec(ctx, []string{"/bin/sh", "-c", setupCmd})
	if err != nil {
		return fmt.Errorf("failed to setup base rootfs: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("failed to setup base rootfs: exit code %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	// Capture the rootfs modifications into a tar snapshot.
	snap, err := sb.Snapshot(ctx, sandbox.RootfsTarSnapshot, storage)
	if err != nil {
		return fmt.Errorf("failed to capture snapshot: %w", err)
	}

	fmt.Printf("Successfully created pre-warmed snapshot: %s\n", snap.ID)
	return nil
}

func main() {
	inputDir := flag.String("input", "", "Host directory to mount read-only at /input (e.g. ./docs)")
	outputDir := flag.String("output", "", "Host directory to mount read-write at /output (e.g. ./results)")
	cmd := flag.String("cmd", "", "Shell command to run in sandbox (default: batch uppercase conversion)")
	timeout := flag.Duration("timeout", 10*time.Second, "Execution timeout (e.g. 5s, 30s)")
	network := flag.String("network", "none", "Network mode: 'none' (default, isolated), 'host', or 'sandbox'")
	workingDir := flag.String("working-dir", "/", "Working directory inside the sandbox (default: /)")
	snapshotDir := flag.String("snapshot-dir", "", "Directory storing pre-warmed snapshots for fast restoration")
	warmSnap := flag.Bool("warm-snapshot", false, "Pre-warm and save a base template snapshot to -snapshot-dir and exit")

	flag.Parse()

	ctx := context.Background()

	// Handle pre-warming snapshot mode.
	if *warmSnap {
		if *snapshotDir == "" {
			fmt.Fprintln(os.Stderr, "Error: -snapshot-dir is required when using -warm-snapshot")
			os.Exit(1)
		}
		if err := WarmSnapshot(ctx, *snapshotDir); err != nil {
			fmt.Fprintf(os.Stderr, "Snapshot error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Normal document processing execution.
	cfg := ProcessConfig{
		InputDir:    *inputDir,
		OutputDir:   *outputDir,
		Command:     *cmd,
		Timeout:     *timeout,
		Network:     *network,
		WorkingDir:  *workingDir,
		SnapshotDir: *snapshotDir,
	}

	if err := ProcessDocuments(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
