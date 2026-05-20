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
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
)

// Options holds the configuration for a Sandbox.
type Options struct {
	runtimeDir string
	id         string
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

	bundleDir, err := NewBundle(options.id, runDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI bundle: %v", err)
	}

	sb := &Sandbox{
		id:        options.id,
		bundleDir: bundleDir,
		runscPath: runscPath(),
		rootState: stateDir,
	}

	// Launch the sandbox in detached mode via os/exec, we use `runsc run` here
	// as a shortcut for `runsc create` and `runsc start`.
	args := []string{"--root", sb.rootState, "run", "--bundle", sb.bundleDir, "--detach", sb.id}
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

	return nil
}

// Bundle returns the path to the OCI bundle directory for this sandbox.
func (s *Sandbox) Bundle() string {
	return s.bundleDir
}
