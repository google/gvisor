// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gvisorbinaries resolves and executes sidecar binaries that runsc
// needs at runtime.
//
// A sidecar is resolved on disk in a "gvisor-bin/" directory located next to
// the main binary.
// TODO(gvisor.dev/issue/13718): Each binary is also embedded in this package
// itself, which can be extracted and exec'd when the on-disk copy is not
// available. This will go away after some time in order to lighten up the
// size of the runsc binary.
package gvisorbinaries

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Sidecar binary filenames under the "gvisor-bin/" directory.
const (
	metricServerName    = "runsc-metric-server"
	checkpointGoferName = "checkpointgofer"
)

// binDirName is the name of the directory holding sidecar binaries.
// Lives next to the runsc binary.
const binDirName = "gvisor-bin"

// sidecarBinariesDirEnv is an environment variable that, when set, overrides
// the directory in which sidecar binaries are located.
// Specified by tests.
const sidecarBinariesDirEnv = "GVISOR_SIDECAR_BINARIES_DIR"

// The sidecar binaries that runsc may need to execute.
// Their embedded fallbacks are not wired here directly to avoid import cycles.
//
// TODO(gvisor.dev/issue/13718): once embedded sidecar binaries are removed,
// delete the embedded fallback entirely.
var (
	// MetricServer is the `runsc metric-server` sidecar binary.
	MetricServer = Binary{Name: metricServerName}
	// CheckpointGofer is the checkpoint gofer sidecar binary.
	CheckpointGofer = Binary{Name: checkpointGoferName}
)

// All lists every known sidecar.
var All = []*Binary{&MetricServer, &CheckpointGofer}

// Options is the set of options used to execute a sidecar binary.
type Options struct {
	// Argv is the set of arguments to exec with. Argv[0] is the name of the
	// binary as invoked. If Argv is empty, it defaults to a single-element
	// slice holding the resolved binary path.
	Argv []string

	// Envv is the set of environment variables to pass to the executed process.
	Envv []string

	// Files is the set of file descriptors to pass to forked processes.
	// Used only by ForkExec.
	Files []uintptr

	// SysProcAttr provides OS-specific options to the executed process.
	// Used only by ForkExec.
	SysProcAttr *unix.SysProcAttr
}

// String returns a string representation of the argv.
func (o *Options) String() string {
	return fmt.Sprintf("%v", o.Argv)
}

// Binary is a sidecar binary.
type Binary struct {
	// Name is the filename of the binary.
	Name string

	// embeddedExec/embeddedForkExec, if set, can run a copy of the binary that
	// is embedded in the main binary.
	//
	// TODO(gvisor.dev/issue/13718): remove along with the embed package once
	// embedded sidecar binaries are gone.
	embeddedExec     func(Options) error
	embeddedForkExec func(Options) (int, error)
}

// DeclareEmbedded sets embedded exec/forkexec handlers.
//
// TODO(gvisor.dev/issue/13718): remove.
func (b *Binary) DeclareEmbedded(execFn func(Options) error, forkExecFn func(Options) (int, error)) {
	b.embeddedExec = execFn
	b.embeddedForkExec = forkExecFn
}

// Dir returns the directory in which sidecar binaries are located.
// Not guaranteed to exist.
func Dir() (string, error) {
	if dir := os.Getenv(sidecarBinariesDirEnv); dir != "" {
		return dir, nil
	}
	exe, err := filepath.EvalSymlinks(specutils.ExePath)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path to runsc binary %q: %w", specutils.ExePath, err)
	}
	return filepath.Join(filepath.Dir(exe), binDirName), nil
}

// Path returns the path to a usable on-disk copy of the binary.
// Returns error if not present or executable.
func (b *Binary) Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, b.Name)
	fi, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%q is not a regular file", p)
	}
	if fi.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("%q is not executable", p)
	}
	return p, nil
}

// notAvailableError returns an error for the case where the binary is
// not available.
func (b *Binary) notAvailableError() error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	return fmt.Errorf("sidecar binary %q not found (expected at %q); install it per https://gvisor.dev/docs/user_guide/install/ instructions", b.Name, filepath.Join(dir, b.Name))
}

// Exec resolves the binary and replaces the current process with it. It only
// returns if execution could not be started.
func (b *Binary) Exec(opts Options) error {
	if p, err := b.Path(); err == nil {
		log.Infof("sidecar %q found: executing %s (%v)", b.Name, p, &opts)
		return execDisk(p, opts)
	}
	if b.embeddedExec != nil {
		log.Infof("sidecar %q: using embedded copy (%v)", b.Name, &opts)
		return b.embeddedExec(opts)
	}
	return b.notAvailableError()
}

// ForkExec resolves the binary and runs it in a new process, returning the
// child's PID.
func (b *Binary) ForkExec(opts Options) (int, error) {
	if p, err := b.Path(); err == nil {
		log.Infof("sidecar %q: executing %s (%v)", b.Name, p, &opts)
		return forkExecDisk(p, opts)
	}
	if b.embeddedForkExec != nil {
		log.Infof("sidecar %q: using embedded copy (%v)", b.Name, &opts)
		return b.embeddedForkExec(opts)
	}
	return 0, b.notAvailableError()
}

// execDisk execs an on-disk binary.
func execDisk(path string, opts Options) error {
	argv := opts.Argv
	if len(argv) == 0 {
		argv = []string{path}
	}
	if err := unix.Exec(path, argv, opts.Envv); err != nil {
		return fmt.Errorf("cannot exec %q: %w", path, err)
	}
	panic("unreachable")
}

// forkExecDisk forks and execs an on-disk binary.
func forkExecDisk(path string, opts Options) (int, error) {
	argv := opts.Argv
	if len(argv) == 0 {
		argv = []string{path}
	}
	return syscall.ForkExec(path, argv, &syscall.ProcAttr{
		Env:   opts.Envv,
		Files: opts.Files,
		Sys:   opts.SysProcAttr,
	})
}
