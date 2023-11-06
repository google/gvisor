// Copyright 2023 The gVisor Authors.
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

// Package embeddedbinary embeds an external binary and provides a function to
// exec it.
package embeddedbinary

import (
	"bytes"
	"compress/flate"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// BinaryName is the name of the embedded binary.
const BinaryName = "embedded.bin.name"

//go:embed embedded.bin.flate
var compressedBinary []byte

// Options is the set of options to execute the embedded binary.
type Options struct {
	// Argv is the set of arguments to exec with.
	// `Argv[0]` is the name of the binary as invoked.
	// If Argv is empty, it will default to a single-element slice, with
	// `Argv[0]` being the binary name.
	Argv []string

	// Envv is the set of environment variables to pass to the executed process.
	Envv []string

	// Files is the set of file descriptors to pass to forked processes.
	// Only used when forking, not pure exec'ing.
	Files []uintptr
}

// Bogus import to satisfy the compiler that we are using the flate import,
// even when compression is disabled.
const _ = flate.NoCompression

// run decompresses and run the embedded binary with the given arguments.
// If fork is true, the binary runs in a separate process, and its PID is
// returned.
// Otherwise, the binary is exec'd, so the current process stops executing.
func run(options Options, fork bool) (int, error) {
	if len(options.Argv) == 0 {
		options.Argv = []string{BinaryName}
	}
	// The "flate.NewReader" below may be replaced by "io.Reader" when
	// compression is off.
	binaryReader := flate.NewReader(bytes.NewReader(compressedBinary))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	oldMask := unix.Umask(0077)
	defer unix.Umask(oldMask)
	tmpDir, err := os.MkdirTemp("", "gvisor.*.tmp")
	if err != nil {
		return 0, fmt.Errorf("cannot create temp directory: %w", err)
	}
	tmpDirHandle, err := os.Open(tmpDir)
	if err != nil {
		return 0, fmt.Errorf("cannot open temp directory: %w", err)
	}
	defer tmpDirHandle.Close()
	binPath := path.Join(tmpDir, BinaryName)
	tmpFile, err := os.OpenFile(binPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return 0, fmt.Errorf("cannot open temp file: %w", err)
	}
	if err := os.RemoveAll(tmpDir); err != nil {
		return 0, fmt.Errorf("cannot remove temp directory: %w", err)
	}
	unix.Umask(oldMask)
	if _, err := io.Copy(tmpFile, binaryReader); err != nil {
		tmpFile.Close()
		return 0, fmt.Errorf("cannot decompress embedded binary or write it to temporary file: %w", err)
	}
	// Reopen the file for reading.
	tmpFileReadOnly, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", tmpFile.Fd()), os.O_RDONLY, 0700)
	if err != nil {
		tmpFile.Close()
		return 0, fmt.Errorf("cannot re-open temp file for reading: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return 0, fmt.Errorf("cannot close temp file: %w", err)
	}
	defer tmpFileReadOnly.Close()
	tmpFD := tmpFileReadOnly.Fd()
	if _, err := unix.Seek(int(tmpFD), 0, unix.SEEK_SET); err != nil {
		return 0, fmt.Errorf("cannot seek temp file back to 0: %w", err)
	}
	fdPath := fmt.Sprintf("/proc/self/fd/%d", tmpFD)
	if fork {
		return syscall.ForkExec(fdPath, options.Argv, &syscall.ProcAttr{
			Env:   options.Envv,
			Files: options.Files,
		})
	}
	if err := unix.Exec(fdPath, options.Argv, options.Envv); err != nil {
		return 0, fmt.Errorf("cannot exec embedded binary: %w", err)
	}
	panic("unreachable")
}

// Exec execs the embedded binary. The current process is replaced.
// This function only returns if unsuccessful.
func Exec(options Options) error {
	_, err := run(options, false)
	return err
}

// ForkExec runs the embedded binary in a separate process.
// Returns the PID of the child process.
func ForkExec(options Options) (int, error) {
	return run(options, true)
}
