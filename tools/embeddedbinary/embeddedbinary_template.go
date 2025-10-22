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

	// SysProcAttr provides OS-specific options to the executed process.
	// Only used when forking, not pure exec'ing.
	SysProcAttr *unix.SysProcAttr
}

// Bogus import to satisfy the compiler that we are using the flate import,
// even when compression is disabled.
const _ = flate.NoCompression

// run decompresses and run the embedded binary with the given arguments.
// If fork is true, the binary runs in a separate process, and its PID is
// returned.
// Otherwise, the binary is exec'd, so the current process stops executing.
func run(options *Options, fork bool) (int, error) {
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

	tmpFD := -1
	// /tmp is sometimes mounted noexec for "security" reasons. Handle this by
	// falling back to executing from a memfd.
	parentDir := os.TempDir()
	var parentDirStatfs unix.Statfs_t
	if err := unix.Statfs(parentDir, &parentDirStatfs); err == nil && parentDirStatfs.Flags&unix.ST_NOEXEC == 0 {
		tmpDir, err := os.MkdirTemp(parentDir, "gvisor.*.tmp")
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
		tmpFD = int(tmpFileReadOnly.Fd())
	} else {
		var err error
		tmpFD, err = unix.MemfdCreate(BinaryName, unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
		if err == unix.EINVAL {
			// Assume that the kernel precedes 105ff5339f498 ("mm/memfd: add
			// MFD_NOEXEC_SEAL and MFD_EXEC"), Linux 6.3+.
			tmpFD, err = unix.MemfdCreate(BinaryName, unix.MFD_ALLOW_SEALING)
		}
		if err != nil {
			return 0, fmt.Errorf("cannot create memfd: %w", err)
		}
		tmpFile := os.NewFile(uintptr(tmpFD), BinaryName)
		defer tmpFile.Close()
		unix.Umask(oldMask)
		if _, err := io.Copy(tmpFile, binaryReader); err != nil {
			return 0, fmt.Errorf("cannot decompress embedded binary or write it to temporary memfd: %w", err)
		}
		// Prevent future writes to the memfd.
		if _, err := unix.FcntlInt(uintptr(tmpFD), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
			return 0, fmt.Errorf("cannot seal memfd: %w", err)
		}
	}

	if _, err := unix.Seek(tmpFD, 0, unix.SEEK_SET); err != nil {
		return 0, fmt.Errorf("cannot seek temp file back to 0: %w", err)
	}
	if fork {
		// Go's syscall/exec_linux.go:forkAndExecInChild1() can clobber FDs
		// outside of syscall.ProcAttr.Files, including tmpFD, so the FD that
		// the child execs must be in syscall.ProcAttr.Files to ensure that
		// it's valid at time of execve().
		childTmpFD := len(options.Files)
		files := append(options.Files, uintptr(tmpFD))
		fdPath := fmt.Sprintf("/proc/self/fd/%d", childTmpFD)
		return syscall.ForkExec(fdPath, options.Argv, &syscall.ProcAttr{
			Env:   options.Envv,
			Files: files,
			Sys:   options.SysProcAttr,
		})
	}
	fdPath := fmt.Sprintf("/proc/self/fd/%d", tmpFD)
	if err := unix.Exec(fdPath, options.Argv, options.Envv); err != nil {
		return 0, fmt.Errorf("cannot exec embedded binary: %w", err)
	}
	panic("unreachable")
}

// Exec execs the embedded binary. The current process is replaced.
// This function only returns if unsuccessful.
func Exec(options Options) error {
	_, err := run(&options, false)
	return err
}

// ForkExec runs the embedded binary in a separate process.
// Returns the PID of the child process.
func ForkExec(options Options) (int, error) {
	return run(&options, true)
}
