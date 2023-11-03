package metricserver

import (
	"bytes"
	"compress/flate"

	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"syscall"

	_ "embed"
	"golang.org/x/sys/unix"
)

// BinaryName is the name of the embedded binary.
const BinaryName = "metricserver"

//go:embed metricserver.flate
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

// run decompresses and run the embedded binary with the given arguments.
// If fork is true, the binary runs in a separate process, and its PID is
// returned.
// Otherwise, the binary is exec'd, so the current process stops executing.
func run(options Options, fork bool) (int, error) {
	if len(options.Argv) == 0 {
		options.Argv = []string{BinaryName}
	}
	decompressed := flate.NewReader(bytes.NewReader(compressedBinary))
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
	if _, err := io.Copy(tmpFile, decompressed); err != nil {
		tmpFile.Close()
		return 0, fmt.Errorf("cannot decompress embedded binary or write it to temporary file: %w", err)
	}

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
