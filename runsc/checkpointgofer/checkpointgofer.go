package checkpointgofer

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
const BinaryName = "checkpointgofer"

//go:embed checkpointgofer.bin
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

	binaryReader := io.Reader(bytes.NewReader(compressedBinary))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	oldMask := unix.Umask(0077)
	defer unix.Umask(oldMask)

	tmpFD := -1

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

		if _, err := unix.FcntlInt(uintptr(tmpFD), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
			return 0, fmt.Errorf("cannot seal memfd: %w", err)
		}
	}

	if _, err := unix.Seek(tmpFD, 0, unix.SEEK_SET); err != nil {
		return 0, fmt.Errorf("cannot seek temp file back to 0: %w", err)
	}
	if fork {

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
