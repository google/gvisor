// Copyright 2018 The gVisor Authors.
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

// Package loader loads an executable file into a MemoryManager.
package loader

import (
	"bytes"
	"fmt"
	"io"
	"path"

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsbridge"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/usermem"
)

// LoadArgs holds specifications for an executable file to be loaded.
type LoadArgs struct {
	// MemoryManager is the memory manager to load the executable into.
	MemoryManager *mm.MemoryManager

	// RemainingTraversals is the maximum number of symlinks to follow to
	// resolve Filename. This counter is passed by reference to keep it
	// updated throughout the call stack.
	RemainingTraversals *uint

	// ResolveFinal indicates whether the final link of Filename should be
	// resolved, if it is a symlink.
	ResolveFinal bool

	// Filename is the path for the executable.
	Filename string

	// File is an open fs.File object of the executable. If File is not
	// nil, then File will be loaded and Filename will be ignored.
	//
	// The caller is responsible for checking that the user can execute this file.
	File fsbridge.File

	// Opener is used to open the executable file when 'File' is nil.
	Opener fsbridge.Lookup

	// CloseOnExec indicates that the executable (or one of its parent
	// directories) was opened with O_CLOEXEC. If the executable is an
	// interpreter script, then cause an ENOENT error to occur, since the
	// script would otherwise be inaccessible to the interpreter.
	CloseOnExec bool

	// Argv is the vector of arguments to pass to the executable.
	Argv []string

	// Envv is the vector of environment variables to pass to the
	// executable.
	Envv []string

	// Features specifies the CPU feature set for the executable.
	Features *cpuid.FeatureSet
}

// openPath opens args.Filename and checks that it is valid for loading.
//
// openPath returns an *fs.Dirent and *fs.File for args.Filename, which is not
// installed in the Task FDTable. The caller takes ownership of both.
//
// args.Filename must be a readable, executable, regular file.
func openPath(ctx context.Context, args LoadArgs) (fsbridge.File, error) {
	if args.Filename == "" {
		ctx.Infof("cannot open empty name")
		return nil, linuxerr.ENOENT
	}

	// TODO(gvisor.dev/issue/160): Linux requires only execute permission,
	// not read. However, our backing filesystems may prevent us from reading
	// the file without read permission. Additionally, a task with a
	// non-readable executable has additional constraints on access via
	// ptrace and procfs.
	opts := vfs.OpenOptions{
		Flags:    linux.O_RDONLY,
		FileExec: true,
	}
	return args.Opener.OpenPath(ctx, args.Filename, opts, args.RemainingTraversals, args.ResolveFinal)
}

// checkIsRegularFile prevents us from trying to execute a directory, pipe, etc.
func checkIsRegularFile(ctx context.Context, file fsbridge.File, filename string) error {
	t, err := file.Type(ctx)
	if err != nil {
		return err
	}
	if t != linux.ModeRegular {
		ctx.Infof("%q is not a regular file: %v", filename, t)
		return linuxerr.EACCES
	}
	return nil
}

// allocStack allocates and maps a stack in to any available part of the address space.
func allocStack(ctx context.Context, m *mm.MemoryManager, a arch.Context) (*arch.Stack, error) {
	ar, err := m.MapStack(ctx)
	if err != nil {
		return nil, err
	}
	return &arch.Stack{Arch: a, IO: m, Bottom: ar.End}, nil
}

const (
	// maxLoaderAttempts is the maximum number of attempts to try to load
	// an interpreter scripts, to prevent loops. 6 (initial + 5 changes) is
	// what the Linux kernel allows (fs/exec.c:search_binary_handler).
	maxLoaderAttempts = 6
)

// loadExecutable loads an executable that is pointed to by args.File. The
// caller is responsible for checking that the user can execute this file.
// If nil, the path args.Filename is resolved and loaded (check that the user
// can execute this file is done here in this case). If the executable is an
// interpreter script rather than an ELF, the binary of the corresponding
// interpreter will be loaded.
//
// It returns:
//  * loadedELF, description of the loaded binary
//  * arch.Context matching the binary arch
//  * fs.Dirent of the binary file
//  * Possibly updated args.Argv
func loadExecutable(ctx context.Context, args LoadArgs) (loadedELF, arch.Context, fsbridge.File, []string, error) {
	for i := 0; i < maxLoaderAttempts; i++ {
		if args.File == nil {
			var err error
			args.File, err = openPath(ctx, args)
			if err != nil {
				ctx.Infof("Error opening %s: %v", args.Filename, err)
				return loadedELF{}, nil, nil, nil, err
			}
			// Ensure file is release in case the code loops or errors out.
			defer args.File.DecRef(ctx)
		} else {
			if err := checkIsRegularFile(ctx, args.File, args.Filename); err != nil {
				return loadedELF{}, nil, nil, nil, err
			}
		}

		// Check the header. Is this an ELF or interpreter script?
		var hdr [4]uint8
		// N.B. We assume that reading from a regular file cannot block.
		_, err := args.File.ReadFull(ctx, usermem.BytesIOSequence(hdr[:]), 0)
		// Allow unexpected EOF, as a valid executable could be only three bytes
		// (e.g., #!a).
		if err != nil && err != io.ErrUnexpectedEOF {
			if err == io.EOF {
				err = linuxerr.ENOEXEC
			}
			return loadedELF{}, nil, nil, nil, err
		}

		switch {
		case bytes.Equal(hdr[:], []byte(elfMagic)):
			loaded, ac, err := loadELF(ctx, args)
			if err != nil {
				ctx.Infof("Error loading ELF: %v", err)
				return loadedELF{}, nil, nil, nil, err
			}
			// An ELF is always terminal. Hold on to file.
			args.File.IncRef()
			return loaded, ac, args.File, args.Argv, err

		case bytes.Equal(hdr[:2], []byte(interpreterScriptMagic)):
			if args.CloseOnExec {
				return loadedELF{}, nil, nil, nil, linuxerr.ENOENT
			}
			args.Filename, args.Argv, err = parseInterpreterScript(ctx, args.Filename, args.File, args.Argv)
			if err != nil {
				ctx.Infof("Error loading interpreter script: %v", err)
				return loadedELF{}, nil, nil, nil, err
			}
			// Refresh the traversal limit for the interpreter.
			*args.RemainingTraversals = linux.MaxSymlinkTraversals

		default:
			ctx.Infof("Unknown magic: %v", hdr)
			return loadedELF{}, nil, nil, nil, linuxerr.ENOEXEC
		}
		// Set to nil in case we loop on a Interpreter Script.
		args.File = nil
	}

	return loadedELF{}, nil, nil, nil, linuxerr.ELOOP
}

// Load loads args.File into a MemoryManager. If args.File is nil, the path
// args.Filename is resolved and loaded instead.
//
// If Load returns ErrSwitchFile it should be called again with the returned
// path and argv.
//
// Preconditions:
// * The Task MemoryManager is empty.
// * Load is called on the Task goroutine.
func Load(ctx context.Context, args LoadArgs, extraAuxv []arch.AuxEntry, vdso *VDSO) (abi.OS, arch.Context, string, *syserr.Error) {
	// Load the executable itself.
	loaded, ac, file, newArgv, err := loadExecutable(ctx, args)
	if err != nil {
		return 0, nil, "", syserr.NewDynamic(fmt.Sprintf("failed to load %s: %v", args.Filename, err), syserr.FromError(err).ToLinux())
	}
	defer file.DecRef(ctx)

	// Load the VDSO.
	vdsoAddr, err := loadVDSO(ctx, args.MemoryManager, vdso, loaded)
	if err != nil {
		return 0, nil, "", syserr.NewDynamic(fmt.Sprintf("error loading VDSO: %v", err), syserr.FromError(err).ToLinux())
	}

	// Setup the heap. brk starts at the next page after the end of the
	// executable. Userspace can assume that the remainer of the page after
	// loaded.end is available for its use.
	e, ok := loaded.end.RoundUp()
	if !ok {
		return 0, nil, "", syserr.NewDynamic(fmt.Sprintf("brk overflows: %#x", loaded.end), errno.ENOEXEC)
	}
	args.MemoryManager.BrkSetup(ctx, e)

	// Allocate our stack.
	stack, err := allocStack(ctx, args.MemoryManager, ac)
	if err != nil {
		return 0, nil, "", syserr.NewDynamic(fmt.Sprintf("Failed to allocate stack: %v", err), syserr.FromError(err).ToLinux())
	}

	// Push the original filename to the stack, for AT_EXECFN.
	if _, err := stack.PushNullTerminatedByteSlice([]byte(args.Filename)); err != nil {
		return 0, nil, "", syserr.NewDynamic(fmt.Sprintf("Failed to push exec filename: %v", err), syserr.FromError(err).ToLinux())
	}
	execfn := stack.Bottom

	// Push 16 random bytes on the stack which AT_RANDOM will point to.
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, nil, "", syserr.NewDynamic(fmt.Sprintf("Failed to read random bytes: %v", err), syserr.FromError(err).ToLinux())
	}
	if _, err = stack.PushNullTerminatedByteSlice(b[:]); err != nil {
		return 0, nil, "", syserr.NewDynamic(fmt.Sprintf("Failed to push random bytes: %v", err), syserr.FromError(err).ToLinux())
	}
	random := stack.Bottom

	c := auth.CredentialsFromContext(ctx)

	// Add generic auxv entries.
	auxv := append(loaded.auxv, arch.Auxv{
		arch.AuxEntry{linux.AT_UID, hostarch.Addr(c.RealKUID.In(c.UserNamespace).OrOverflow())},
		arch.AuxEntry{linux.AT_EUID, hostarch.Addr(c.EffectiveKUID.In(c.UserNamespace).OrOverflow())},
		arch.AuxEntry{linux.AT_GID, hostarch.Addr(c.RealKGID.In(c.UserNamespace).OrOverflow())},
		arch.AuxEntry{linux.AT_EGID, hostarch.Addr(c.EffectiveKGID.In(c.UserNamespace).OrOverflow())},
		// The conditions that require AT_SECURE = 1 never arise. See
		// kernel.Task.updateCredsForExecLocked.
		arch.AuxEntry{linux.AT_SECURE, 0},
		arch.AuxEntry{linux.AT_CLKTCK, linux.CLOCKS_PER_SEC},
		arch.AuxEntry{linux.AT_EXECFN, execfn},
		arch.AuxEntry{linux.AT_RANDOM, random},
		arch.AuxEntry{linux.AT_PAGESZ, hostarch.PageSize},
		arch.AuxEntry{linux.AT_SYSINFO_EHDR, vdsoAddr},
	}...)
	auxv = append(auxv, extraAuxv...)

	sl, err := stack.Load(newArgv, args.Envv, auxv)
	if err != nil {
		return 0, nil, "", syserr.NewDynamic(fmt.Sprintf("Failed to load stack: %v", err), syserr.FromError(err).ToLinux())
	}

	m := args.MemoryManager
	m.SetArgvStart(sl.ArgvStart)
	m.SetArgvEnd(sl.ArgvEnd)
	m.SetEnvvStart(sl.EnvvStart)
	m.SetEnvvEnd(sl.EnvvEnd)
	m.SetAuxv(auxv)
	m.SetExecutable(ctx, file)

	symbolValue, err := getSymbolValueFromVDSO("rt_sigreturn")
	if err != nil {
		return 0, nil, "", syserr.NewDynamic(fmt.Sprintf("Failed to find rt_sigreturn in vdso: %v", err), syserr.FromError(err).ToLinux())
	}

	// Found rt_sigretrun.
	addr := uint64(vdsoAddr) + symbolValue - vdsoPrelink
	m.SetVDSOSigReturn(addr)

	ac.SetIP(uintptr(loaded.entry))
	ac.SetStack(uintptr(stack.Bottom))

	name := path.Base(args.Filename)
	if len(name) > linux.TASK_COMM_LEN-1 {
		name = name[:linux.TASK_COMM_LEN-1]
	}

	return loaded.os, ac, name, nil
}
