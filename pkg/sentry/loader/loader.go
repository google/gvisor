// Copyright 2018 Google Inc.
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

// Package loader loads a binary into a MemoryManager.
package loader

import (
	"bytes"
	"io"
	"path"

	"gvisor.googlesource.com/gvisor/pkg/abi"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/cpuid"
	"gvisor.googlesource.com/gvisor/pkg/rand"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/mm"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// readFull behaves like io.ReadFull for an *fs.File.
func readFull(ctx context.Context, f *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	var total int64
	for dst.NumBytes() > 0 {
		n, err := f.Preadv(ctx, dst, offset+total)
		total += n
		if err == io.EOF && total != 0 {
			return total, io.ErrUnexpectedEOF
		} else if err != nil {
			return total, err
		}
		dst = dst.DropFirst64(n)
	}
	return total, nil
}

// openPath opens name for loading.
//
// openPath returns the fs.Dirent and an *fs.File for name, which is not
// installed in the Task FDMap. The caller takes ownership of both.
//
// name must be a readable, executable, regular file.
func openPath(ctx context.Context, mm *fs.MountNamespace, root, wd *fs.Dirent, maxTraversals uint, name string) (*fs.Dirent, *fs.File, error) {
	if name == "" {
		ctx.Infof("cannot open empty name")
		return nil, nil, syserror.ENOENT
	}

	d, err := mm.FindInode(ctx, root, wd, name, maxTraversals)
	if err != nil {
		return nil, nil, err
	}
	defer d.DecRef()

	perms := fs.PermMask{
		// TODO: Linux requires only execute permission,
		// not read. However, our backing filesystems may prevent us
		// from reading the file without read permission.
		//
		// Additionally, a task with a non-readable executable has
		// additional constraints on access via ptrace and procfs.
		Read:    true,
		Execute: true,
	}
	if err := d.Inode.CheckPermission(ctx, perms); err != nil {
		return nil, nil, err
	}

	// If they claim it's a directory, then make sure.
	//
	// N.B. we reject directories below, but we must first reject
	// non-directories passed as directories.
	if len(name) > 0 && name[len(name)-1] == '/' && !fs.IsDir(d.Inode.StableAttr) {
		return nil, nil, syserror.ENOTDIR
	}

	// No exec-ing directories, pipes, etc!
	if !fs.IsRegular(d.Inode.StableAttr) {
		ctx.Infof("%s is not regular: %v", name, d.Inode.StableAttr)
		return nil, nil, syserror.EACCES
	}

	// Create a new file.
	file, err := d.Inode.GetFile(ctx, d, fs.FileFlags{Read: true})
	if err != nil {
		return nil, nil, err
	}

	// We must be able to read at arbitrary offsets.
	if !file.Flags().Pread {
		file.DecRef()
		ctx.Infof("%s cannot be read at an offset: %+v", name, file.Flags())
		return nil, nil, syserror.EACCES
	}

	// Grab a reference for the caller.
	d.IncRef()
	return d, file, nil
}

// allocStack allocates and maps a stack in to any available part of the address space.
func allocStack(ctx context.Context, m *mm.MemoryManager, a arch.Context) (*arch.Stack, error) {
	ar, err := m.MapStack(ctx)
	if err != nil {
		return nil, err
	}
	return &arch.Stack{a, m, ar.End}, nil
}

const (
	// maxLoaderAttempts is the maximum number of attempts to try to load
	// an interpreter scripts, to prevent loops. 6 (initial + 5 changes) is
	// what the Linux kernel allows (fs/exec.c:search_binary_handler).
	maxLoaderAttempts = 6
)

// loadPath resolves filename to a binary and loads it.
//
// It returns:
//  * loadedELF, description of the loaded binary
//  * arch.Context matching the binary arch
//  * fs.Dirent of the binary file
//  * Possibly updated argv
func loadPath(ctx context.Context, m *mm.MemoryManager, mounts *fs.MountNamespace, root, wd *fs.Dirent, maxTraversals uint, fs *cpuid.FeatureSet, filename string, argv, envv []string) (loadedELF, arch.Context, *fs.Dirent, []string, error) {
	for i := 0; i < maxLoaderAttempts; i++ {
		d, f, err := openPath(ctx, mounts, root, wd, maxTraversals, filename)
		if err != nil {
			ctx.Infof("Error opening %s: %v", filename, err)
			return loadedELF{}, nil, nil, nil, err
		}
		defer f.DecRef()
		// We will return d in the successful case, but defer a DecRef
		// for intermediate loops and failure cases.
		defer d.DecRef()

		// Check the header. Is this an ELF or interpreter script?
		var hdr [4]uint8
		// N.B. We assume that reading from a regular file cannot block.
		_, err = readFull(ctx, f, usermem.BytesIOSequence(hdr[:]), 0)
		// Allow unexpected EOF, as a valid executable could be only three
		// bytes (e.g., #!a).
		if err != nil && err != io.ErrUnexpectedEOF {
			if err == io.EOF {
				err = syserror.ENOEXEC
			}
			return loadedELF{}, nil, nil, nil, err
		}

		switch {
		case bytes.Equal(hdr[:], []byte(elfMagic)):
			loaded, ac, err := loadELF(ctx, m, mounts, root, wd, maxTraversals, fs, f)
			if err != nil {
				ctx.Infof("Error loading ELF: %v", err)
				return loadedELF{}, nil, nil, nil, err
			}
			// An ELF is always terminal. Hold on to d.
			d.IncRef()
			return loaded, ac, d, argv, err
		case bytes.Equal(hdr[:2], []byte(interpreterScriptMagic)):
			newpath, newargv, err := parseInterpreterScript(ctx, filename, f, argv, envv)
			if err != nil {
				ctx.Infof("Error loading interpreter script: %v", err)
				return loadedELF{}, nil, nil, nil, err
			}
			filename = newpath
			argv = newargv
		default:
			ctx.Infof("Unknown magic: %v", hdr)
			return loadedELF{}, nil, nil, nil, syserror.ENOEXEC
		}
	}

	return loadedELF{}, nil, nil, nil, syserror.ELOOP
}

// Load loads filename into a MemoryManager.
//
// If Load returns ErrSwitchFile it should be called again with the returned
// path and argv.
//
// Preconditions:
//  * The Task MemoryManager is empty.
//  * Load is called on the Task goroutine.
func Load(ctx context.Context, m *mm.MemoryManager, mounts *fs.MountNamespace, root, wd *fs.Dirent, maxTraversals uint, fs *cpuid.FeatureSet, filename string, argv, envv []string, extraAuxv []arch.AuxEntry, vdso *VDSO) (abi.OS, arch.Context, string, error) {
	// Load the binary itself.
	loaded, ac, d, argv, err := loadPath(ctx, m, mounts, root, wd, maxTraversals, fs, filename, argv, envv)
	if err != nil {
		ctx.Infof("Failed to load %s: %v", filename, err)
		return 0, nil, "", err
	}
	defer d.DecRef()

	// Load the VDSO.
	vdsoAddr, err := loadVDSO(ctx, m, vdso, loaded)
	if err != nil {
		ctx.Infof("Error loading VDSO: %v", err)
		return 0, nil, "", err
	}

	// Setup the heap. brk starts at the next page after the end of the
	// binary. Userspace can assume that the remainer of the page after
	// loaded.end is available for its use.
	e, ok := loaded.end.RoundUp()
	if !ok {
		ctx.Warningf("brk overflows: %#x", loaded.end)
		return 0, nil, "", syserror.ENOEXEC
	}
	m.BrkSetup(ctx, e)

	// Allocate our stack.
	stack, err := allocStack(ctx, m, ac)
	if err != nil {
		ctx.Infof("Failed to allocate stack: %v", err)
		return 0, nil, "", err
	}

	// Push the original filename to the stack, for AT_EXECFN.
	execfn, err := stack.Push(filename)
	if err != nil {
		ctx.Infof("Failed to push exec filename: %v", err)
		return 0, nil, "", err
	}

	// Push 16 random bytes on the stack which AT_RANDOM will point to.
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		ctx.Infof("Failed to read random bytes: %v", err)
		return 0, nil, "", err
	}
	random, err := stack.Push(b)
	if err != nil {
		ctx.Infof("Failed to push random bytes: %v", err)
		return 0, nil, "", err
	}

	c := auth.CredentialsFromContext(ctx)

	// Add generic auxv entries.
	auxv := append(loaded.auxv, arch.Auxv{
		arch.AuxEntry{linux.AT_UID, usermem.Addr(c.RealKUID.In(c.UserNamespace).OrOverflow())},
		arch.AuxEntry{linux.AT_EUID, usermem.Addr(c.EffectiveKUID.In(c.UserNamespace).OrOverflow())},
		arch.AuxEntry{linux.AT_GID, usermem.Addr(c.RealKGID.In(c.UserNamespace).OrOverflow())},
		arch.AuxEntry{linux.AT_EGID, usermem.Addr(c.EffectiveKGID.In(c.UserNamespace).OrOverflow())},
		arch.AuxEntry{linux.AT_CLKTCK, linux.CLOCKS_PER_SEC},
		arch.AuxEntry{linux.AT_EXECFN, execfn},
		arch.AuxEntry{linux.AT_RANDOM, random},
		arch.AuxEntry{linux.AT_PAGESZ, usermem.PageSize},
		arch.AuxEntry{linux.AT_SYSINFO_EHDR, vdsoAddr},
	}...)
	auxv = append(auxv, extraAuxv...)

	sl, err := stack.Load(argv, envv, auxv)
	if err != nil {
		ctx.Infof("Failed to load stack: %v", err)
		return 0, nil, "", err
	}

	m.SetArgvStart(sl.ArgvStart)
	m.SetArgvEnd(sl.ArgvEnd)
	m.SetEnvvStart(sl.EnvvStart)
	m.SetEnvvEnd(sl.EnvvEnd)
	m.SetAuxv(auxv)
	m.SetExecutable(d)

	ac.SetIP(uintptr(loaded.entry))
	ac.SetStack(uintptr(stack.Bottom))

	name := path.Base(filename)
	if len(name) > linux.TASK_COMM_LEN-1 {
		name = name[:linux.TASK_COMM_LEN-1]
	}

	return loaded.os, ac, name, nil
}
