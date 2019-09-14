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

package linux

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/fs/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/fasync"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
)

// fileOpAt performs an operation on the second last component in the path.
func fileOpAt(t *kernel.Task, dirFD int32, path string, fn func(root *fs.Dirent, d *fs.Dirent, name string, remainingTraversals uint) error) error {
	// Extract the last component.
	dir, name := fs.SplitLast(path)
	if dir == "/" {
		// Common case: we are accessing a file in the root.
		root := t.FSContext().RootDirectory()
		err := fn(root, root, name, linux.MaxSymlinkTraversals)
		root.DecRef()
		return err
	} else if dir == "." && dirFD == linux.AT_FDCWD {
		// Common case: we are accessing a file relative to the current
		// working directory; skip the look-up.
		wd := t.FSContext().WorkingDirectory()
		root := t.FSContext().RootDirectory()
		err := fn(root, wd, name, linux.MaxSymlinkTraversals)
		wd.DecRef()
		root.DecRef()
		return err
	}

	return fileOpOn(t, dirFD, dir, true /* resolve */, func(root *fs.Dirent, d *fs.Dirent, remainingTraversals uint) error {
		return fn(root, d, name, remainingTraversals)
	})
}

// fileOpOn performs an operation on the last entry of the path.
func fileOpOn(t *kernel.Task, dirFD int32, path string, resolve bool, fn func(root *fs.Dirent, d *fs.Dirent, remainingTraversals uint) error) error {
	var (
		d   *fs.Dirent // The file.
		wd  *fs.Dirent // The working directory (if required.)
		rel *fs.Dirent // The relative directory for search (if required.)
		f   *fs.File   // The file corresponding to dirFD (if required.)
		err error
	)

	// Extract the working directory (maybe).
	if len(path) > 0 && path[0] == '/' {
		// Absolute path; rel can be nil.
	} else if dirFD == linux.AT_FDCWD {
		// Need to reference the working directory.
		wd = t.FSContext().WorkingDirectory()
		rel = wd
	} else {
		// Need to extract the given FD.
		f = t.GetFile(dirFD)
		if f == nil {
			return syserror.EBADF
		}
		rel = f.Dirent
		if !fs.IsDir(rel.Inode.StableAttr) {
			return syserror.ENOTDIR
		}
	}

	// Grab the root (always required.)
	root := t.FSContext().RootDirectory()

	// Lookup the node.
	remainingTraversals := uint(linux.MaxSymlinkTraversals)
	if resolve {
		d, err = t.MountNamespace().FindInode(t, root, rel, path, &remainingTraversals)
	} else {
		d, err = t.MountNamespace().FindLink(t, root, rel, path, &remainingTraversals)
	}
	root.DecRef()
	if wd != nil {
		wd.DecRef()
	}
	if f != nil {
		f.DecRef()
	}
	if err != nil {
		return err
	}

	err = fn(root, d, remainingTraversals)
	d.DecRef()
	return err
}

// copyInPath copies a path in.
func copyInPath(t *kernel.Task, addr usermem.Addr, allowEmpty bool) (path string, dirPath bool, err error) {
	path, err = t.CopyInString(addr, linux.PATH_MAX)
	if err != nil {
		return "", false, err
	}
	if path == "" && !allowEmpty {
		return "", false, syserror.ENOENT
	}

	// If the path ends with a /, then checks must be enforced in various
	// ways in the different callers. We pass this back to the caller.
	path, dirPath = fs.TrimTrailingSlashes(path)

	return path, dirPath, nil
}

func openAt(t *kernel.Task, dirFD int32, addr usermem.Addr, flags uint) (fd uintptr, err error) {
	path, dirPath, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return 0, err
	}

	resolve := flags&linux.O_NOFOLLOW == 0
	err = fileOpOn(t, dirFD, path, resolve, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		// First check a few things about the filesystem before trying to get the file
		// reference.
		//
		// It's required that Check does not try to open files not that aren't backed by
		// this dirent (e.g. pipes and sockets) because this would result in opening these
		// files an extra time just to check permissions.
		if err := d.Inode.CheckPermission(t, flagsToPermissions(flags)); err != nil {
			return err
		}

		if fs.IsSymlink(d.Inode.StableAttr) && !resolve {
			return syserror.ELOOP
		}

		fileFlags := linuxToFlags(flags)
		// Linux always adds the O_LARGEFILE flag when running in 64-bit mode.
		fileFlags.LargeFile = true
		if fs.IsDir(d.Inode.StableAttr) {
			// Don't allow directories to be opened writable.
			if fileFlags.Write {
				return syserror.EISDIR
			}
		} else {
			// If O_DIRECTORY is set, but the file is not a directory, then fail.
			if fileFlags.Directory {
				return syserror.ENOTDIR
			}
			// If it's a directory, then make sure.
			if dirPath {
				return syserror.ENOTDIR
			}
			if flags&linux.O_TRUNC != 0 {
				if err := d.Inode.Truncate(t, d, 0); err != nil {
					return err
				}
			}
		}

		file, err := d.Inode.GetFile(t, d, fileFlags)
		if err != nil {
			return syserror.ConvertIntr(err, kernel.ERESTARTSYS)
		}
		defer file.DecRef()

		// Success.
		newFD, err := t.NewFDFrom(0, file, kernel.FDFlags{
			CloseOnExec: flags&linux.O_CLOEXEC != 0,
		})
		if err != nil {
			return err
		}

		// Set return result in frame.
		fd = uintptr(newFD)

		// Generate notification for opened file.
		d.InotifyEvent(linux.IN_OPEN, 0)

		return nil
	})
	return fd, err // Use result in frame.
}

func mknodAt(t *kernel.Task, dirFD int32, addr usermem.Addr, mode linux.FileMode) error {
	path, dirPath, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return err
	}
	if dirPath {
		return syserror.ENOENT
	}

	return fileOpAt(t, dirFD, path, func(root *fs.Dirent, d *fs.Dirent, name string, _ uint) error {
		if !fs.IsDir(d.Inode.StableAttr) {
			return syserror.ENOTDIR
		}

		// Do we have the appropriate permissions on the parent?
		if err := d.Inode.CheckPermission(t, fs.PermMask{Write: true, Execute: true}); err != nil {
			return err
		}

		// Attempt a creation.
		perms := fs.FilePermsFromMode(mode &^ linux.FileMode(t.FSContext().Umask()))

		switch mode.FileType() {
		case 0:
			// "Zero file type is equivalent to type S_IFREG." - mknod(2)
			fallthrough
		case linux.ModeRegular:
			// We are not going to return the file, so the actual
			// flags used don't matter, but they cannot be empty or
			// Create will complain.
			flags := fs.FileFlags{Read: true, Write: true}
			file, err := d.Create(t, root, name, flags, perms)
			if err != nil {
				return err
			}
			file.DecRef()
			return nil

		case linux.ModeNamedPipe:
			return d.CreateFifo(t, root, name, perms)

		case linux.ModeSocket:
			// While it is possible create a unix domain socket file on linux
			// using mknod(2), in practice this is pretty useless from an
			// application. Linux internally uses mknod() to create the socket
			// node during bind(2), but we implement bind(2) independently. If
			// an application explicitly creates a socket node using mknod(),
			// you can't seem to bind() or connect() to the resulting socket.
			//
			// Instead of emulating this seemingly useless behaviour, we'll
			// indicate that the filesystem doesn't support the creation of
			// sockets.
			return syserror.EOPNOTSUPP

		case linux.ModeCharacterDevice:
			fallthrough
		case linux.ModeBlockDevice:
			// TODO(b/72101894): We don't support creating block or character
			// devices at the moment.
			//
			// When we start supporting block and character devices, we'll
			// need to check for CAP_MKNOD here.
			return syserror.EPERM

		default:
			// "EINVAL - mode requested creation of something other than a
			// regular file, device special file, FIFO or socket." - mknod(2)
			return syserror.EINVAL
		}
	})
}

// Mknod implements the linux syscall mknod(2).
func Mknod(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	path := args[0].Pointer()
	mode := linux.FileMode(args[1].ModeT())
	// We don't need this argument until we support creation of device nodes.
	_ = args[2].Uint() // dev

	return 0, nil, mknodAt(t, linux.AT_FDCWD, path, mode)
}

// Mknodat implements the linux syscall mknodat(2).
func Mknodat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirFD := args[0].Int()
	path := args[1].Pointer()
	mode := linux.FileMode(args[2].ModeT())
	// We don't need this argument until we support creation of device nodes.
	_ = args[3].Uint() // dev

	return 0, nil, mknodAt(t, dirFD, path, mode)
}

func createAt(t *kernel.Task, dirFD int32, addr usermem.Addr, flags uint, mode linux.FileMode) (fd uintptr, err error) {
	path, dirPath, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return 0, err
	}
	if dirPath {
		return 0, syserror.ENOENT
	}

	fileFlags := linuxToFlags(flags)
	// Linux always adds the O_LARGEFILE flag when running in 64-bit mode.
	fileFlags.LargeFile = true

	err = fileOpAt(t, dirFD, path, func(root *fs.Dirent, parent *fs.Dirent, name string, remainingTraversals uint) error {
		// Resolve the name to see if it exists, and follow any
		// symlinks along the way. We must do the symlink resolution
		// manually because if the symlink target does not exist, we
		// must create the target (and not the symlink itself).
		var (
			found *fs.Dirent
			err   error
		)
		for {
			if !fs.IsDir(parent.Inode.StableAttr) {
				return syserror.ENOTDIR
			}

			// Start by looking up the dirent at 'name'.
			found, err = t.MountNamespace().FindLink(t, root, parent, name, &remainingTraversals)
			if err != nil {
				break
			}
			defer found.DecRef()

			// We found something (possibly a symlink). If the
			// O_EXCL flag was passed, then we can immediately
			// return EEXIST.
			if flags&linux.O_EXCL != 0 {
				return syserror.EEXIST
			}

			// If we have a non-symlink, then we can proceed.
			if !fs.IsSymlink(found.Inode.StableAttr) {
				break
			}

			// If O_NOFOLLOW was passed, then don't try to resolve
			// anything.
			if flags&linux.O_NOFOLLOW != 0 {
				return syserror.ELOOP
			}

			// Try to resolve the symlink directly to a Dirent.
			var resolved *fs.Dirent
			resolved, err = found.Inode.Getlink(t)
			if err == nil {
				// No more resolution necessary.
				defer resolved.DecRef()
				break
			}
			if err != fs.ErrResolveViaReadlink {
				return err
			}

			// Are we able to resolve further?
			if remainingTraversals == 0 {
				return syscall.ELOOP
			}

			// Resolve the symlink to a path via Readlink.
			var path string
			path, err = found.Inode.Readlink(t)
			if err != nil {
				break
			}
			remainingTraversals--

			// Get the new parent from the target path.
			var newParent *fs.Dirent
			newParentPath, newName := fs.SplitLast(path)
			newParent, err = t.MountNamespace().FindInode(t, root, parent, newParentPath, &remainingTraversals)
			if err != nil {
				break
			}
			defer newParent.DecRef()

			// Repeat the process with the parent and name of the
			// symlink target.
			parent = newParent
			name = newName
		}

		var newFile *fs.File
		switch err {
		case nil:
			// Like sys_open, check for a few things about the
			// filesystem before trying to get a reference to the
			// fs.File. The same constraints on Check apply.
			if err := found.Inode.CheckPermission(t, flagsToPermissions(flags)); err != nil {
				return err
			}

			// Should we truncate the file?
			if flags&linux.O_TRUNC != 0 {
				if err := found.Inode.Truncate(t, found, 0); err != nil {
					return err
				}
			}

			// Create a new fs.File.
			newFile, err = found.Inode.GetFile(t, found, fileFlags)
			if err != nil {
				return syserror.ConvertIntr(err, kernel.ERESTARTSYS)
			}
			defer newFile.DecRef()
		case syserror.ENOENT:
			// File does not exist. Proceed with creation.

			// Do we have write permissions on the parent?
			if err := parent.Inode.CheckPermission(t, fs.PermMask{Write: true, Execute: true}); err != nil {
				return err
			}

			// Attempt a creation.
			perms := fs.FilePermsFromMode(mode &^ linux.FileMode(t.FSContext().Umask()))
			newFile, err = parent.Create(t, root, name, fileFlags, perms)
			if err != nil {
				// No luck, bail.
				return err
			}
			defer newFile.DecRef()
			found = newFile.Dirent
		default:
			return err
		}

		// Success.
		newFD, err := t.NewFDFrom(0, newFile, kernel.FDFlags{
			CloseOnExec: flags&linux.O_CLOEXEC != 0,
		})
		if err != nil {
			return err
		}

		// Set result in frame.
		fd = uintptr(newFD)

		// Queue the open inotify event. The creation event is
		// automatically queued when the dirent is found. The open
		// events are implemented at the syscall layer so we need to
		// manually queue one here.
		found.InotifyEvent(linux.IN_OPEN, 0)

		return nil
	})
	return fd, err // Use result in frame.
}

// Open implements linux syscall open(2).
func Open(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	flags := uint(args[1].Uint())
	if flags&linux.O_CREAT != 0 {
		mode := linux.FileMode(args[2].ModeT())
		n, err := createAt(t, linux.AT_FDCWD, addr, flags, mode)
		return n, nil, err
	}
	n, err := openAt(t, linux.AT_FDCWD, addr, flags)
	return n, nil, err
}

// Openat implements linux syscall openat(2).
func Openat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirFD := args[0].Int()
	addr := args[1].Pointer()
	flags := uint(args[2].Uint())
	if flags&linux.O_CREAT != 0 {
		mode := linux.FileMode(args[3].ModeT())
		n, err := createAt(t, dirFD, addr, flags, mode)
		return n, nil, err
	}
	n, err := openAt(t, dirFD, addr, flags)
	return n, nil, err
}

// Creat implements linux syscall creat(2).
func Creat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	mode := linux.FileMode(args[1].ModeT())
	n, err := createAt(t, linux.AT_FDCWD, addr, linux.O_WRONLY|linux.O_TRUNC, mode)
	return n, nil, err
}

// accessContext is a context that overrides the credentials used, but
// otherwise carries the same values as the embedded context.
//
// accessContext should only be used for access(2).
type accessContext struct {
	context.Context
	creds *auth.Credentials
}

// Value implements context.Context.
func (ac accessContext) Value(key interface{}) interface{} {
	switch key {
	case auth.CtxCredentials:
		return ac.creds
	default:
		return ac.Context.Value(key)
	}
}

func accessAt(t *kernel.Task, dirFD int32, addr usermem.Addr, resolve bool, mode uint) error {
	const rOK = 4
	const wOK = 2
	const xOK = 1

	path, _, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return err
	}

	// Sanity check the mode.
	if mode&^(rOK|wOK|xOK) != 0 {
		return syserror.EINVAL
	}

	return fileOpOn(t, dirFD, path, resolve, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		// access(2) and faccessat(2) check permissions using real
		// UID/GID, not effective UID/GID.
		//
		// "access() needs to use the real uid/gid, not the effective
		// uid/gid. We do this by temporarily clearing all FS-related
		// capabilities and switching the fsuid/fsgid around to the
		// real ones." -fs/open.c:faccessat
		creds := t.Credentials().Fork()
		creds.EffectiveKUID = creds.RealKUID
		creds.EffectiveKGID = creds.RealKGID
		if creds.EffectiveKUID.In(creds.UserNamespace) == auth.RootUID {
			creds.EffectiveCaps = creds.PermittedCaps
		} else {
			creds.EffectiveCaps = 0
		}

		ctx := &accessContext{
			Context: t,
			creds:   creds,
		}

		return d.Inode.CheckPermission(ctx, fs.PermMask{
			Read:    mode&rOK != 0,
			Write:   mode&wOK != 0,
			Execute: mode&xOK != 0,
		})
	})
}

// Access implements linux syscall access(2).
func Access(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	mode := args[1].ModeT()

	return 0, nil, accessAt(t, linux.AT_FDCWD, addr, true, mode)
}

// Faccessat implements linux syscall faccessat(2).
func Faccessat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirFD := args[0].Int()
	addr := args[1].Pointer()
	mode := args[2].ModeT()
	flags := args[3].Int()

	return 0, nil, accessAt(t, dirFD, addr, flags&linux.AT_SYMLINK_NOFOLLOW == 0, mode)
}

// Ioctl implements linux syscall ioctl(2).
func Ioctl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	request := int(args[1].Int())

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// Shared flags between file and socket.
	switch request {
	case linux.FIONCLEX:
		t.FDTable().SetFlags(fd, kernel.FDFlags{
			CloseOnExec: false,
		})
		return 0, nil, nil
	case linux.FIOCLEX:
		t.FDTable().SetFlags(fd, kernel.FDFlags{
			CloseOnExec: true,
		})
		return 0, nil, nil

	case linux.FIONBIO:
		var set int32
		if _, err := t.CopyIn(args[2].Pointer(), &set); err != nil {
			return 0, nil, err
		}
		flags := file.Flags()
		if set != 0 {
			flags.NonBlocking = true
		} else {
			flags.NonBlocking = false
		}
		file.SetFlags(flags.Settable())
		return 0, nil, nil

	case linux.FIOASYNC:
		var set int32
		if _, err := t.CopyIn(args[2].Pointer(), &set); err != nil {
			return 0, nil, err
		}
		flags := file.Flags()
		if set != 0 {
			flags.Async = true
		} else {
			flags.Async = false
		}
		file.SetFlags(flags.Settable())
		return 0, nil, nil

	case linux.FIOSETOWN, linux.SIOCSPGRP:
		var set int32
		if _, err := t.CopyIn(args[2].Pointer(), &set); err != nil {
			return 0, nil, err
		}
		fSetOwn(t, file, set)
		return 0, nil, nil

	case linux.FIOGETOWN, linux.SIOCGPGRP:
		who := fGetOwn(t, file)
		_, err := t.CopyOut(args[2].Pointer(), &who)
		return 0, nil, err

	default:
		ret, err := file.FileOperations.Ioctl(t, file, t.MemoryManager(), args)
		if err != nil {
			return 0, nil, err
		}

		return ret, nil, nil
	}
}

// Getcwd implements the linux syscall getcwd(2).
func Getcwd(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	size := args[1].SizeT()
	cwd := t.FSContext().WorkingDirectory()
	defer cwd.DecRef()
	root := t.FSContext().RootDirectory()
	defer root.DecRef()

	// Get our fullname from the root and preprend unreachable if the root was
	// unreachable from our current dirent this is the same behavior as on linux.
	s, reachable := cwd.FullName(root)
	if !reachable {
		s = "(unreachable)" + s
	}

	// Note this is >= because we need a terminator.
	if uint(len(s)) >= size {
		return 0, nil, syserror.ERANGE
	}

	// Copy out the path name for the node.
	bytes, err := t.CopyOutBytes(addr, []byte(s))
	if err != nil {
		return 0, nil, err
	}

	// Top it off with a terminator.
	_, err = t.CopyOut(addr+usermem.Addr(bytes), []byte("\x00"))
	return uintptr(bytes + 1), nil, err
}

// Chroot implements the linux syscall chroot(2).
func Chroot(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	if !t.HasCapability(linux.CAP_SYS_CHROOT) {
		return 0, nil, syserror.EPERM
	}

	path, _, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, path, true /* resolve */, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		// Is it a directory?
		if !fs.IsDir(d.Inode.StableAttr) {
			return syserror.ENOTDIR
		}

		// Does it have execute permissions?
		if err := d.Inode.CheckPermission(t, fs.PermMask{Execute: true}); err != nil {
			return err
		}

		t.FSContext().SetRootDirectory(d)
		return nil
	})
}

// Chdir implements the linux syscall chdir(2).
func Chdir(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	path, _, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, path, true /* resolve */, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		// Is it a directory?
		if !fs.IsDir(d.Inode.StableAttr) {
			return syserror.ENOTDIR
		}

		// Does it have execute permissions?
		if err := d.Inode.CheckPermission(t, fs.PermMask{Execute: true}); err != nil {
			return err
		}

		t.FSContext().SetWorkingDirectory(d)
		return nil
	})
}

// Fchdir implements the linux syscall fchdir(2).
func Fchdir(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// Is it a directory?
	if !fs.IsDir(file.Dirent.Inode.StableAttr) {
		return 0, nil, syserror.ENOTDIR
	}

	// Does it have execute permissions?
	if err := file.Dirent.Inode.CheckPermission(t, fs.PermMask{Execute: true}); err != nil {
		return 0, nil, err
	}

	t.FSContext().SetWorkingDirectory(file.Dirent)
	return 0, nil, nil
}

// Close implements linux syscall close(2).
func Close(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	// Note that Remove provides a reference on the file that we may use to
	// flush. It is still active until we drop the final reference below
	// (and other reference-holding operations complete).
	file := t.FDTable().Remove(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	err := file.Flush(t)
	return 0, nil, handleIOError(t, false /* partial */, err, syserror.EINTR, "close", file)
}

// Dup implements linux syscall dup(2).
func Dup(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	newFD, err := t.NewFDFrom(0, file, kernel.FDFlags{})
	if err != nil {
		return 0, nil, syserror.EMFILE
	}
	return uintptr(newFD), nil, nil
}

// Dup2 implements linux syscall dup2(2).
func Dup2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldfd := args[0].Int()
	newfd := args[1].Int()

	// If oldfd is a valid file descriptor, and newfd has the same value as oldfd,
	// then dup2() does nothing, and returns newfd.
	if oldfd == newfd {
		oldFile := t.GetFile(oldfd)
		if oldFile == nil {
			return 0, nil, syserror.EBADF
		}
		defer oldFile.DecRef()

		return uintptr(newfd), nil, nil
	}

	// Zero out flags arg to be used by Dup3.
	args[2].Value = 0
	return Dup3(t, args)
}

// Dup3 implements linux syscall dup3(2).
func Dup3(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldfd := args[0].Int()
	newfd := args[1].Int()
	flags := args[2].Uint()

	if oldfd == newfd {
		return 0, nil, syserror.EINVAL
	}

	oldFile := t.GetFile(oldfd)
	if oldFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer oldFile.DecRef()

	err := t.NewFDAt(newfd, oldFile, kernel.FDFlags{CloseOnExec: flags&linux.O_CLOEXEC != 0})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(newfd), nil, nil
}

func fGetOwn(t *kernel.Task, file *fs.File) int32 {
	ma := file.Async(nil)
	if ma == nil {
		return 0
	}
	a := ma.(*fasync.FileAsync)
	ot, otg, opg := a.Owner()
	switch {
	case ot != nil:
		return int32(t.PIDNamespace().IDOfTask(ot))
	case otg != nil:
		return int32(t.PIDNamespace().IDOfThreadGroup(otg))
	case opg != nil:
		return int32(-t.PIDNamespace().IDOfProcessGroup(opg))
	default:
		return 0
	}
}

// fSetOwn sets the file's owner with the semantics of F_SETOWN in Linux.
//
// If who is positive, it represents a PID. If negative, it represents a PGID.
// If the PID or PGID is invalid, the owner is silently unset.
func fSetOwn(t *kernel.Task, file *fs.File, who int32) {
	a := file.Async(fasync.New).(*fasync.FileAsync)
	if who < 0 {
		pg := t.PIDNamespace().ProcessGroupWithID(kernel.ProcessGroupID(-who))
		a.SetOwnerProcessGroup(t, pg)
	}
	tg := t.PIDNamespace().ThreadGroupWithID(kernel.ThreadID(who))
	a.SetOwnerThreadGroup(t, tg)
}

// Fcntl implements linux syscall fcntl(2).
func Fcntl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	cmd := args[1].Int()

	file, flags := t.FDTable().Get(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	switch cmd {
	case linux.F_DUPFD, linux.F_DUPFD_CLOEXEC:
		from := args[2].Int()
		fd, err := t.NewFDFrom(from, file, kernel.FDFlags{
			CloseOnExec: cmd == linux.F_DUPFD_CLOEXEC,
		})
		if err != nil {
			return 0, nil, err
		}
		return uintptr(fd), nil, nil
	case linux.F_GETFD:
		return uintptr(flags.ToLinuxFDFlags()), nil, nil
	case linux.F_SETFD:
		flags := args[2].Uint()
		t.FDTable().SetFlags(fd, kernel.FDFlags{
			CloseOnExec: flags&linux.FD_CLOEXEC != 0,
		})
	case linux.F_GETFL:
		return uintptr(file.Flags().ToLinux()), nil, nil
	case linux.F_SETFL:
		flags := uint(args[2].Uint())
		file.SetFlags(linuxToFlags(flags).Settable())
	case linux.F_SETLK, linux.F_SETLKW:
		// In Linux the file system can choose to provide lock operations for an inode.
		// Normally pipe and socket types lack lock operations. We diverge and use a heavy
		// hammer by only allowing locks on files and directories.
		if !fs.IsFile(file.Dirent.Inode.StableAttr) && !fs.IsDir(file.Dirent.Inode.StableAttr) {
			return 0, nil, syserror.EBADF
		}

		// Copy in the lock request.
		flockAddr := args[2].Pointer()
		var flock linux.Flock
		if _, err := t.CopyIn(flockAddr, &flock); err != nil {
			return 0, nil, err
		}

		// Compute the lock whence.
		var sw fs.SeekWhence
		switch flock.Whence {
		case 0:
			sw = fs.SeekSet
		case 1:
			sw = fs.SeekCurrent
		case 2:
			sw = fs.SeekEnd
		default:
			return 0, nil, syserror.EINVAL
		}

		// Compute the lock offset.
		var off int64
		switch sw {
		case fs.SeekSet:
			off = 0
		case fs.SeekCurrent:
			// Note that Linux does not hold any mutexes while retrieving the file offset,
			// see fs/locks.c:flock_to_posix_lock and fs/locks.c:fcntl_setlk.
			off = file.Offset()
		case fs.SeekEnd:
			uattr, err := file.Dirent.Inode.UnstableAttr(t)
			if err != nil {
				return 0, nil, err
			}
			off = uattr.Size
		default:
			return 0, nil, syserror.EINVAL
		}

		// Compute the lock range.
		rng, err := lock.ComputeRange(flock.Start, flock.Len, off)
		if err != nil {
			return 0, nil, err
		}

		// The lock uid is that of the Task's FDTable.
		lockUniqueID := lock.UniqueID(t.FDTable().ID())

		// These locks don't block; execute the non-blocking operation using the inode's lock
		// context directly.
		switch flock.Type {
		case linux.F_RDLCK:
			if !file.Flags().Read {
				return 0, nil, syserror.EBADF
			}
			if cmd == linux.F_SETLK {
				// Non-blocking lock, provide a nil lock.Blocker.
				if !file.Dirent.Inode.LockCtx.Posix.LockRegion(lockUniqueID, lock.ReadLock, rng, nil) {
					return 0, nil, syserror.EAGAIN
				}
			} else {
				// Blocking lock, pass in the task to satisfy the lock.Blocker interface.
				if !file.Dirent.Inode.LockCtx.Posix.LockRegion(lockUniqueID, lock.ReadLock, rng, t) {
					return 0, nil, syserror.EINTR
				}
			}
			return 0, nil, nil
		case linux.F_WRLCK:
			if !file.Flags().Write {
				return 0, nil, syserror.EBADF
			}
			if cmd == linux.F_SETLK {
				// Non-blocking lock, provide a nil lock.Blocker.
				if !file.Dirent.Inode.LockCtx.Posix.LockRegion(lockUniqueID, lock.WriteLock, rng, nil) {
					return 0, nil, syserror.EAGAIN
				}
			} else {
				// Blocking lock, pass in the task to satisfy the lock.Blocker interface.
				if !file.Dirent.Inode.LockCtx.Posix.LockRegion(lockUniqueID, lock.WriteLock, rng, t) {
					return 0, nil, syserror.EINTR
				}
			}
			return 0, nil, nil
		case linux.F_UNLCK:
			file.Dirent.Inode.LockCtx.Posix.UnlockRegion(lockUniqueID, rng)
			return 0, nil, nil
		default:
			return 0, nil, syserror.EINVAL
		}
	case linux.F_GETOWN:
		return uintptr(fGetOwn(t, file)), nil, nil
	case linux.F_SETOWN:
		fSetOwn(t, file, args[2].Int())
		return 0, nil, nil
	case linux.F_GET_SEALS:
		val, err := tmpfs.GetSeals(file.Dirent.Inode)
		return uintptr(val), nil, err
	case linux.F_ADD_SEALS:
		if !file.Flags().Write {
			return 0, nil, syserror.EPERM
		}
		err := tmpfs.AddSeals(file.Dirent.Inode, args[2].Uint())
		return 0, nil, err
	case linux.F_GETPIPE_SZ:
		sz, ok := file.FileOperations.(fs.FifoSizer)
		if !ok {
			return 0, nil, syserror.EINVAL
		}
		size, err := sz.FifoSize(t, file)
		return uintptr(size), nil, err
	case linux.F_SETPIPE_SZ:
		sz, ok := file.FileOperations.(fs.FifoSizer)
		if !ok {
			return 0, nil, syserror.EINVAL
		}
		n, err := sz.SetFifoSize(int64(args[2].Int()))
		return uintptr(n), nil, err
	default:
		// Everything else is not yet supported.
		return 0, nil, syserror.EINVAL
	}
	return 0, nil, nil
}

const (
	_FADV_NORMAL     = 0
	_FADV_RANDOM     = 1
	_FADV_SEQUENTIAL = 2
	_FADV_WILLNEED   = 3
	_FADV_DONTNEED   = 4
	_FADV_NOREUSE    = 5
)

// Fadvise64 implements linux syscall fadvise64(2).
// This implementation currently ignores the provided advice.
func Fadvise64(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	length := args[2].Int64()
	advice := args[3].Int()

	// Note: offset is allowed to be negative.
	if length < 0 {
		return 0, nil, syserror.EINVAL
	}

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// If the FD refers to a pipe or FIFO, return error.
	if fs.IsPipe(file.Dirent.Inode.StableAttr) {
		return 0, nil, syserror.ESPIPE
	}

	switch advice {
	case _FADV_NORMAL:
	case _FADV_RANDOM:
	case _FADV_SEQUENTIAL:
	case _FADV_WILLNEED:
	case _FADV_DONTNEED:
	case _FADV_NOREUSE:
	default:
		return 0, nil, syserror.EINVAL
	}

	// Sure, whatever.
	return 0, nil, nil
}

func mkdirAt(t *kernel.Task, dirFD int32, addr usermem.Addr, mode linux.FileMode) error {
	path, _, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return err
	}

	return fileOpAt(t, dirFD, path, func(root *fs.Dirent, d *fs.Dirent, name string, _ uint) error {
		if !fs.IsDir(d.Inode.StableAttr) {
			return syserror.ENOTDIR
		}

		// Does this directory exist already?
		remainingTraversals := uint(linux.MaxSymlinkTraversals)
		f, err := t.MountNamespace().FindInode(t, root, d, name, &remainingTraversals)
		switch err {
		case nil:
			// The directory existed.
			defer f.DecRef()
			return syserror.EEXIST
		case syserror.EACCES:
			// Permission denied while walking to the directory.
			return err
		default:
			// Do we have write permissions on the parent?
			if err := d.Inode.CheckPermission(t, fs.PermMask{Write: true, Execute: true}); err != nil {
				return err
			}

			// Create the directory.
			perms := fs.FilePermsFromMode(mode &^ linux.FileMode(t.FSContext().Umask()))
			return d.CreateDirectory(t, root, name, perms)
		}
	})
}

// Mkdir implements linux syscall mkdir(2).
func Mkdir(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	mode := linux.FileMode(args[1].ModeT())

	return 0, nil, mkdirAt(t, linux.AT_FDCWD, addr, mode)
}

// Mkdirat implements linux syscall mkdirat(2).
func Mkdirat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirFD := args[0].Int()
	addr := args[1].Pointer()
	mode := linux.FileMode(args[2].ModeT())

	return 0, nil, mkdirAt(t, dirFD, addr, mode)
}

func rmdirAt(t *kernel.Task, dirFD int32, addr usermem.Addr) error {
	path, _, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return err
	}

	// Special case: removing the root always returns EBUSY.
	if path == "/" {
		return syserror.EBUSY
	}

	return fileOpAt(t, dirFD, path, func(root *fs.Dirent, d *fs.Dirent, name string, _ uint) error {
		if !fs.IsDir(d.Inode.StableAttr) {
			return syserror.ENOTDIR
		}

		// Linux returns different ernos when the path ends in single
		// dot vs. double dots.
		switch name {
		case ".":
			return syserror.EINVAL
		case "..":
			return syserror.ENOTEMPTY
		}

		if err := fs.MayDelete(t, root, d, name); err != nil {
			return err
		}

		return d.RemoveDirectory(t, root, name)
	})
}

// Rmdir implements linux syscall rmdir(2).
func Rmdir(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	return 0, nil, rmdirAt(t, linux.AT_FDCWD, addr)
}

func symlinkAt(t *kernel.Task, dirFD int32, newAddr usermem.Addr, oldAddr usermem.Addr) error {
	newPath, dirPath, err := copyInPath(t, newAddr, false /* allowEmpty */)
	if err != nil {
		return err
	}
	if dirPath {
		return syserror.ENOENT
	}

	// The oldPath is copied in verbatim. This is because the symlink
	// will include all details, including trailing slashes.
	oldPath, err := t.CopyInString(oldAddr, linux.PATH_MAX)
	if err != nil {
		return err
	}
	if oldPath == "" {
		return syserror.ENOENT
	}

	return fileOpAt(t, dirFD, newPath, func(root *fs.Dirent, d *fs.Dirent, name string, _ uint) error {
		if !fs.IsDir(d.Inode.StableAttr) {
			return syserror.ENOTDIR
		}

		// Make sure we have write permissions on the parent directory.
		if err := d.Inode.CheckPermission(t, fs.PermMask{Write: true, Execute: true}); err != nil {
			return err
		}
		return d.CreateLink(t, root, oldPath, name)
	})
}

// Symlink implements linux syscall symlink(2).
func Symlink(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldAddr := args[0].Pointer()
	newAddr := args[1].Pointer()

	return 0, nil, symlinkAt(t, linux.AT_FDCWD, newAddr, oldAddr)
}

// Symlinkat implements linux syscall symlinkat(2).
func Symlinkat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldAddr := args[0].Pointer()
	dirFD := args[1].Int()
	newAddr := args[2].Pointer()

	return 0, nil, symlinkAt(t, dirFD, newAddr, oldAddr)
}

// mayLinkAt determines whether t can create a hard link to target.
//
// This corresponds to Linux's fs/namei.c:may_linkat.
func mayLinkAt(t *kernel.Task, target *fs.Inode) error {
	// Linux will impose the following restrictions on hard links only if
	// sysctl_protected_hardlinks is enabled. The kernel disables this
	// setting by default for backward compatibility (see commit
	// 561ec64ae67e), but also recommends that distributions enable it (and
	// Debian does:
	// https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=889098).
	//
	// gVisor currently behaves as though sysctl_protected_hardlinks is
	// always enabled, and thus imposes the following restrictions on hard
	// links.

	if target.CheckOwnership(t) {
		// fs/namei.c:may_linkat: "Source inode owner (or CAP_FOWNER)
		// can hardlink all they like."
		return nil
	}

	// If we are not the owner, then the file must be regular and have
	// Read+Write permissions.
	if !fs.IsRegular(target.StableAttr) {
		return syserror.EPERM
	}
	if target.CheckPermission(t, fs.PermMask{Read: true, Write: true}) != nil {
		return syserror.EPERM
	}

	return nil
}

// linkAt creates a hard link to the target specified by oldDirFD and oldAddr,
// specified by newDirFD and newAddr.  If resolve is true, then the symlinks
// will be followed when evaluating the target.
func linkAt(t *kernel.Task, oldDirFD int32, oldAddr usermem.Addr, newDirFD int32, newAddr usermem.Addr, resolve, allowEmpty bool) error {
	oldPath, _, err := copyInPath(t, oldAddr, allowEmpty)
	if err != nil {
		return err
	}
	newPath, dirPath, err := copyInPath(t, newAddr, false /* allowEmpty */)
	if err != nil {
		return err
	}
	if dirPath {
		return syserror.ENOENT
	}

	if allowEmpty && oldPath == "" {
		target := t.GetFile(oldDirFD)
		if target == nil {
			return syserror.EBADF
		}
		defer target.DecRef()
		if err := mayLinkAt(t, target.Dirent.Inode); err != nil {
			return err
		}

		// Resolve the target directory.
		return fileOpAt(t, newDirFD, newPath, func(root *fs.Dirent, newParent *fs.Dirent, newName string, _ uint) error {
			if !fs.IsDir(newParent.Inode.StableAttr) {
				return syserror.ENOTDIR
			}

			// Make sure we have write permissions on the parent directory.
			if err := newParent.Inode.CheckPermission(t, fs.PermMask{Write: true, Execute: true}); err != nil {
				return err
			}
			return newParent.CreateHardLink(t, root, target.Dirent, newName)
		})
	}

	// Resolve oldDirFD and oldAddr to a dirent.  The "resolve" argument
	// only applies to this name.
	return fileOpOn(t, oldDirFD, oldPath, resolve, func(root *fs.Dirent, target *fs.Dirent, _ uint) error {
		if err := mayLinkAt(t, target.Inode); err != nil {
			return err
		}

		// Next resolve newDirFD and newAddr to the parent dirent and name.
		return fileOpAt(t, newDirFD, newPath, func(root *fs.Dirent, newParent *fs.Dirent, newName string, _ uint) error {
			if !fs.IsDir(newParent.Inode.StableAttr) {
				return syserror.ENOTDIR
			}

			// Make sure we have write permissions on the parent directory.
			if err := newParent.Inode.CheckPermission(t, fs.PermMask{Write: true, Execute: true}); err != nil {
				return err
			}
			return newParent.CreateHardLink(t, root, target, newName)
		})
	})
}

// Link implements linux syscall link(2).
func Link(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldAddr := args[0].Pointer()
	newAddr := args[1].Pointer()

	// man link(2):
	// POSIX.1-2001 says that link() should dereference oldpath if it is a
	// symbolic link. However, since kernel 2.0, Linux does not do so: if
	// oldpath is a symbolic link, then newpath is created as a (hard) link
	// to the same symbolic link file (i.e., newpath becomes a symbolic
	// link to the same file that oldpath refers to).
	resolve := false
	return 0, nil, linkAt(t, linux.AT_FDCWD, oldAddr, linux.AT_FDCWD, newAddr, resolve, false /* allowEmpty */)
}

// Linkat implements linux syscall linkat(2).
func Linkat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldDirFD := args[0].Int()
	oldAddr := args[1].Pointer()
	newDirFD := args[2].Int()
	newAddr := args[3].Pointer()

	// man linkat(2):
	// By default, linkat(), does not dereference oldpath if it is a
	// symbolic link (like link(2)). Since Linux 2.6.18, the flag
	// AT_SYMLINK_FOLLOW can be specified in flags to cause oldpath to be
	// dereferenced if it is a symbolic link.
	flags := args[4].Int()

	// Sanity check flags.
	if flags&^(linux.AT_SYMLINK_FOLLOW|linux.AT_EMPTY_PATH) != 0 {
		return 0, nil, syserror.EINVAL
	}

	resolve := flags&linux.AT_SYMLINK_FOLLOW == linux.AT_SYMLINK_FOLLOW
	allowEmpty := flags&linux.AT_EMPTY_PATH == linux.AT_EMPTY_PATH

	if allowEmpty && !t.HasCapabilityIn(linux.CAP_DAC_READ_SEARCH, t.UserNamespace().Root()) {
		return 0, nil, syserror.ENOENT
	}

	return 0, nil, linkAt(t, oldDirFD, oldAddr, newDirFD, newAddr, resolve, allowEmpty)
}

func readlinkAt(t *kernel.Task, dirFD int32, addr usermem.Addr, bufAddr usermem.Addr, size uint) (copied uintptr, err error) {
	path, dirPath, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return 0, err
	}
	if dirPath {
		return 0, syserror.ENOENT
	}

	err = fileOpOn(t, dirFD, path, false /* resolve */, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		// Check for Read permission.
		if err := d.Inode.CheckPermission(t, fs.PermMask{Read: true}); err != nil {
			return err
		}

		s, err := d.Inode.Readlink(t)
		if err == syserror.ENOLINK {
			return syserror.EINVAL
		}
		if err != nil {
			return err
		}

		buffer := []byte(s)
		if uint(len(buffer)) > size {
			buffer = buffer[:size]
		}

		n, err := t.CopyOutBytes(bufAddr, buffer)

		// Update frame return value.
		copied = uintptr(n)

		return err
	})
	return copied, err // Return frame value.
}

// Readlink implements linux syscall readlink(2).
func Readlink(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	bufAddr := args[1].Pointer()
	size := args[2].SizeT()

	n, err := readlinkAt(t, linux.AT_FDCWD, addr, bufAddr, size)
	return n, nil, err
}

// Readlinkat implements linux syscall readlinkat(2).
func Readlinkat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirFD := args[0].Int()
	addr := args[1].Pointer()
	bufAddr := args[2].Pointer()
	size := args[3].SizeT()

	n, err := readlinkAt(t, dirFD, addr, bufAddr, size)
	return n, nil, err
}

func unlinkAt(t *kernel.Task, dirFD int32, addr usermem.Addr) error {
	path, dirPath, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return err
	}

	return fileOpAt(t, dirFD, path, func(root *fs.Dirent, d *fs.Dirent, name string, _ uint) error {
		if !fs.IsDir(d.Inode.StableAttr) {
			return syserror.ENOTDIR
		}

		if err := fs.MayDelete(t, root, d, name); err != nil {
			return err
		}

		return d.Remove(t, root, name, dirPath)
	})
}

// Unlink implements linux syscall unlink(2).
func Unlink(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	return 0, nil, unlinkAt(t, linux.AT_FDCWD, addr)
}

// Unlinkat implements linux syscall unlinkat(2).
func Unlinkat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirFD := args[0].Int()
	addr := args[1].Pointer()
	flags := args[2].Uint()
	if flags&linux.AT_REMOVEDIR != 0 {
		return 0, nil, rmdirAt(t, dirFD, addr)
	}
	return 0, nil, unlinkAt(t, dirFD, addr)
}

// Truncate implements linux syscall truncate(2).
func Truncate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	length := args[1].Int64()

	if length < 0 {
		return 0, nil, syserror.EINVAL
	}

	path, dirPath, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return 0, nil, err
	}
	if dirPath {
		return 0, nil, syserror.EINVAL
	}

	if uint64(length) >= t.ThreadGroup().Limits().Get(limits.FileSize).Cur {
		t.SendSignal(&arch.SignalInfo{
			Signo: int32(linux.SIGXFSZ),
			Code:  arch.SignalInfoUser,
		})
		return 0, nil, syserror.EFBIG
	}

	return 0, nil, fileOpOn(t, linux.AT_FDCWD, path, true /* resolve */, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		if fs.IsDir(d.Inode.StableAttr) {
			return syserror.EISDIR
		}
		if !fs.IsFile(d.Inode.StableAttr) {
			return syserror.EINVAL
		}

		// Reject truncation if the access permissions do not allow truncation.
		// This is different from the behavior of sys_ftruncate, see below.
		if err := d.Inode.CheckPermission(t, fs.PermMask{Write: true}); err != nil {
			return err
		}

		if err := d.Inode.Truncate(t, d, length); err != nil {
			return err
		}

		// File length modified, generate notification.
		d.InotifyEvent(linux.IN_MODIFY, 0)

		return nil
	})
}

// Ftruncate implements linux syscall ftruncate(2).
func Ftruncate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	length := args[1].Int64()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// Reject truncation if the file flags do not permit this operation.
	// This is different from truncate(2) above.
	if !file.Flags().Write {
		return 0, nil, syserror.EINVAL
	}

	// Note that this is different from truncate(2) above, where a
	// directory returns EISDIR.
	if !fs.IsFile(file.Dirent.Inode.StableAttr) {
		return 0, nil, syserror.EINVAL
	}

	if length < 0 {
		return 0, nil, syserror.EINVAL
	}

	if uint64(length) >= t.ThreadGroup().Limits().Get(limits.FileSize).Cur {
		t.SendSignal(&arch.SignalInfo{
			Signo: int32(linux.SIGXFSZ),
			Code:  arch.SignalInfoUser,
		})
		return 0, nil, syserror.EFBIG
	}

	if err := file.Dirent.Inode.Truncate(t, file.Dirent, length); err != nil {
		return 0, nil, err
	}

	// File length modified, generate notification.
	file.Dirent.InotifyEvent(linux.IN_MODIFY, 0)

	return 0, nil, nil
}

// Umask implements linux syscall umask(2).
func Umask(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	mask := args[0].ModeT()
	mask = t.FSContext().SwapUmask(mask & 0777)
	return uintptr(mask), nil, nil
}

// Change ownership of a file.
//
// uid and gid may be -1, in which case they will not be changed.
func chown(t *kernel.Task, d *fs.Dirent, uid auth.UID, gid auth.GID) error {
	owner := fs.FileOwner{
		UID: auth.NoID,
		GID: auth.NoID,
	}

	uattr, err := d.Inode.UnstableAttr(t)
	if err != nil {
		return err
	}
	c := t.Credentials()
	hasCap := d.Inode.CheckCapability(t, linux.CAP_CHOWN)
	isOwner := uattr.Owner.UID == c.EffectiveKUID
	if uid.Ok() {
		kuid := c.UserNamespace.MapToKUID(uid)
		// Valid UID must be supplied if UID is to be changed.
		if !kuid.Ok() {
			return syserror.EINVAL
		}

		// "Only a privileged process (CAP_CHOWN) may change the owner
		// of a file." -chown(2)
		//
		// Linux also allows chown if you own the file and are
		// explicitly not changing its UID.
		isNoop := uattr.Owner.UID == kuid
		if !(hasCap || (isOwner && isNoop)) {
			return syserror.EPERM
		}

		owner.UID = kuid
	}
	if gid.Ok() {
		kgid := c.UserNamespace.MapToKGID(gid)
		// Valid GID must be supplied if GID is to be changed.
		if !kgid.Ok() {
			return syserror.EINVAL
		}

		// "The owner of a file may change the group of the file to any
		// group of which that owner is a member. A privileged process
		// (CAP_CHOWN) may change the group arbitrarily." -chown(2)
		isNoop := uattr.Owner.GID == kgid
		isMemberGroup := c.InGroup(kgid)
		if !(hasCap || (isOwner && (isNoop || isMemberGroup))) {
			return syserror.EPERM
		}

		owner.GID = kgid
	}

	// FIXME(b/62949101): This is racy; the inode's owner may have changed in
	// the meantime. (Linux holds i_mutex while calling
	// fs/attr.c:notify_change() => inode_operations::setattr =>
	// inode_change_ok().)
	if err := d.Inode.SetOwner(t, d, owner); err != nil {
		return err
	}

	// When the owner or group are changed by an unprivileged user,
	// chown(2) also clears the set-user-ID and set-group-ID bits, but
	// we do not support them.
	return nil
}

func chownAt(t *kernel.Task, fd int32, addr usermem.Addr, resolve, allowEmpty bool, uid auth.UID, gid auth.GID) error {
	path, _, err := copyInPath(t, addr, allowEmpty)
	if err != nil {
		return err
	}

	if path == "" {
		// Annoying. What's wrong with fchown?
		file := t.GetFile(fd)
		if file == nil {
			return syserror.EBADF
		}
		defer file.DecRef()

		return chown(t, file.Dirent, uid, gid)
	}

	return fileOpOn(t, fd, path, resolve, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		return chown(t, d, uid, gid)
	})
}

// Chown implements linux syscall chown(2).
func Chown(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	uid := auth.UID(args[1].Uint())
	gid := auth.GID(args[2].Uint())

	return 0, nil, chownAt(t, linux.AT_FDCWD, addr, true /* resolve */, false /* allowEmpty */, uid, gid)
}

// Lchown implements linux syscall lchown(2).
func Lchown(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	uid := auth.UID(args[1].Uint())
	gid := auth.GID(args[2].Uint())

	return 0, nil, chownAt(t, linux.AT_FDCWD, addr, false /* resolve */, false /* allowEmpty */, uid, gid)
}

// Fchown implements linux syscall fchown(2).
func Fchown(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	uid := auth.UID(args[1].Uint())
	gid := auth.GID(args[2].Uint())

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	return 0, nil, chown(t, file.Dirent, uid, gid)
}

// Fchownat implements Linux syscall fchownat(2).
func Fchownat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirFD := args[0].Int()
	addr := args[1].Pointer()
	uid := auth.UID(args[2].Uint())
	gid := auth.GID(args[3].Uint())
	flags := args[4].Int()

	if flags&^(linux.AT_EMPTY_PATH|linux.AT_SYMLINK_NOFOLLOW) != 0 {
		return 0, nil, syserror.EINVAL
	}

	return 0, nil, chownAt(t, dirFD, addr, flags&linux.AT_SYMLINK_NOFOLLOW == 0, flags&linux.AT_EMPTY_PATH != 0, uid, gid)
}

func chmod(t *kernel.Task, d *fs.Dirent, mode linux.FileMode) error {
	// Must own file to change mode.
	if !d.Inode.CheckOwnership(t) {
		return syserror.EPERM
	}

	p := fs.FilePermsFromMode(mode)
	if !d.Inode.SetPermissions(t, d, p) {
		return syserror.EPERM
	}

	// File attribute changed, generate notification.
	d.InotifyEvent(linux.IN_ATTRIB, 0)

	return nil
}

func chmodAt(t *kernel.Task, fd int32, addr usermem.Addr, mode linux.FileMode) error {
	path, _, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return err
	}

	return fileOpOn(t, fd, path, true /* resolve */, func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		return chmod(t, d, mode)
	})
}

// Chmod implements linux syscall chmod(2).
func Chmod(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	mode := linux.FileMode(args[1].ModeT())

	return 0, nil, chmodAt(t, linux.AT_FDCWD, addr, mode)
}

// Fchmod implements linux syscall fchmod(2).
func Fchmod(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	mode := linux.FileMode(args[1].ModeT())

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	return 0, nil, chmod(t, file.Dirent, mode)
}

// Fchmodat implements linux syscall fchmodat(2).
func Fchmodat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	mode := linux.FileMode(args[2].ModeT())

	return 0, nil, chmodAt(t, fd, addr, mode)
}

// defaultSetToSystemTimeSpec returns a TimeSpec that will set ATime and MTime
// to the system time.
func defaultSetToSystemTimeSpec() fs.TimeSpec {
	return fs.TimeSpec{
		ATimeSetSystemTime: true,
		MTimeSetSystemTime: true,
	}
}

func utimes(t *kernel.Task, dirFD int32, addr usermem.Addr, ts fs.TimeSpec, resolve bool) error {
	setTimestamp := func(root *fs.Dirent, d *fs.Dirent, _ uint) error {
		// Does the task own the file?
		if !d.Inode.CheckOwnership(t) {
			// Trying to set a specific time? Must be owner.
			if (ts.ATimeOmit || !ts.ATimeSetSystemTime) && (ts.MTimeOmit || !ts.MTimeSetSystemTime) {
				return syserror.EPERM
			}

			// Trying to set to current system time? Must have write access.
			if err := d.Inode.CheckPermission(t, fs.PermMask{Write: true}); err != nil {
				return err
			}
		}

		if err := d.Inode.SetTimestamps(t, d, ts); err != nil {
			return err
		}

		// File attribute changed, generate notification.
		d.InotifyEvent(linux.IN_ATTRIB, 0)
		return nil
	}

	// From utimes.c:
	// "If filename is NULL and dfd refers to an open file, then operate on
	// the file.  Otherwise look up filename, possibly using dfd as a
	// starting point."
	if addr == 0 && dirFD != linux.AT_FDCWD {
		if !resolve {
			// Linux returns EINVAL in this case. See utimes.c.
			return syserror.EINVAL
		}
		f := t.GetFile(dirFD)
		if f == nil {
			return syserror.EBADF
		}
		defer f.DecRef()

		root := t.FSContext().RootDirectory()
		defer root.DecRef()

		return setTimestamp(root, f.Dirent, linux.MaxSymlinkTraversals)
	}

	path, _, err := copyInPath(t, addr, false /* allowEmpty */)
	if err != nil {
		return err
	}

	return fileOpOn(t, dirFD, path, resolve, setTimestamp)
}

// Utime implements linux syscall utime(2).
func Utime(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	filenameAddr := args[0].Pointer()
	timesAddr := args[1].Pointer()

	// No timesAddr argument will be interpreted as current system time.
	ts := defaultSetToSystemTimeSpec()
	if timesAddr != 0 {
		var times linux.Utime
		if _, err := t.CopyIn(timesAddr, &times); err != nil {
			return 0, nil, err
		}
		ts = fs.TimeSpec{
			ATime: ktime.FromSeconds(times.Actime),
			MTime: ktime.FromSeconds(times.Modtime),
		}
	}
	return 0, nil, utimes(t, linux.AT_FDCWD, filenameAddr, ts, true)
}

// Utimes implements linux syscall utimes(2).
func Utimes(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	filenameAddr := args[0].Pointer()
	timesAddr := args[1].Pointer()

	// No timesAddr argument will be interpreted as current system time.
	ts := defaultSetToSystemTimeSpec()
	if timesAddr != 0 {
		var times [2]linux.Timeval
		if _, err := t.CopyIn(timesAddr, &times); err != nil {
			return 0, nil, err
		}
		ts = fs.TimeSpec{
			ATime: ktime.FromTimeval(times[0]),
			MTime: ktime.FromTimeval(times[1]),
		}
	}
	return 0, nil, utimes(t, linux.AT_FDCWD, filenameAddr, ts, true)
}

// timespecIsValid checks that the timespec is valid for use in utimensat.
func timespecIsValid(ts linux.Timespec) bool {
	// Nsec must be UTIME_OMIT, UTIME_NOW, or less than 10^9.
	return ts.Nsec == linux.UTIME_OMIT || ts.Nsec == linux.UTIME_NOW || ts.Nsec < 1e9
}

// Utimensat implements linux syscall utimensat(2).
func Utimensat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirFD := args[0].Int()
	pathnameAddr := args[1].Pointer()
	timesAddr := args[2].Pointer()
	flags := args[3].Int()

	// No timesAddr argument will be interpreted as current system time.
	ts := defaultSetToSystemTimeSpec()
	if timesAddr != 0 {
		var times [2]linux.Timespec
		if _, err := t.CopyIn(timesAddr, &times); err != nil {
			return 0, nil, err
		}
		if !timespecIsValid(times[0]) || !timespecIsValid(times[1]) {
			return 0, nil, syserror.EINVAL
		}

		// If both are UTIME_OMIT, this is a noop.
		if times[0].Nsec == linux.UTIME_OMIT && times[1].Nsec == linux.UTIME_OMIT {
			return 0, nil, nil
		}

		ts = fs.TimeSpec{
			ATime:              ktime.FromTimespec(times[0]),
			ATimeOmit:          times[0].Nsec == linux.UTIME_OMIT,
			ATimeSetSystemTime: times[0].Nsec == linux.UTIME_NOW,
			MTime:              ktime.FromTimespec(times[1]),
			MTimeOmit:          times[1].Nsec == linux.UTIME_OMIT,
			MTimeSetSystemTime: times[0].Nsec == linux.UTIME_NOW,
		}
	}
	return 0, nil, utimes(t, dirFD, pathnameAddr, ts, flags&linux.AT_SYMLINK_NOFOLLOW == 0)
}

// Futimesat implements linux syscall futimesat(2).
func Futimesat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	dirFD := args[0].Int()
	pathnameAddr := args[1].Pointer()
	timesAddr := args[2].Pointer()

	// No timesAddr argument will be interpreted as current system time.
	ts := defaultSetToSystemTimeSpec()
	if timesAddr != 0 {
		var times [2]linux.Timeval
		if _, err := t.CopyIn(timesAddr, &times); err != nil {
			return 0, nil, err
		}
		if times[0].Usec >= 1e6 || times[0].Usec < 0 ||
			times[1].Usec >= 1e6 || times[1].Usec < 0 {
			return 0, nil, syserror.EINVAL
		}

		ts = fs.TimeSpec{
			ATime: ktime.FromTimeval(times[0]),
			MTime: ktime.FromTimeval(times[1]),
		}
	}
	return 0, nil, utimes(t, dirFD, pathnameAddr, ts, true)
}

func renameAt(t *kernel.Task, oldDirFD int32, oldAddr usermem.Addr, newDirFD int32, newAddr usermem.Addr) error {
	newPath, _, err := copyInPath(t, newAddr, false /* allowEmpty */)
	if err != nil {
		return err
	}
	oldPath, _, err := copyInPath(t, oldAddr, false /* allowEmpty */)
	if err != nil {
		return err
	}

	return fileOpAt(t, oldDirFD, oldPath, func(root *fs.Dirent, oldParent *fs.Dirent, oldName string, _ uint) error {
		if !fs.IsDir(oldParent.Inode.StableAttr) {
			return syserror.ENOTDIR
		}

		// Rename rejects paths that end in ".", "..", or empty (i.e.
		// the root) with EBUSY.
		switch oldName {
		case "", ".", "..":
			return syserror.EBUSY
		}

		return fileOpAt(t, newDirFD, newPath, func(root *fs.Dirent, newParent *fs.Dirent, newName string, _ uint) error {
			if !fs.IsDir(newParent.Inode.StableAttr) {
				return syserror.ENOTDIR
			}

			// Rename rejects paths that end in ".", "..", or empty
			// (i.e.  the root) with EBUSY.
			switch newName {
			case "", ".", "..":
				return syserror.EBUSY
			}

			return fs.Rename(t, root, oldParent, oldName, newParent, newName)
		})
	})
}

// Rename implements linux syscall rename(2).
func Rename(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldPathAddr := args[0].Pointer()
	newPathAddr := args[1].Pointer()
	return 0, nil, renameAt(t, linux.AT_FDCWD, oldPathAddr, linux.AT_FDCWD, newPathAddr)
}

// Renameat implements linux syscall renameat(2).
func Renameat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	oldDirFD := args[0].Int()
	oldPathAddr := args[1].Pointer()
	newDirFD := args[2].Int()
	newPathAddr := args[3].Pointer()
	return 0, nil, renameAt(t, oldDirFD, oldPathAddr, newDirFD, newPathAddr)
}

// Fallocate implements linux system call fallocate(2).
func Fallocate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	mode := args[1].Int64()
	offset := args[2].Int64()
	length := args[3].Int64()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	if offset < 0 || length <= 0 {
		return 0, nil, syserror.EINVAL
	}
	if mode != 0 {
		t.Kernel().EmitUnimplementedEvent(t)
		return 0, nil, syserror.ENOTSUP
	}
	if !file.Flags().Write {
		return 0, nil, syserror.EBADF
	}
	if fs.IsPipe(file.Dirent.Inode.StableAttr) {
		return 0, nil, syserror.ESPIPE
	}
	if fs.IsDir(file.Dirent.Inode.StableAttr) {
		return 0, nil, syserror.EISDIR
	}
	if !fs.IsRegular(file.Dirent.Inode.StableAttr) {
		return 0, nil, syserror.ENODEV
	}
	size := offset + length
	if size < 0 {
		return 0, nil, syserror.EFBIG
	}
	if uint64(size) >= t.ThreadGroup().Limits().Get(limits.FileSize).Cur {
		t.SendSignal(&arch.SignalInfo{
			Signo: int32(linux.SIGXFSZ),
			Code:  arch.SignalInfoUser,
		})
		return 0, nil, syserror.EFBIG
	}

	if err := file.Dirent.Inode.Allocate(t, file.Dirent, offset, length); err != nil {
		return 0, nil, err
	}

	// File length modified, generate notification.
	file.Dirent.InotifyEvent(linux.IN_MODIFY, 0)

	return 0, nil, nil
}

// Flock implements linux syscall flock(2).
func Flock(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	operation := args[1].Int()

	file := t.GetFile(fd)
	if file == nil {
		// flock(2): EBADF fd is not an open file descriptor.
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	nonblocking := operation&linux.LOCK_NB != 0
	operation &^= linux.LOCK_NB

	// flock(2):
	// Locks created by flock() are associated with an open file table entry. This means that
	// duplicate file descriptors (created by, for example, fork(2) or dup(2)) refer to the
	// same lock, and this lock may be modified or released using any of these descriptors. Furthermore,
	// the lock is released either by an explicit LOCK_UN operation on any of these duplicate
	// descriptors, or when all such descriptors have been closed.
	//
	// If a process uses open(2) (or similar) to obtain more than one descriptor for the same file,
	// these descriptors are treated independently by flock(). An attempt to lock the file using
	// one of these file descriptors may be denied by a lock that the calling process has already placed via
	// another descriptor.
	//
	// We use the File UniqueID as the lock UniqueID because it needs to reference the same lock across dup(2)
	// and fork(2).
	lockUniqueID := lock.UniqueID(file.UniqueID)

	// A BSD style lock spans the entire file.
	rng := lock.LockRange{
		Start: 0,
		End:   lock.LockEOF,
	}

	switch operation {
	case linux.LOCK_EX:
		if nonblocking {
			// Since we're nonblocking we pass a nil lock.Blocker implementation.
			if !file.Dirent.Inode.LockCtx.BSD.LockRegion(lockUniqueID, lock.WriteLock, rng, nil) {
				return 0, nil, syserror.EWOULDBLOCK
			}
		} else {
			// Because we're blocking we will pass the task to satisfy the lock.Blocker interface.
			if !file.Dirent.Inode.LockCtx.BSD.LockRegion(lockUniqueID, lock.WriteLock, rng, t) {
				return 0, nil, syserror.EINTR
			}
		}
	case linux.LOCK_SH:
		if nonblocking {
			// Since we're nonblocking we pass a nil lock.Blocker implementation.
			if !file.Dirent.Inode.LockCtx.BSD.LockRegion(lockUniqueID, lock.ReadLock, rng, nil) {
				return 0, nil, syserror.EWOULDBLOCK
			}
		} else {
			// Because we're blocking we will pass the task to satisfy the lock.Blocker interface.
			if !file.Dirent.Inode.LockCtx.BSD.LockRegion(lockUniqueID, lock.ReadLock, rng, t) {
				return 0, nil, syserror.EINTR
			}
		}
	case linux.LOCK_UN:
		file.Dirent.Inode.LockCtx.BSD.UnlockRegion(lockUniqueID, rng)
	default:
		// flock(2): EINVAL operation is invalid.
		return 0, nil, syserror.EINVAL
	}

	return 0, nil, nil
}

const (
	memfdPrefix     = "/memfd:"
	memfdAllFlags   = uint32(linux.MFD_CLOEXEC | linux.MFD_ALLOW_SEALING)
	memfdMaxNameLen = linux.NAME_MAX - len(memfdPrefix) + 1
)

// MemfdCreate implements the linux syscall memfd_create(2).
func MemfdCreate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	flags := args[1].Uint()

	if flags&^memfdAllFlags != 0 {
		// Unknown bits in flags.
		return 0, nil, syserror.EINVAL
	}

	allowSeals := flags&linux.MFD_ALLOW_SEALING != 0
	cloExec := flags&linux.MFD_CLOEXEC != 0

	name, err := t.CopyInString(addr, syscall.PathMax-len(memfdPrefix))
	if err != nil {
		return 0, nil, err
	}
	if len(name) > memfdMaxNameLen {
		return 0, nil, syserror.EINVAL
	}
	name = memfdPrefix + name

	inode := tmpfs.NewMemfdInode(t, allowSeals)
	dirent := fs.NewDirent(t, inode, name)
	// Per Linux, mm/shmem.c:__shmem_file_setup(), memfd files are set up with
	// FMODE_READ | FMODE_WRITE.
	file, err := inode.GetFile(t, dirent, fs.FileFlags{Read: true, Write: true})
	if err != nil {
		return 0, nil, err
	}

	defer dirent.DecRef()
	defer file.DecRef()

	newFD, err := t.NewFDFrom(0, file, kernel.FDFlags{
		CloseOnExec: cloExec,
	})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(newFD), nil, nil
}
