// Copyright 2018 Google LLC
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

package host

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/unimpl"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// TTYFileOperations implements fs.FileOperations for a host file descriptor
// that wraps a TTY FD.
//
// +stateify savable
type TTYFileOperations struct {
	fileOperations

	// mu protects the fields below.
	mu sync.Mutex

	// FGProcessGroup is the foreground process group this TTY.  Will be
	// nil if not set or if this file has been released.
	fgProcessGroup *kernel.ProcessGroup
}

// newTTYFile returns a new fs.File that wraps a TTY FD.
func newTTYFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags, iops *inodeOperations) *fs.File {
	return fs.NewFile(ctx, dirent, flags, &TTYFileOperations{
		fileOperations: fileOperations{iops: iops},
	})
}

// ForegroundProcessGroup returns the foreground process for the TTY. This will
// be nil if the foreground process has not been set or if the file has been
// released.
func (t *TTYFileOperations) ForegroundProcessGroup() *kernel.ProcessGroup {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fgProcessGroup
}

// Release implements fs.FileOperations.Release.
func (t *TTYFileOperations) Release() {
	t.mu.Lock()
	t.fgProcessGroup = nil
	t.mu.Unlock()

	t.fileOperations.Release()
}

// Ioctl implements fs.FileOperations.Ioctl.
func (t *TTYFileOperations) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	// Ignore arg[0].  This is the real FD:
	fd := t.fileOperations.iops.fileState.FD()
	ioctl := args[1].Uint64()
	switch ioctl {
	case linux.TCGETS:
		termios, err := ioctlGetTermios(fd)
		if err != nil {
			return 0, err
		}
		_, err = usermem.CopyObjectOut(ctx, io, args[2].Pointer(), termios, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err

	case linux.TCSETS, linux.TCSETSW, linux.TCSETSF:
		var termios linux.Termios
		if _, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &termios, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, err
		}
		err := ioctlSetTermios(fd, ioctl, &termios)
		return 0, err

	case linux.TIOCGPGRP:
		// Args: pid_t *argp
		// When successful, equivalent to *argp = tcgetpgrp(fd).
		// Get the process group ID of the foreground process group on
		// this terminal.

		t.mu.Lock()
		defer t.mu.Unlock()

		if t.fgProcessGroup == nil {
			// No process group has been set yet. Let's just lie
			// and tell it the process group from the current task.
			// The app is probably going to set it to something
			// else very soon anyways.
			t.fgProcessGroup = kernel.TaskFromContext(ctx).ThreadGroup().ProcessGroup()
		}

		// Map the ProcessGroup into a ProcessGroupID in the task's PID
		// namespace.
		pgID := kernel.TaskFromContext(ctx).ThreadGroup().PIDNamespace().IDOfProcessGroup(t.fgProcessGroup)
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), &pgID, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err

	case linux.TIOCSPGRP:
		// Args: const pid_t *argp
		// Equivalent to tcsetpgrp(fd, *argp).
		// Set the foreground process group ID of this terminal.

		var pgID kernel.ProcessGroupID
		if _, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &pgID, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, err
		}

		// pgID must be non-negative.
		if pgID < 0 {
			return 0, syserror.EINVAL
		}

		// Process group with pgID must exist in this PID namespace.
		task := kernel.TaskFromContext(ctx)
		pidns := task.PIDNamespace()
		pg := pidns.ProcessGroupWithID(pgID)
		if pg == nil {
			return 0, syserror.ESRCH
		}

		// Process group must be in same session as calling task's
		// process group.
		curSession := task.ThreadGroup().ProcessGroup().Session()
		curSessionID := pidns.IDOfSession(curSession)
		if pidns.IDOfSession(pg.Session()) != curSessionID {
			return 0, syserror.EPERM
		}

		t.mu.Lock()
		t.fgProcessGroup = pg
		t.mu.Unlock()
		return 0, nil

	case linux.TIOCGWINSZ:
		// Args: struct winsize *argp
		// Get window size.
		winsize, err := ioctlGetWinsize(fd)
		if err != nil {
			return 0, err
		}
		_, err = usermem.CopyObjectOut(ctx, io, args[2].Pointer(), winsize, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err

	case linux.TIOCSWINSZ:
		// Args: const struct winsize *argp
		// Set window size.
		var winsize linux.Winsize
		if _, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &winsize, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, err
		}
		err := ioctlSetWinsize(fd, &winsize)
		return 0, err

	// Unimplemented commands.
	case linux.TIOCSETD,
		linux.TIOCSBRK,
		linux.TIOCCBRK,
		linux.TCSBRK,
		linux.TCSBRKP,
		linux.TIOCSTI,
		linux.TIOCCONS,
		linux.FIONBIO,
		linux.TIOCEXCL,
		linux.TIOCNXCL,
		linux.TIOCGEXCL,
		linux.TIOCNOTTY,
		linux.TIOCSCTTY,
		linux.TIOCGSID,
		linux.TIOCGETD,
		linux.TIOCVHANGUP,
		linux.TIOCGDEV,
		linux.TIOCMGET,
		linux.TIOCMSET,
		linux.TIOCMBIC,
		linux.TIOCMBIS,
		linux.TIOCGICOUNT,
		linux.TCFLSH,
		linux.TIOCSSERIAL,
		linux.TIOCGPTPEER:

		unimpl.EmitUnimplementedEvent(ctx)
		fallthrough
	default:
		return 0, syserror.ENOTTY
	}
}
