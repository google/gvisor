// Copyright 2020 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/unimpl"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// TTYFileDescription implements vfs.FileDescriptionImpl for a host file
// descriptor that wraps a TTY FD.
//
// It implements kernel.TTYOperations.
//
// +stateify savable
type TTYFileDescription struct {
	fileDescription
}

// TTY returns the kernel.TTY.
func (t *TTYFileDescription) TTY() *kernel.TTY {
	return t.inode.tty
}

// ThreadGroup returns the kernel.ThreadGroup associated with this tty.
func (t *TTYFileDescription) ThreadGroup() *kernel.ThreadGroup {
	return t.inode.tty.ThreadGroup()
}

// PRead implements vfs.FileDescriptionImpl.PRead.
//
// Reading from a TTY is only allowed for foreground process groups. Background
// process groups will either get EIO or a SIGTTIN.
func (t *TTYFileDescription) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	// Are we allowed to do the read?
	// drivers/tty/n_tty.c:n_tty_read()=>job_control()=>tty_check_change().
	if err := t.TTY().CheckChange(ctx, linux.SIGTTIN); err != nil {
		return 0, err
	}

	// Do the read.
	return t.fileDescription.PRead(ctx, dst, offset, opts)
}

// Read implements vfs.FileDescriptionImpl.Read.
//
// Reading from a TTY is only allowed for foreground process groups. Background
// process groups will either get EIO or a SIGTTIN.
func (t *TTYFileDescription) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	// Are we allowed to do the read?
	// drivers/tty/n_tty.c:n_tty_read()=>job_control()=>tty_check_change().
	if err := t.TTY().CheckChange(ctx, linux.SIGTTIN); err != nil {
		return 0, err
	}

	// Do the read.
	return t.fileDescription.Read(ctx, dst, opts)
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (t *TTYFileDescription) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	t.inode.termiosMu.Lock()
	defer t.inode.termiosMu.Unlock()
	// Check whether TOSTOP is enabled. This corresponds to the check in
	// drivers/tty/n_tty.c:n_tty_write().
	if t.inode.termios.LEnabled(linux.TOSTOP) {
		if err := t.TTY().CheckChange(ctx, linux.SIGTTOU); err != nil {
			return 0, err
		}
	}
	return t.fileDescription.PWrite(ctx, src, offset, opts)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (t *TTYFileDescription) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	t.inode.termiosMu.Lock()
	defer t.inode.termiosMu.Unlock()
	// Check whether TOSTOP is enabled. This corresponds to the check in
	// drivers/tty/n_tty.c:n_tty_write().
	if t.inode.termios.LEnabled(linux.TOSTOP) {
		if err := t.TTY().CheckChange(ctx, linux.SIGTTOU); err != nil {
			return 0, err
		}
	}
	return t.fileDescription.Write(ctx, src, opts)
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (t *TTYFileDescription) Ioctl(ctx context.Context, io usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		return 0, linuxerr.ENOTTY
	}

	// Ignore arg[0]. This is the real FD:
	fd := t.inode.hostFD
	ioctl := args[1].Uint64()
	switch ioctl {
	case linux.FIONREAD:
		v, err := ioctlFionread(fd)
		if err != nil {
			return 0, err
		}

		var buf [4]byte
		hostarch.ByteOrder.PutUint32(buf[:], v)
		_, err = io.CopyOut(ctx, args[2].Pointer(), buf[:], usermem.IOOpts{})
		return 0, err

	case linux.TCGETS:
		termios, err := ioctlGetTermios(fd)
		if err != nil {
			return 0, err
		}
		_, err = termios.CopyOut(task, args[2].Pointer())
		return 0, err

	case linux.TCSETS, linux.TCSETSW, linux.TCSETSF:
		t.inode.termiosMu.Lock()
		defer t.inode.termiosMu.Unlock()

		if err := t.inode.tty.CheckChange(ctx, linux.SIGTTOU); err != nil {
			return 0, err
		}

		var termios linux.Termios
		if _, err := termios.CopyIn(task, args[2].Pointer()); err != nil {
			return 0, err
		}
		err := ioctlSetTermios(fd, ioctl, &termios)
		if err == nil {
			t.inode.termios.FromTermios(termios)
		}
		return 0, err

	case linux.TIOCGPGRP:
		// Args: pid_t *argp
		// When successful, equivalent to *argp = tcgetpgrp(fd).
		// Get the process group ID of the foreground process group on this
		// terminal.

		pidns := kernel.PIDNamespaceFromContext(ctx)
		if pidns == nil {
			return 0, linuxerr.ENOTTY
		}

		tg := t.ThreadGroup()
		if tg == nil {
			return 0, linuxerr.ENOTTY
		}
		fgpg, err := tg.ForegroundProcessGroup(t.TTY())
		if err != nil {
			return 0, err
		}

		// Map the ProcessGroup into a ProcessGroupID in the task's PID namespace.
		pgID := primitive.Int32(pidns.IDOfProcessGroup(fgpg))
		_, err = pgID.CopyOut(task, args[2].Pointer())
		return 0, err

	case linux.TIOCSPGRP:
		// Args: const pid_t *argp
		// Equivalent to tcsetpgrp(fd, *argp).
		// Set the foreground process group ID of this terminal.

		var pgIDP primitive.Int32
		if _, err := pgIDP.CopyIn(task, args[2].Pointer()); err != nil {
			return 0, err
		}
		pgID := kernel.ProcessGroupID(pgIDP)

		tg := t.ThreadGroup()
		if tg == nil {
			return 0, linuxerr.ENOTTY
		}
		if err := tg.SetForegroundProcessGroupID(ctx, t.TTY(), pgID); err != nil {
			return 0, err
		}

		return 0, nil

	case linux.TIOCGWINSZ:
		// Args: struct winsize *argp
		// Get window size.
		winsize, err := ioctlGetWinsize(fd)
		if err != nil {
			return 0, err
		}
		_, err = winsize.CopyOut(task, args[2].Pointer())
		return 0, err

	case linux.TIOCSWINSZ:
		// Args: const struct winsize *argp
		// Set window size.

		// Unlike setting the termios, any process group (even background ones) can
		// set the winsize.

		var winsize linux.Winsize
		if _, err := winsize.CopyIn(task, args[2].Pointer()); err != nil {
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

		unimpl.EmitUnimplementedEvent(ctx, sysno)
		fallthrough
	default:
		return 0, linuxerr.ENOTTY
	}
}
