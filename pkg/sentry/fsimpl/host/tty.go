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
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/unimpl"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// TTYFileDescription implements vfs.FileDescriptionImpl for a host file
// descriptor that wraps a TTY FD.
//
// +stateify savable
type TTYFileDescription struct {
	fileDescription

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// session is the session attached to this TTYFileDescription.
	session *kernel.Session

	// fgProcessGroup is the foreground process group that is currently
	// connected to this TTY.
	fgProcessGroup *kernel.ProcessGroup

	// termios contains the terminal attributes for this TTY.
	termios linux.KernelTermios
}

// InitForegroundProcessGroup sets the foreground process group and session for
// the TTY. This should only be called once, after the foreground process group
// has been created, but before it has started running.
func (t *TTYFileDescription) InitForegroundProcessGroup(pg *kernel.ProcessGroup) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fgProcessGroup != nil {
		panic("foreground process group is already set")
	}
	t.fgProcessGroup = pg
	t.session = pg.Session()
}

// ForegroundProcessGroup returns the foreground process for the TTY.
func (t *TTYFileDescription) ForegroundProcessGroup() *kernel.ProcessGroup {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fgProcessGroup
}

// Release implements fs.FileOperations.Release.
func (t *TTYFileDescription) Release(ctx context.Context) {
	t.mu.Lock()
	t.fgProcessGroup = nil
	t.mu.Unlock()

	t.fileDescription.Release(ctx)
}

// PRead implements vfs.FileDescriptionImpl.PRead.
//
// Reading from a TTY is only allowed for foreground process groups. Background
// process groups will either get EIO or a SIGTTIN.
func (t *TTYFileDescription) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Are we allowed to do the read?
	// drivers/tty/n_tty.c:n_tty_read()=>job_control()=>tty_check_change().
	if err := t.checkChange(ctx, linux.SIGTTIN); err != nil {
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
	t.mu.Lock()
	defer t.mu.Unlock()

	// Are we allowed to do the read?
	// drivers/tty/n_tty.c:n_tty_read()=>job_control()=>tty_check_change().
	if err := t.checkChange(ctx, linux.SIGTTIN); err != nil {
		return 0, err
	}

	// Do the read.
	return t.fileDescription.Read(ctx, dst, opts)
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (t *TTYFileDescription) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check whether TOSTOP is enabled. This corresponds to the check in
	// drivers/tty/n_tty.c:n_tty_write().
	if t.termios.LEnabled(linux.TOSTOP) {
		if err := t.checkChange(ctx, linux.SIGTTOU); err != nil {
			return 0, err
		}
	}
	return t.fileDescription.PWrite(ctx, src, offset, opts)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (t *TTYFileDescription) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check whether TOSTOP is enabled. This corresponds to the check in
	// drivers/tty/n_tty.c:n_tty_write().
	if t.termios.LEnabled(linux.TOSTOP) {
		if err := t.checkChange(ctx, linux.SIGTTOU); err != nil {
			return 0, err
		}
	}
	return t.fileDescription.Write(ctx, src, opts)
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (t *TTYFileDescription) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		return 0, syserror.ENOTTY
	}

	// Ignore arg[0]. This is the real FD:
	fd := t.inode.hostFD
	ioctl := args[1].Uint64()
	switch ioctl {
	case linux.TCGETS:
		termios, err := ioctlGetTermios(fd)
		if err != nil {
			return 0, err
		}
		_, err = termios.CopyOut(task, args[2].Pointer())
		return 0, err

	case linux.TCSETS, linux.TCSETSW, linux.TCSETSF:
		t.mu.Lock()
		defer t.mu.Unlock()

		if err := t.checkChange(ctx, linux.SIGTTOU); err != nil {
			return 0, err
		}

		var termios linux.Termios
		if _, err := termios.CopyIn(task, args[2].Pointer()); err != nil {
			return 0, err
		}
		err := ioctlSetTermios(fd, ioctl, &termios)
		if err == nil {
			t.termios.FromTermios(termios)
		}
		return 0, err

	case linux.TIOCGPGRP:
		// Args: pid_t *argp
		// When successful, equivalent to *argp = tcgetpgrp(fd).
		// Get the process group ID of the foreground process group on this
		// terminal.

		pidns := kernel.PIDNamespaceFromContext(ctx)
		if pidns == nil {
			return 0, syserror.ENOTTY
		}

		t.mu.Lock()
		defer t.mu.Unlock()

		// Map the ProcessGroup into a ProcessGroupID in the task's PID namespace.
		pgID := primitive.Int32(pidns.IDOfProcessGroup(t.fgProcessGroup))
		_, err := pgID.CopyOut(task, args[2].Pointer())
		return 0, err

	case linux.TIOCSPGRP:
		// Args: const pid_t *argp
		// Equivalent to tcsetpgrp(fd, *argp).
		// Set the foreground process group ID of this terminal.

		t.mu.Lock()
		defer t.mu.Unlock()

		// Check that we are allowed to set the process group.
		if err := t.checkChange(ctx, linux.SIGTTOU); err != nil {
			// drivers/tty/tty_io.c:tiocspgrp() converts -EIO from tty_check_change()
			// to -ENOTTY.
			if linuxerr.Equals(linuxerr.EIO, err) {
				return 0, syserror.ENOTTY
			}
			return 0, err
		}

		// Check that calling task's process group is in the TTY session.
		if task.ThreadGroup().Session() != t.session {
			return 0, syserror.ENOTTY
		}

		var pgIDP primitive.Int32
		if _, err := pgIDP.CopyIn(task, args[2].Pointer()); err != nil {
			return 0, err
		}
		pgID := kernel.ProcessGroupID(pgIDP)

		// pgID must be non-negative.
		if pgID < 0 {
			return 0, linuxerr.EINVAL
		}

		// Process group with pgID must exist in this PID namespace.
		pidns := task.PIDNamespace()
		pg := pidns.ProcessGroupWithID(pgID)
		if pg == nil {
			return 0, syserror.ESRCH
		}

		// Check that new process group is in the TTY session.
		if pg.Session() != t.session {
			return 0, linuxerr.EPERM
		}

		t.fgProcessGroup = pg
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

		unimpl.EmitUnimplementedEvent(ctx)
		fallthrough
	default:
		return 0, syserror.ENOTTY
	}
}

// checkChange checks that the process group is allowed to read, write, or
// change the state of the TTY.
//
// This corresponds to Linux drivers/tty/tty_io.c:tty_check_change(). The logic
// is a bit convoluted, but documented inline.
//
// Preconditions: t.mu must be held.
func (t *TTYFileDescription) checkChange(ctx context.Context, sig linux.Signal) error {
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		// No task? Linux does not have an analog for this case, but
		// tty_check_change only blocks specific cases and is
		// surprisingly permissive. Allowing the change seems
		// appropriate.
		return nil
	}

	tg := task.ThreadGroup()
	pg := tg.ProcessGroup()

	// If the session for the task is different than the session for the
	// controlling TTY, then the change is allowed. Seems like a bad idea,
	// but that's exactly what linux does.
	if tg.Session() != t.fgProcessGroup.Session() {
		return nil
	}

	// If we are the foreground process group, then the change is allowed.
	if pg == t.fgProcessGroup {
		return nil
	}

	// We are not the foreground process group.

	// Is the provided signal blocked or ignored?
	if (task.SignalMask()&linux.SignalSetOf(sig) != 0) || tg.SignalHandlers().IsIgnored(sig) {
		// If the signal is SIGTTIN, then we are attempting to read
		// from the TTY. Don't send the signal and return EIO.
		if sig == linux.SIGTTIN {
			return syserror.EIO
		}

		// Otherwise, we are writing or changing terminal state. This is allowed.
		return nil
	}

	// If the process group is an orphan, return EIO.
	if pg.IsOrphan() {
		return syserror.EIO
	}

	// Otherwise, send the signal to the process group and return ERESTARTSYS.
	//
	// Note that Linux also unconditionally sets TIF_SIGPENDING on current,
	// but this isn't necessary in gVisor because the rationale given in
	// 040b6362d58f "tty: fix leakage of -ERESTARTSYS to userland" doesn't
	// apply: the sentry will handle -ERESTARTSYS in
	// kernel.runApp.execute() even if the kernel.Task isn't interrupted.
	//
	// Linux ignores the result of kill_pgrp().
	_ = pg.SendSignal(kernel.SignalInfoPriv(sig))
	return syserror.ERESTARTSYS
}
