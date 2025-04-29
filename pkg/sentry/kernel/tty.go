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

package kernel

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// TTYOperations handle tty operations. It is analogous to (a small subset) of
// Linux's struct tty_operations and exists to avoid a circular dependency.
type TTYOperations interface {
	// OpenTTY opens the tty.
	OpenTTY(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error)
}

// TTY defines the relationship between a thread group and its controlling
// terminal.
//
// +stateify savable
type TTY struct {
	// TTYOperations holds operations on the tty. It is immutable.
	TTYOperations

	// index is the terminal index. It is immutable.
	index uint32

	mu sync.Mutex `state:"nosave"`

	// tg is protected by mu.
	tg *ThreadGroup
}

// NewTTY constructs a new TTY.
func NewTTY(index uint32, ttyOps TTYOperations) *TTY {
	return &TTY{
		TTYOperations: ttyOps,
		index:         index,
	}
}

// Index returns the tty's index.
func (tty *TTY) Index() uint32 {
	return tty.index
}

// ThreadGroup returns the ThreadGroup this TTY is associated with.
func (tty *TTY) ThreadGroup() *ThreadGroup {
	tty.mu.Lock()
	defer tty.mu.Unlock()
	return tty.tg
}

// SignalForegroundProcessGroup sends the signal to the foreground process
// group of the TTY.
func (tty *TTY) SignalForegroundProcessGroup(info *linux.SignalInfo) {
	tty.mu.Lock()
	defer tty.mu.Unlock()

	tg := tty.tg
	if tg == nil {
		// This TTY is not a controlling thread group. This can happen
		// if it was opened with O_NOCTTY, or if it failed the checks
		// on session and leaders in SetControllingTTY(). There is
		// nothing to signal.
		return
	}

	tg.pidns.owner.mu.Lock()
	fg := tg.processGroup.session.foreground
	tg.pidns.owner.mu.Unlock()

	if fg == nil {
		// Nothing to signal.
		return
	}

	if err := fg.SendSignal(info); err != nil {
		log.Warningf("failed to signal foreground process group (pgid=%d): %v", fg.id, err)
	}
}

// CheckChange checks that the calling tash is allowed to read, write, or
// change the state of the TTY.
//
// This corresponds to Linux drivers/tty/tty_io.c:tty_check_change().
func (tty *TTY) CheckChange(ctx context.Context, sig linux.Signal) error {
	task := TaskFromContext(ctx)
	if task == nil {
		// No task? Linux does not have an analog for this case, but
		// tty_check_change only blocks specific cases and is
		// surprisingly permissive. Allowing the change seems
		// appropriate.
		return nil
	}

	tg := task.ThreadGroup()
	pg := tg.ProcessGroup()
	ttyTG := tty.ThreadGroup()

	// If the session for the task is different than the session for the
	// controlling TTY, then the change is allowed. Seems like a bad idea,
	// but that's exactly what linux does.
	if ttyTG == nil || tg.Session() != ttyTG.Session() {
		return nil
	}

	// If we are the foreground process group, then the change is allowed.
	if fgpg, _ := ttyTG.ForegroundProcessGroup(tty); pg == fgpg {
		return nil
	}

	// We are not the foreground process group.

	// Is the provided signal blocked or ignored?
	if (task.SignalMask()&linux.SignalSetOf(sig) != 0) || tg.SignalHandlers().IsIgnored(sig) {
		// If the signal is SIGTTIN, then we are attempting to read
		// from the TTY. Don't send the signal and return EIO.
		if sig == linux.SIGTTIN {
			return linuxerr.EIO
		}

		// Otherwise, we are writing or changing terminal state. This is allowed.
		return nil
	}

	// If the process group is an orphan, return EIO.
	if pg.IsOrphan() {
		return linuxerr.EIO
	}

	// Otherwise, send the signal to the process group and return ERESTARTSYS.
	//
	// Note that Linux also unconditionally sets TIF_SIGPENDING on current,
	// but this isn't necessary in gVisor because the rationale given in
	// https://github.com/torvalds/linux/commit/040b6362d58f "tty: fix
	// leakage of -ERESTARTSYS to userland" doesn't apply: the sentry will
	// handle -ERESTARTSYS in kernel.runApp.execute() even if the
	// kernel.Task isn't interrupted.
	//
	// Linux ignores the result of kill_pgrp().
	_ = pg.SendSignal(SignalInfoPriv(sig))
	return linuxerr.ERESTARTSYS
}
