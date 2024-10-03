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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// TTYOperations handle tty operations. It is analogous to (a small subset) of
// Linux's struct tty_operations and exists to avoid a circular dependency.
type TTYOperations interface {
	// Open opens the tty.
	Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error)
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
