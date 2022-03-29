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

package devpts

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// Terminal is a pseudoterminal.
//
// +stateify savable
type Terminal struct {
	// n is the terminal index. It is immutable.
	n uint32

	// ld is the line discipline of the terminal. It is immutable.
	ld *lineDiscipline

	// kTTY contains the controlling process of this terminal. This field
	// is immutable.
	kTTY *kernel.TTY
}

func newTerminal(n uint32) *Terminal {
	termios := linux.DefaultReplicaTermios
	t := Terminal{
		n:    n,
		ld:   newLineDiscipline(termios),
		kTTY: &kernel.TTY{Index: n},
	}
	return &t
}

// setControllingTTY makes tm the controlling terminal of the calling thread
// group.
func (tm *Terminal) setControllingTTY(ctx context.Context, steal bool, isReadable bool) error {
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		panic("setControllingTTY must be called from a task context")
	}

	return task.ThreadGroup().SetControllingTTY(tm.kTTY, steal, isReadable)
}

// releaseControllingTTY removes tm as the controlling terminal of the calling
// thread group.
func (tm *Terminal) releaseControllingTTY(ctx context.Context) error {
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		panic("releaseControllingTTY must be called from a task context")
	}

	return task.ThreadGroup().ReleaseControllingTTY(tm.kTTY)
}

// foregroundProcessGroup gets the process group ID of tm's foreground process.
func (tm *Terminal) foregroundProcessGroup(ctx context.Context, args arch.SyscallArguments) (uintptr, error) {
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		panic("foregroundProcessGroup must be called from a task context")
	}

	ret, err := task.ThreadGroup().ForegroundProcessGroup(tm.kTTY)
	if err != nil {
		return 0, err
	}

	// Write it out to *arg.
	retP := primitive.Int32(ret)
	_, err = retP.CopyOut(task, args[2].Pointer())
	return 0, err
}

// foregroundProcessGroup sets tm's foreground process.
func (tm *Terminal) setForegroundProcessGroup(ctx context.Context, args arch.SyscallArguments) (uintptr, error) {
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		panic("setForegroundProcessGroup must be called from a task context")
	}

	// Read in the process group ID.
	var pgid primitive.Int32
	if _, err := pgid.CopyIn(task, args[2].Pointer()); err != nil {
		return 0, err
	}

	ret, err := task.ThreadGroup().SetForegroundProcessGroup(tm.kTTY, kernel.ProcessGroupID(pgid))
	return uintptr(ret), err
}
