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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/futex"
	"gvisor.dev/gvisor/pkg/sentry/loader"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/syserr"
)

var errNoSyscalls = syserr.New("no syscall table found", linux.ENOEXEC)

// Auxmap contains miscellaneous data for the task.
type Auxmap map[string]interface{}

// TaskImage is the subset of a task's data that is provided by the loader.
//
// +stateify savable
type TaskImage struct {
	// Name is the thread name set by the prctl(PR_SET_NAME) system call.
	Name string

	// Arch is the architecture-specific context (registers, etc.)
	Arch arch.Context

	// MemoryManager is the task's address space.
	MemoryManager *mm.MemoryManager

	// fu implements futexes in the address space.
	fu *futex.Manager

	// st is the task's syscall table.
	st *SyscallTable `state:".(syscallTableInfo)"`
}

// release releases all resources held by the TaskImage. release is called by
// the task when it execs into a new TaskImage or exits.
func (image *TaskImage) release() {
	// Nil out pointers so that if the task is saved after release, it doesn't
	// follow the pointers to possibly now-invalid objects.
	if image.MemoryManager != nil {
		image.MemoryManager.DecUsers(context.Background())
		image.MemoryManager = nil
	}
	image.fu = nil
}

// Fork returns a duplicate of image. The copied TaskImage always has an
// independent arch.Context. If shareAddressSpace is true, the copied
// TaskImage shares an address space with the original; otherwise, the copied
// TaskImage has an independent address space that is initially a duplicate
// of the original's.
func (image *TaskImage) Fork(ctx context.Context, k *Kernel, shareAddressSpace bool) (*TaskImage, error) {
	newImage := &TaskImage{
		Name: image.Name,
		Arch: image.Arch.Fork(),
		st:   image.st,
	}
	if shareAddressSpace {
		newImage.MemoryManager = image.MemoryManager
		if newImage.MemoryManager != nil {
			if !newImage.MemoryManager.IncUsers() {
				// Shouldn't be possible since image.MemoryManager should be a
				// counted user.
				panic(fmt.Sprintf("TaskImage.Fork called with userless TaskImage.MemoryManager"))
			}
		}
		newImage.fu = image.fu
	} else {
		newMM, err := image.MemoryManager.Fork(ctx)
		if err != nil {
			return nil, err
		}
		newImage.MemoryManager = newMM
		newImage.fu = k.futexes.Fork()
	}
	return newImage, nil
}

// Arch returns t's arch.Context.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) Arch() arch.Context {
	return t.image.Arch
}

// MemoryManager returns t's MemoryManager. MemoryManager does not take an
// additional reference on the returned MM.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) MemoryManager() *mm.MemoryManager {
	return t.image.MemoryManager
}

// SyscallTable returns t's syscall table.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) SyscallTable() *SyscallTable {
	return t.image.st
}

// Stack returns the userspace stack.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) Stack() *arch.Stack {
	return &arch.Stack{
		Arch:   t.Arch(),
		IO:     t.MemoryManager(),
		Bottom: hostarch.Addr(t.Arch().Stack()),
	}
}

// LoadTaskImage loads a specified file into a new TaskImage.
//
// args.MemoryManager does not need to be set by the caller.
func (k *Kernel) LoadTaskImage(ctx context.Context, args loader.LoadArgs) (*TaskImage, *syserr.Error) {
	// If File is not nil, we should load that instead of resolving Filename.
	if args.File != nil {
		args.Filename = args.File.PathnameWithDeleted(ctx)
	}

	// Prepare a new user address space to load into.
	m := mm.NewMemoryManager(k, k, k.SleepForAddressSpaceActivation)
	defer m.DecUsers(ctx)
	args.MemoryManager = m

	os, ac, name, err := loader.Load(ctx, args, k.extraAuxv, k.vdso)
	if err != nil {
		return nil, err
	}

	// Lookup our new syscall table.
	st, ok := LookupSyscallTable(os, ac.Arch())
	if !ok {
		// No syscall table found. This means that the ELF binary does not match
		// the architecture.
		return nil, errNoSyscalls
	}

	if !m.IncUsers() {
		panic("Failed to increment users count on new MM")
	}
	return &TaskImage{
		Name:          name,
		Arch:          ac,
		MemoryManager: m,
		fu:            k.futexes.Fork(),
		st:            st,
	}, nil
}
