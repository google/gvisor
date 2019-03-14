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

package kernel

import (
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/cpuid"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/futex"
	"gvisor.googlesource.com/gvisor/pkg/sentry/loader"
	"gvisor.googlesource.com/gvisor/pkg/sentry/mm"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
)

var errNoSyscalls = syserr.New("no syscall table found", linux.ENOEXEC)

// Auxmap contains miscellaneous data for the task.
type Auxmap map[string]interface{}

// TaskContext is the subset of a task's data that is provided by the loader.
//
// +stateify savable
type TaskContext struct {
	// Name is the thread name set by the prctl(PR_SET_NAME) system call.
	Name string

	// Arch is the architecture-specific context (registers, etc.)
	Arch arch.Context

	// MemoryManager is the task's address space.
	MemoryManager *mm.MemoryManager

	// fu implements futexes in the address space.
	fu *futex.Manager

	// st is the task's syscall table.
	st *SyscallTable
}

// release releases all resources held by the TaskContext. release is called by
// the task when it execs into a new TaskContext or exits.
func (tc *TaskContext) release() {
	// Nil out pointers so that if the task is saved after release, it doesn't
	// follow the pointers to possibly now-invalid objects.
	if tc.MemoryManager != nil {
		// TODO
		tc.MemoryManager.DecUsers(context.Background())
		tc.MemoryManager = nil
	}
	tc.fu = nil
}

// Fork returns a duplicate of tc. The copied TaskContext always has an
// independent arch.Context. If shareAddressSpace is true, the copied
// TaskContext shares an address space with the original; otherwise, the copied
// TaskContext has an independent address space that is initially a duplicate
// of the original's.
func (tc *TaskContext) Fork(ctx context.Context, k *Kernel, shareAddressSpace bool) (*TaskContext, error) {
	newTC := &TaskContext{
		Arch: tc.Arch.Fork(),
		st:   tc.st,
	}
	if shareAddressSpace {
		newTC.MemoryManager = tc.MemoryManager
		if newTC.MemoryManager != nil {
			if !newTC.MemoryManager.IncUsers() {
				// Shouldn't be possible since tc.MemoryManager should be a
				// counted user.
				panic(fmt.Sprintf("TaskContext.Fork called with userless TaskContext.MemoryManager"))
			}
		}
		newTC.fu = tc.fu
	} else {
		newMM, err := tc.MemoryManager.Fork(ctx)
		if err != nil {
			return nil, err
		}
		newTC.MemoryManager = newMM
		newTC.fu = k.futexes.Fork()
	}
	return newTC, nil
}

// Arch returns t's arch.Context.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) Arch() arch.Context {
	return t.tc.Arch
}

// MemoryManager returns t's MemoryManager. MemoryManager does not take an
// additional reference on the returned MM.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) MemoryManager() *mm.MemoryManager {
	return t.tc.MemoryManager
}

// SyscallTable returns t's syscall table.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) SyscallTable() *SyscallTable {
	return t.tc.st
}

// Stack returns the userspace stack.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) Stack() *arch.Stack {
	return &arch.Stack{t.Arch(), t.MemoryManager(), usermem.Addr(t.Arch().Stack())}
}

// LoadTaskImage loads filename into a new TaskContext.
//
// It takes several arguments:
//  * mounts: MountNamespace to lookup filename in
//  * root: Root to lookup filename under
//  * wd: Working directory to lookup filename under
//  * maxTraversals: maximum number of symlinks to follow
//  * filename: path to binary to load
//  * argv: Binary argv
//  * envv: Binary envv
//  * fs: Binary FeatureSet
func (k *Kernel) LoadTaskImage(ctx context.Context, mounts *fs.MountNamespace, root, wd *fs.Dirent, maxTraversals *uint, filename string, argv, envv []string, fs *cpuid.FeatureSet) (*TaskContext, *syserr.Error) {
	// Prepare a new user address space to load into.
	m := mm.NewMemoryManager(k, k)
	defer m.DecUsers(ctx)

	os, ac, name, err := loader.Load(ctx, m, mounts, root, wd, maxTraversals, fs, filename, argv, envv, k.extraAuxv, k.vdso)
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
	return &TaskContext{
		Name:          name,
		Arch:          ac,
		MemoryManager: m,
		fu:            k.futexes.Fork(),
		st:            st,
	}, nil
}
