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

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// FSContext contains filesystem context.
//
// This includes umask and working directory.
//
// +stateify savable
type FSContext struct {
	FSContextRefs

	// mu protects below.
	mu fsContextMutex `state:"nosave"`

	// root is the filesystem root.
	root vfs.VirtualDentry

	// cwd is the current working directory.
	cwd vfs.VirtualDentry

	// umask is the current file mode creation mask. When a thread using this
	// context invokes a syscall that creates a file, bits set in umask are
	// removed from the permissions that the file is created with.
	umask uint

	// preventSharing is true for the duration of an associated Task's execve
	preventSharing bool
}

// NewFSContext returns a new filesystem context.
func NewFSContext(root, cwd vfs.VirtualDentry, umask uint) *FSContext {
	root.IncRef()
	cwd.IncRef()
	f := FSContext{
		root:  root,
		cwd:   cwd,
		umask: umask,
	}
	f.InitRefs()
	return &f
}

// destroy destroys the FSContext.
//
// Preconditions: f must have no refcount.
func (f *FSContext) destroy(ctx context.Context) {
	// Hold f.mu so that we don't race with RootDirectory() and
	// WorkingDirectory().
	f.mu.Lock()
	root := f.root
	cwd := f.cwd
	f.root = vfs.VirtualDentry{}
	f.cwd = vfs.VirtualDentry{}
	f.mu.Unlock()
	root.DecRef(ctx)
	cwd.DecRef(ctx)
}

// DecRef implements RefCounter.DecRef.
//
// When f reaches zero references, DecRef will be called on both root and cwd
// Dirents.
//
// Note that there may still be calls to WorkingDirectory() or RootDirectory()
// (that return nil).  This is because valid references may still be held via
// proc files or other mechanisms.
func (f *FSContext) DecRef(ctx context.Context) {
	f.FSContextRefs.DecRef(func() {
		f.destroy(ctx)
	})
}

// Fork forks this FSContext.
//
// This is not a valid call after f is destroyed.
func (f *FSContext) Fork() *FSContext {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.cwd.Ok() {
		panic("FSContext.Fork() called after destroy")
	}
	f.cwd.IncRef()
	f.root.IncRef()

	ctx := &FSContext{
		cwd:   f.cwd,
		root:  f.root,
		umask: f.umask,
	}
	ctx.InitRefs()
	return ctx
}

// WorkingDirectory returns the current working directory.
//
// This will return an empty vfs.VirtualDentry if called after f is
// destroyed, otherwise it will return a Dirent with a reference taken.
func (f *FSContext) WorkingDirectory() vfs.VirtualDentry {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.cwd.Ok() {
		f.cwd.IncRef()
	}
	return f.cwd
}

// SetWorkingDirectory sets the current working directory.
// This will take an extra reference on the VirtualDentry.
//
// This is not a valid call after f is destroyed.
func (f *FSContext) SetWorkingDirectory(ctx context.Context, d vfs.VirtualDentry) {
	f.mu.Lock()

	if !f.cwd.Ok() {
		f.mu.Unlock()
		panic(fmt.Sprintf("FSContext.SetWorkingDirectory(%v)) called after destroy", d))
	}

	old := f.cwd
	f.cwd = d
	d.IncRef()
	f.mu.Unlock()
	old.DecRef(ctx)
}

// RootDirectory returns the current filesystem root.
//
// This will return an empty vfs.VirtualDentry if called after f is
// destroyed, otherwise it will return a Dirent with a reference taken.
func (f *FSContext) RootDirectory() vfs.VirtualDentry {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.root.Ok() {
		f.root.IncRef()
	}
	return f.root
}

// SetRootDirectory sets the root directory. It takes a reference on vd.
//
// This is not a valid call after f is destroyed.
func (f *FSContext) SetRootDirectory(ctx context.Context, vd vfs.VirtualDentry) {
	if !vd.Ok() {
		panic("FSContext.SetRootDirectory called with zero-value VirtualDentry")
	}

	f.mu.Lock()

	if !f.root.Ok() {
		f.mu.Unlock()
		panic(fmt.Sprintf("FSContext.SetRootDirectory(%v)) called after destroy", vd))
	}

	old := f.root
	vd.IncRef()
	f.root = vd
	f.mu.Unlock()
	old.DecRef(ctx)
}

// Umask returns the current umask.
func (f *FSContext) Umask() uint {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.umask
}

// SwapUmask atomically sets the current umask and returns the old umask.
func (f *FSContext) SwapUmask(mask uint) uint {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := f.umask
	f.umask = mask
	return old
}

// checkAndPreventSharingOutsideTG returns true if the FSContext is shared
// outside of the given thread group. If it happens to be not shared, i.e.,
// used only by the given thread group, it will prevent this from changing by
// causing subsequent calls by clone(2) to fsContext.share() to fail until
// fsContext.allowSharing() is called.
//
// See Linux's fs_struct->in_exec.
func (f *FSContext) checkAndPreventSharingOutsideTG(tg *ThreadGroup) bool {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()
	f.mu.Lock()
	defer f.mu.Unlock()

	tgCount := int64(0)
	for t := tg.tasks.Front(); t != nil; t = t.Next() {
		if t.FSContext() == f {
			tgCount++
		}
	}

	shared := f.ReadRefs() > tgCount
	if !shared {
		f.preventSharing = true
	}
	return shared
}

// allowSharing allows the FSContext to be shared again via clone(2).
func (f *FSContext) allowSharing() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.preventSharing = false
}

// share is a wrapper around IncRef. It returns false if a concurrent execve(2) in one of
// the thread groups that uses this FSContext has prevented sharing.
func (f *FSContext) share() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.preventSharing {
		return false
	}
	f.IncRef()
	return true
}

// unshareFromTask removes the FSContext f from the given Task t and replaces it with newF.
// It returns a bool indicating whether f needs to be destroyed.

// This func operates without compromising a concurrent checkAndPreventSharingOutsideTG(): t's
// association with f is severed atomically by holding f.mu, allowing the concurrent func to
// correctly ascribe extra ref counts to tasks outside of t's thread group.
//
// Preconditions: The caller must be on the task goroutine and must hold t.mu.
func (f *FSContext) unshareFromTask(t *Task, newF *FSContext) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	t.fsContext.Store(newF)
	destroy := false
	f.FSContextRefs.DecRef(func() { destroy = true })
	return destroy
}
