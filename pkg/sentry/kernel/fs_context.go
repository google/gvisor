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
	"gvisor.dev/gvisor/pkg/sync"
)

// FSContext contains filesystem context.
//
// This includes umask and working directory.
//
// +stateify savable
type FSContext struct {
	FSContextRefs

	// mu protects below.
	mu sync.Mutex `state:"nosave"`

	// root is the filesystem root.
	root vfs.VirtualDentry

	// cwd is the current working directory.
	cwd vfs.VirtualDentry

	// umask is the current file mode creation mask. When a thread using this
	// context invokes a syscall that creates a file, bits set in umask are
	// removed from the permissions that the file is created with.
	umask uint
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
		// Hold f.mu so that we don't race with RootDirectory() and
		// WorkingDirectory().
		f.mu.Lock()
		defer f.mu.Unlock()

		f.root.DecRef(ctx)
		f.root = vfs.VirtualDentry{}
		f.cwd.DecRef(ctx)
		f.cwd = vfs.VirtualDentry{}
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
	defer f.mu.Unlock()

	if !f.cwd.Ok() {
		panic(fmt.Sprintf("FSContext.SetWorkingDirectory(%v)) called after destroy", d))
	}

	old := f.cwd
	f.cwd = d
	d.IncRef()
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
