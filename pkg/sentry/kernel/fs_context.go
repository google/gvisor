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

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// FSContext contains filesystem context.
//
// This includes umask and working directory.
//
// +stateify savable
type FSContext struct {
	refs.AtomicRefCount

	// mu protects below.
	mu sync.Mutex `state:"nosave"`

	// root is the filesystem root. Will be nil iff the FSContext has been
	// destroyed.
	root *fs.Dirent

	// rootVFS2 is the filesystem root.
	rootVFS2 vfs.VirtualDentry

	// cwd is the current working directory. Will be nil iff the FSContext
	// has been destroyed.
	cwd *fs.Dirent

	// cwdVFS2 is the current working directory.
	cwdVFS2 vfs.VirtualDentry

	// umask is the current file mode creation mask. When a thread using this
	// context invokes a syscall that creates a file, bits set in umask are
	// removed from the permissions that the file is created with.
	umask uint
}

// newFSContext returns a new filesystem context.
func newFSContext(root, cwd *fs.Dirent, umask uint) *FSContext {
	root.IncRef()
	cwd.IncRef()
	f := FSContext{
		root:  root,
		cwd:   cwd,
		umask: umask,
	}
	f.EnableLeakCheck("kernel.FSContext")
	return &f
}

// NewFSContextVFS2 returns a new filesystem context.
func NewFSContextVFS2(root, cwd vfs.VirtualDentry, umask uint) *FSContext {
	root.IncRef()
	cwd.IncRef()
	f := FSContext{
		rootVFS2: root,
		cwdVFS2:  cwd,
		umask:    umask,
	}
	f.EnableLeakCheck("kernel.FSContext")
	return &f
}

// destroy is the destructor for an FSContext.
//
// This will call DecRef on both root and cwd Dirents.  If either call to
// DecRef returns an error, then it will be propagated.  If both calls to
// DecRef return an error, then the one from root.DecRef will be propagated.
//
// Note that there may still be calls to WorkingDirectory() or RootDirectory()
// (that return nil).  This is because valid references may still be held via
// proc files or other mechanisms.
func (f *FSContext) destroy() {
	// Hold f.mu so that we don't race with RootDirectory() and
	// WorkingDirectory().
	f.mu.Lock()
	defer f.mu.Unlock()

	if VFS2Enabled {
		f.rootVFS2.DecRef()
		f.rootVFS2 = vfs.VirtualDentry{}
		f.cwdVFS2.DecRef()
		f.cwdVFS2 = vfs.VirtualDentry{}
	} else {
		f.root.DecRef()
		f.root = nil
		f.cwd.DecRef()
		f.cwd = nil
	}
}

// DecRef implements RefCounter.DecRef with destructor f.destroy.
func (f *FSContext) DecRef() {
	f.DecRefWithDestructor(f.destroy)
}

// Fork forks this FSContext.
//
// This is not a valid call after destroy.
func (f *FSContext) Fork() *FSContext {
	f.mu.Lock()
	defer f.mu.Unlock()

	if VFS2Enabled {
		f.cwdVFS2.IncRef()
		f.rootVFS2.IncRef()
	} else {
		f.cwd.IncRef()
		f.root.IncRef()
	}

	return &FSContext{
		cwd:      f.cwd,
		root:     f.root,
		cwdVFS2:  f.cwdVFS2,
		rootVFS2: f.rootVFS2,
		umask:    f.umask,
	}
}

// WorkingDirectory returns the current working directory.
//
// This will return nil if called after destroy(), otherwise it will return a
// Dirent with a reference taken.
func (f *FSContext) WorkingDirectory() *fs.Dirent {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.cwd.IncRef()
	return f.cwd
}

// WorkingDirectoryVFS2 returns the current working directory.
//
// This will return nil if called after destroy(), otherwise it will return a
// Dirent with a reference taken.
func (f *FSContext) WorkingDirectoryVFS2() vfs.VirtualDentry {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.cwdVFS2.IncRef()
	return f.cwdVFS2
}

// SetWorkingDirectory sets the current working directory.
// This will take an extra reference on the Dirent.
//
// This is not a valid call after destroy.
func (f *FSContext) SetWorkingDirectory(d *fs.Dirent) {
	if d == nil {
		panic("FSContext.SetWorkingDirectory called with nil dirent")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.cwd == nil {
		panic(fmt.Sprintf("FSContext.SetWorkingDirectory(%v)) called after destroy", d))
	}

	old := f.cwd
	f.cwd = d
	d.IncRef()
	old.DecRef()
}

// SetWorkingDirectoryVFS2 sets the current working directory.
// This will take an extra reference on the VirtualDentry.
//
// This is not a valid call after destroy.
func (f *FSContext) SetWorkingDirectoryVFS2(d vfs.VirtualDentry) {
	f.mu.Lock()
	defer f.mu.Unlock()

	old := f.cwdVFS2
	f.cwdVFS2 = d
	d.IncRef()
	old.DecRef()
}

// RootDirectory returns the current filesystem root.
//
// This will return nil if called after destroy(), otherwise it will return a
// Dirent with a reference taken.
func (f *FSContext) RootDirectory() *fs.Dirent {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.root != nil {
		f.root.IncRef()
	}
	return f.root
}

// RootDirectoryVFS2 returns the current filesystem root.
//
// This will return nil if called after destroy(), otherwise it will return a
// Dirent with a reference taken.
func (f *FSContext) RootDirectoryVFS2() vfs.VirtualDentry {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.rootVFS2.IncRef()
	return f.rootVFS2
}

// SetRootDirectory sets the root directory.
// This will take an extra reference on the Dirent.
//
// This is not a valid call after free.
func (f *FSContext) SetRootDirectory(d *fs.Dirent) {
	if d == nil {
		panic("FSContext.SetRootDirectory called with nil dirent")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.root == nil {
		panic(fmt.Sprintf("FSContext.SetRootDirectory(%v)) called after destroy", d))
	}

	old := f.root
	f.root = d
	d.IncRef()
	old.DecRef()
}

// SetRootDirectoryVFS2 sets the root directory. It takes a reference on vd.
//
// This is not a valid call after free.
func (f *FSContext) SetRootDirectoryVFS2(vd vfs.VirtualDentry) {
	if !vd.Ok() {
		panic("FSContext.SetRootDirectoryVFS2 called with zero-value VirtualDentry")
	}

	f.mu.Lock()

	if !f.rootVFS2.Ok() {
		f.mu.Unlock()
		panic(fmt.Sprintf("FSContext.SetRootDirectoryVFS2(%v)) called after destroy", vd))
	}

	old := f.rootVFS2
	vd.IncRef()
	f.rootVFS2 = vd
	f.mu.Unlock()
	old.DecRef()
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
