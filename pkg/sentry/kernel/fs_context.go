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
	"sync"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/fs"
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

	// cwd is the current working directory. Will be nil iff the FSContext
	// has been destroyed.
	cwd *fs.Dirent

	// umask is the current file mode creation mask. When a thread using this
	// context invokes a syscall that creates a file, bits set in umask are
	// removed from the permissions that the file is created with.
	umask uint
}

// newFSContext returns a new filesystem context.
func newFSContext(root, cwd *fs.Dirent, umask uint) *FSContext {
	root.IncRef()
	cwd.IncRef()
	return &FSContext{
		root:  root,
		cwd:   cwd,
		umask: umask,
	}
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

	f.root.DecRef()
	f.root = nil

	f.cwd.DecRef()
	f.cwd = nil
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
	f.cwd.IncRef()
	f.root.IncRef()
	return &FSContext{
		cwd:   f.cwd,
		root:  f.root,
		umask: f.umask,
	}
}

// WorkingDirectory returns the current working directory.
//
// This will return nil if called after destroy(), otherwise it will return a
// Dirent with a reference taken.
func (f *FSContext) WorkingDirectory() *fs.Dirent {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cwd != nil {
		f.cwd.IncRef()
	}
	return f.cwd
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
