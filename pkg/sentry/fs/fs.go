// Copyright 2018 Google Inc.
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

// Package fs implements a virtual filesystem layer.
//
// Specific filesystem implementations must implement the InodeOperations
// interface (inode.go).
//
// The MountNamespace (mounts.go) is used to create a collection of mounts in
// a filesystem rooted at a given Inode.
//
// MountSources (mount.go) form a tree, with each mount holding pointers to its
// parent and children.
//
// Dirents (dirents.go) wrap Inodes in a caching layer.
//
// When multiple locks are to be held at the same time, they should be acquired
// in the following order.
//
// Either:
//   File.mu
//     Locks in FileOperations implementations
//       goto Dirent-Locks
//
// Or:
//   MountNamespace.mu
//     goto Dirent-Locks
//
// Dirent-Locks:
//   renameMu
//     Dirent.dirMu
//       Dirent.mu
//         DirentCache.mu
//         Locks in InodeOperations implementations or overlayEntry
//         Inode.Watches.mu (see `Inotify` for other lock ordering)
//	   MountSource.mu
//
// If multiple Dirent or MountSource locks must be taken, locks in the parent must be
// taken before locks in their children.
//
// If locks must be taken on multiple unrelated Dirents, renameMu must be taken
// first. See lockForRename.
package fs

import (
	"sync"
)

// work is a sync.WaitGroup that can be used to queue asynchronous operations
// via Do. Callers can use Barrier to ensure no operations are outstanding.
var work sync.WaitGroup

// AsyncBarrier waits for all outstanding asynchronous work to complete.
func AsyncBarrier() {
	work.Wait()
}

// Async executes a function asynchronously.
func Async(f func()) {
	work.Add(1)
	go func() { // S/R-SAFE: Barrier must be called.
		defer work.Done() // Ensure Done in case of panic.
		f()
	}()
}

// ErrSaveRejection indicates a failed save due to unsupported file system state
// such as dangling open fd, etc.
type ErrSaveRejection struct {
	// Err is the wrapped error.
	Err error
}

// Error returns a sensible description of the save rejection error.
func (e ErrSaveRejection) Error() string {
	return "save rejected due to unsupported file system state: " + e.Err.Error()
}
