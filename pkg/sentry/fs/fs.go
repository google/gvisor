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
//         MountSource.mu
//
// If multiple Dirent or MountSource locks must be taken, locks in the parent must be
// taken before locks in their children.
//
// If locks must be taken on multiple unrelated Dirents, renameMu must be taken
// first. See lockForRename.
package fs

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
)

var (
	// workMu is used to synchronize pending asynchronous work. Async work
	// runs with the lock held for reading. AsyncBarrier will take the lock
	// for writing, thus ensuring that all Async work completes before
	// AsyncBarrier returns.
	workMu sync.RWMutex

	// asyncError is used to store up to one asynchronous execution error.
	asyncError = make(chan error, 1)
)

// AsyncBarrier waits for all outstanding asynchronous work to complete.
func AsyncBarrier() {
	workMu.Lock()
	workMu.Unlock()
}

// Async executes a function asynchronously.
//
// Async must not be called recursively.
func Async(f func()) {
	workMu.RLock()
	go func() { // S/R-SAFE: AsyncBarrier must be called.
		defer workMu.RUnlock() // Ensure RUnlock in case of panic.
		f()
	}()
}

// AsyncWithContext is just like Async, except that it calls the asynchronous
// function with the given context as argument. This function exists to avoid
// needing to allocate an extra function on the heap in a hot path.
func AsyncWithContext(ctx context.Context, f func(context.Context)) {
	workMu.RLock()
	go func() { // S/R-SAFE: AsyncBarrier must be called.
		defer workMu.RUnlock() // Ensure RUnlock in case of panic.
		f(ctx)
	}()
}

// AsyncErrorBarrier waits for all outstanding asynchronous work to complete, or
// the first async error to arrive. Other unfinished async executions will
// continue in the background. Other past and future async errors are ignored.
func AsyncErrorBarrier() error {
	wait := make(chan struct{}, 1)
	go func() { // S/R-SAFE: Does not touch persistent state.
		AsyncBarrier()
		wait <- struct{}{}
	}()
	select {
	case <-wait:
		select {
		case err := <-asyncError:
			return err
		default:
			return nil
		}
	case err := <-asyncError:
		return err
	}
}

// CatchError tries to capture the potential async error returned by the
// function. At most one async error will be captured globally so excessive
// errors will be dropped.
func CatchError(f func() error) func() {
	return func() {
		if err := f(); err != nil {
			select {
			case asyncError <- err:
			default:
				log.Warningf("excessive async error dropped: %v", err)
			}
		}
	}
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

// ErrCorruption indicates a failed restore due to external file system state in
// corruption.
type ErrCorruption struct {
	// Err is the wrapped error.
	Err error
}

// Error returns a sensible description of the save rejection error.
func (e ErrCorruption) Error() string {
	return "restore failed due to external file system state in corruption: " + e.Err.Error()
}
