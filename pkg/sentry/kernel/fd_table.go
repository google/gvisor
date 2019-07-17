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
	"bytes"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/limits"
)

// FDFlags define flags for an individual descriptor.
//
// +stateify savable
type FDFlags struct {
	// CloseOnExec indicates the descriptor should be closed on exec.
	CloseOnExec bool
}

// ToLinuxFileFlags converts a kernel.FDFlags object to a Linux file flags
// representation.
func (f FDFlags) ToLinuxFileFlags() (mask uint) {
	if f.CloseOnExec {
		mask |= linux.O_CLOEXEC
	}
	return
}

// ToLinuxFDFlags converts a kernel.FDFlags object to a Linux descriptor flags
// representation.
func (f FDFlags) ToLinuxFDFlags() (mask uint) {
	if f.CloseOnExec {
		mask |= linux.FD_CLOEXEC
	}
	return
}

// descriptor holds the details about a file descriptor, namely a pointer to
// the file itself and the descriptor flags.
//
// Note that this is immutable and can only be changed via operations on the
// descriptorTable.
//
// +stateify savable
type descriptor struct {
	file  *fs.File
	flags FDFlags
}

// FDTable is used to manage File references and flags.
//
// +stateify savable
type FDTable struct {
	refs.AtomicRefCount
	k *Kernel

	// uid is a unique identifier.
	uid uint64

	// mu protects below.
	mu sync.Mutex `state:"nosave"`

	// used contains the number of non-nil entries. It must be accessed
	// atomically. It may be read atomically without holding mu (but not
	// written).
	used int32

	// descriptorTable holds descriptors.
	descriptorTable `state:".(map[int32]descriptor)"`
}

func (f *FDTable) saveDescriptorTable() map[int32]descriptor {
	m := make(map[int32]descriptor)
	f.forEach(func(fd int32, file *fs.File, flags FDFlags) {
		m[fd] = descriptor{
			file:  file,
			flags: flags,
		}
	})
	return m
}

func (f *FDTable) loadDescriptorTable(m map[int32]descriptor) {
	f.init() // Initialize table.
	for fd, d := range m {
		f.set(fd, d.file, d.flags)

		// Note that we do _not_ need to acquire a extra table
		// reference here. The table reference will already be
		// accounted for in the file, so we drop the reference taken by
		// set above.
		d.file.DecRef()
	}
}

// drop drops the table reference.
func (f *FDTable) drop(file *fs.File) {
	// Release locks.
	file.Dirent.Inode.LockCtx.Posix.UnlockRegion(lock.UniqueID(f.uid), lock.LockRange{0, lock.LockEOF})

	// Send inotify events.
	d := file.Dirent
	var ev uint32
	if fs.IsDir(d.Inode.StableAttr) {
		ev |= linux.IN_ISDIR
	}
	if file.Flags().Write {
		ev |= linux.IN_CLOSE_WRITE
	} else {
		ev |= linux.IN_CLOSE_NOWRITE
	}
	d.InotifyEvent(ev, 0)

	// Drop the table reference.
	file.DecRef()
}

// ID returns a unique identifier for this FDTable.
func (f *FDTable) ID() uint64 {
	return f.uid
}

// NewFDTable allocates a new FDTable that may be used by tasks in k.
func (k *Kernel) NewFDTable() *FDTable {
	f := &FDTable{
		k:   k,
		uid: atomic.AddUint64(&k.fdMapUids, 1),
	}
	f.init()
	return f
}

// destroy removes all of the file descriptors from the map.
func (f *FDTable) destroy() {
	f.RemoveIf(func(*fs.File, FDFlags) bool {
		return true
	})
}

// DecRef implements RefCounter.DecRef with destructor f.destroy.
func (f *FDTable) DecRef() {
	f.DecRefWithDestructor(f.destroy)
}

// Size returns the number of file descriptor slots currently allocated.
func (f *FDTable) Size() int {
	size := atomic.LoadInt32(&f.used)
	return int(size)
}

// forEach iterates over all non-nil files.
//
// It is the caller's responsibility to acquire an appropriate lock.
func (f *FDTable) forEach(fn func(fd int32, file *fs.File, flags FDFlags)) {
	fd := int32(0)
	for {
		file, flags, ok := f.get(fd)
		if !ok {
			break
		}
		if file != nil {
			if !file.TryIncRef() {
				continue // Race caught.
			}
			fn(int32(fd), file, flags)
			file.DecRef()
		}
		fd++
	}
}

// String is a stringer for FDTable.
func (f *FDTable) String() string {
	var b bytes.Buffer
	f.forEach(func(fd int32, file *fs.File, flags FDFlags) {
		n, _ := file.Dirent.FullName(nil /* root */)
		b.WriteString(fmt.Sprintf("\tfd:%d => name %s\n", fd, n))
	})
	return b.String()
}

// NewFDs allocates new FDs guaranteed to be the lowest number available
// greater than or equal to the fd parameter. All files will share the set
// flags. Success is guaranteed to be all or none.
func (f *FDTable) NewFDs(ctx context.Context, fd int32, files []*fs.File, flags FDFlags) (fds []int32, err error) {
	if fd < 0 {
		// Don't accept negative FDs.
		return nil, syscall.EINVAL
	}

	// Default limit.
	end := int32(math.MaxInt32)

	// Ensure we don't get past the provided limit.
	if limitSet := limits.FromContext(ctx); limitSet != nil {
		lim := limitSet.Get(limits.NumberOfFiles)
		if lim.Cur != limits.Infinity {
			end = int32(lim.Cur)
		}
		if fd >= end {
			return nil, syscall.EMFILE
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Install all entries.
	for i := fd; i < end && len(fds) < len(files); i++ {
		if d, _, _ := f.get(i); d == nil {
			f.set(i, files[len(fds)], flags) // Set the descriptor.
			fds = append(fds, i)             // Record the file descriptor.
		}
	}

	// Failure? Unwind existing FDs.
	if len(fds) < len(files) {
		for _, i := range fds {
			f.set(i, nil, FDFlags{}) // Zap entry.
		}
		return nil, syscall.EMFILE
	}

	return fds, nil
}

// NewFDAt sets the file reference for the given FD. If there is an active
// reference for that FD, the ref count for that existing reference is
// decremented.
func (f *FDTable) NewFDAt(ctx context.Context, fd int32, file *fs.File, flags FDFlags) error {
	if fd < 0 {
		// Don't accept negative FDs.
		return syscall.EBADF
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Check the limit for the provided file.
	if limitSet := limits.FromContext(ctx); limitSet != nil {
		if lim := limitSet.Get(limits.NumberOfFiles); lim.Cur != limits.Infinity && uint64(fd) >= lim.Cur {
			return syscall.EMFILE
		}
	}

	// Install the entry.
	f.set(fd, file, flags)
	return nil
}

// SetFlags sets the flags for the given file descriptor.
//
// True is returned iff flags were changed.
func (f *FDTable) SetFlags(fd int32, flags FDFlags) error {
	if fd < 0 {
		// Don't accept negative FDs.
		return syscall.EBADF
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	file, _, _ := f.get(fd)
	if file == nil {
		// No file found.
		return syscall.EBADF
	}

	// Update the flags.
	f.set(fd, file, flags)
	return nil
}

// Get returns a reference to the file and the flags for the FD or nil if no
// file is defined for the given fd.
//
// N.B. Callers are required to use DecRef when they are done.
//
//go:nosplit
func (f *FDTable) Get(fd int32) (*fs.File, FDFlags) {
	if fd < 0 {
		return nil, FDFlags{}
	}

	for {
		file, flags, _ := f.get(fd)
		if file != nil {
			if !file.TryIncRef() {
				continue // Race caught.
			}
			// Reference acquired.
			return file, flags
		}
		// No file available.
		return nil, FDFlags{}
	}
}

// GetFDs returns a list of valid fds.
func (f *FDTable) GetFDs() []int32 {
	fds := make([]int32, 0, int(atomic.LoadInt32(&f.used)))
	f.forEach(func(fd int32, file *fs.File, flags FDFlags) {
		fds = append(fds, fd)
	})
	return fds
}

// GetRefs returns a stable slice of references to all files and bumps the
// reference count on each. The caller must use DecRef on each reference when
// they're done using the slice.
func (f *FDTable) GetRefs() []*fs.File {
	files := make([]*fs.File, 0, f.Size())
	f.forEach(func(_ int32, file *fs.File, flags FDFlags) {
		file.IncRef() // Acquire a reference for caller.
		files = append(files, file)
	})
	return files
}

// Fork returns an independent FDTable.
func (f *FDTable) Fork() *FDTable {
	clone := f.k.NewFDTable()

	f.forEach(func(fd int32, file *fs.File, flags FDFlags) {
		// The set function here will acquire an appropriate table
		// reference for the clone. We don't need anything else.
		clone.set(fd, file, flags)
	})
	return clone
}

// Remove removes an FD from and returns a non-file iff successful.
//
// N.B. Callers are required to use DecRef when they are done.
func (f *FDTable) Remove(fd int32) *fs.File {
	if fd < 0 {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	orig, _, _ := f.get(fd)
	if orig != nil {
		orig.IncRef()             // Reference for caller.
		f.set(fd, nil, FDFlags{}) // Zap entry.
	}
	return orig
}

// RemoveIf removes all FDs where cond is true.
func (f *FDTable) RemoveIf(cond func(*fs.File, FDFlags) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.forEach(func(fd int32, file *fs.File, flags FDFlags) {
		if cond(file, flags) {
			f.set(fd, nil, FDFlags{}) // Clear from table.
		}
	})
}
