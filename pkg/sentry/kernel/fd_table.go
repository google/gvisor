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
	"math"
	"strings"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
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
// It contains both VFS1 and VFS2 file types, but only one of them can be set.
//
// +stateify savable
type descriptor struct {
	// TODO(gvisor.dev/issue/1624): Remove fs.File.
	file     *fs.File
	fileVFS2 *vfs.FileDescription
	flags    FDFlags
}

// FDTable is used to manage File references and flags.
//
// +stateify savable
type FDTable struct {
	FDTableRefs

	k *Kernel

	// mu protects below.
	mu sync.Mutex `state:"nosave"`

	// next is start position to find fd.
	next int32

	// used contains the number of non-nil entries. It must be accessed
	// atomically. It may be read atomically without holding mu (but not
	// written).
	used int32

	// descriptorTable holds descriptors.
	descriptorTable `state:".(map[int32]descriptor)"`
}

func (f *FDTable) saveDescriptorTable() map[int32]descriptor {
	m := make(map[int32]descriptor)
	f.forEach(context.Background(), func(fd int32, file *fs.File, fileVFS2 *vfs.FileDescription, flags FDFlags) {
		m[fd] = descriptor{
			file:     file,
			fileVFS2: fileVFS2,
			flags:    flags,
		}
	})
	return m
}

func (f *FDTable) loadDescriptorTable(m map[int32]descriptor) {
	ctx := context.Background()
	f.init() // Initialize table.
	for fd, d := range m {
		f.setAll(fd, d.file, d.fileVFS2, d.flags)

		// Note that we do _not_ need to acquire a extra table reference here. The
		// table reference will already be accounted for in the file, so we drop the
		// reference taken by set above.
		switch {
		case d.file != nil:
			d.file.DecRef(ctx)
		case d.fileVFS2 != nil:
			d.fileVFS2.DecRef(ctx)
		}
	}
}

// drop drops the table reference.
func (f *FDTable) drop(file *fs.File) {
	// Release locks.
	file.Dirent.Inode.LockCtx.Posix.UnlockRegion(f, lock.LockRange{0, lock.LockEOF})

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
	file.DecRef(context.Background())
}

// dropVFS2 drops the table reference.
func (f *FDTable) dropVFS2(file *vfs.FileDescription) {
	// Release any POSIX lock possibly held by the FDTable. Range {0, 0} means the
	// entire file.
	ctx := context.Background()
	err := file.UnlockPOSIX(ctx, f, 0, 0, linux.SEEK_SET)
	if err != nil && err != syserror.ENOLCK {
		panic(fmt.Sprintf("UnlockPOSIX failed: %v", err))
	}

	// Generate inotify events.
	ev := uint32(linux.IN_CLOSE_NOWRITE)
	if file.IsWritable() {
		ev = linux.IN_CLOSE_WRITE
	}
	file.Dentry().InotifyWithParent(ctx, ev, 0, vfs.PathEvent)

	// Drop the table's reference.
	file.DecRef(ctx)
}

// NewFDTable allocates a new FDTable that may be used by tasks in k.
func (k *Kernel) NewFDTable() *FDTable {
	f := &FDTable{k: k}
	f.init()
	return f
}

// DecRef implements RefCounter.DecRef.
//
// If f reaches zero references, all of its file descriptors are removed.
func (f *FDTable) DecRef(ctx context.Context) {
	f.FDTableRefs.DecRef(func() {
		f.RemoveIf(ctx, func(*fs.File, *vfs.FileDescription, FDFlags) bool {
			return true
		})
	})
}

// Size returns the number of file descriptor slots currently allocated.
func (f *FDTable) Size() int {
	size := atomic.LoadInt32(&f.used)
	return int(size)
}

// forEach iterates over all non-nil files in sorted order.
//
// It is the caller's responsibility to acquire an appropriate lock.
func (f *FDTable) forEach(ctx context.Context, fn func(fd int32, file *fs.File, fileVFS2 *vfs.FileDescription, flags FDFlags)) {
	// retries tracks the number of failed TryIncRef attempts for the same FD.
	retries := 0
	fd := int32(0)
	for {
		file, fileVFS2, flags, ok := f.getAll(fd)
		if !ok {
			break
		}
		switch {
		case file != nil:
			if !file.TryIncRef() {
				retries++
				if retries > 1000 {
					panic(fmt.Sprintf("File in FD table has been destroyed. FD: %d, File: %+v, FileOps: %+v", fd, file, file.FileOperations))
				}
				continue // Race caught.
			}
			fn(fd, file, nil, flags)
			file.DecRef(ctx)
		case fileVFS2 != nil:
			if !fileVFS2.TryIncRef() {
				retries++
				if retries > 1000 {
					panic(fmt.Sprintf("File in FD table has been destroyed. FD: %d, File: %+v, Impl: %+v", fd, fileVFS2, fileVFS2.Impl()))
				}
				continue // Race caught.
			}
			fn(fd, nil, fileVFS2, flags)
			fileVFS2.DecRef(ctx)
		}
		retries = 0
		fd++
	}
}

// String is a stringer for FDTable.
func (f *FDTable) String() string {
	var buf strings.Builder
	ctx := context.Background()
	f.forEach(ctx, func(fd int32, file *fs.File, fileVFS2 *vfs.FileDescription, flags FDFlags) {
		switch {
		case file != nil:
			n, _ := file.Dirent.FullName(nil /* root */)
			fmt.Fprintf(&buf, "\tfd:%d => name %s\n", fd, n)

		case fileVFS2 != nil:
			vfsObj := fileVFS2.Mount().Filesystem().VirtualFilesystem()
			name, err := vfsObj.PathnameWithDeleted(ctx, vfs.VirtualDentry{}, fileVFS2.VirtualDentry())
			if err != nil {
				fmt.Fprintf(&buf, "<err: %v>\n", err)
				return
			}
			fmt.Fprintf(&buf, "\tfd:%d => name %s\n", fd, name)
		}
	})
	return buf.String()
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

	// From f.next to find available fd.
	if fd < f.next {
		fd = f.next
	}

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

	if fd == f.next {
		// Update next search start position.
		f.next = fds[len(fds)-1] + 1
	}

	return fds, nil
}

// NewFDsVFS2 allocates new FDs guaranteed to be the lowest number available
// greater than or equal to the fd parameter. All files will share the set
// flags. Success is guaranteed to be all or none.
func (f *FDTable) NewFDsVFS2(ctx context.Context, fd int32, files []*vfs.FileDescription, flags FDFlags) (fds []int32, err error) {
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

	// From f.next to find available fd.
	if fd < f.next {
		fd = f.next
	}

	// Install all entries.
	for i := fd; i < end && len(fds) < len(files); i++ {
		if d, _, _ := f.getVFS2(i); d == nil {
			f.setVFS2(i, files[len(fds)], flags) // Set the descriptor.
			fds = append(fds, i)                 // Record the file descriptor.
		}
	}

	// Failure? Unwind existing FDs.
	if len(fds) < len(files) {
		for _, i := range fds {
			f.setVFS2(i, nil, FDFlags{}) // Zap entry.
		}
		return nil, syscall.EMFILE
	}

	if fd == f.next {
		// Update next search start position.
		f.next = fds[len(fds)-1] + 1
	}

	return fds, nil
}

// NewFDVFS2 allocates a file descriptor greater than or equal to minfd for
// the given file description. If it succeeds, it takes a reference on file.
func (f *FDTable) NewFDVFS2(ctx context.Context, minfd int32, file *vfs.FileDescription, flags FDFlags) (int32, error) {
	if minfd < 0 {
		// Don't accept negative FDs.
		return -1, syscall.EINVAL
	}

	// Default limit.
	end := int32(math.MaxInt32)

	// Ensure we don't get past the provided limit.
	if limitSet := limits.FromContext(ctx); limitSet != nil {
		lim := limitSet.Get(limits.NumberOfFiles)
		if lim.Cur != limits.Infinity {
			end = int32(lim.Cur)
		}
		if minfd >= end {
			return -1, syscall.EMFILE
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// From f.next to find available fd.
	fd := minfd
	if fd < f.next {
		fd = f.next
	}
	for fd < end {
		if d, _, _ := f.getVFS2(fd); d == nil {
			f.setVFS2(fd, file, flags)
			if fd == f.next {
				// Update next search start position.
				f.next = fd + 1
			}
			return fd, nil
		}
		fd++
	}
	return -1, syscall.EMFILE
}

// NewFDAt sets the file reference for the given FD. If there is an active
// reference for that FD, the ref count for that existing reference is
// decremented.
func (f *FDTable) NewFDAt(ctx context.Context, fd int32, file *fs.File, flags FDFlags) error {
	return f.newFDAt(ctx, fd, file, nil, flags)
}

// NewFDAtVFS2 sets the file reference for the given FD. If there is an active
// reference for that FD, the ref count for that existing reference is
// decremented.
func (f *FDTable) NewFDAtVFS2(ctx context.Context, fd int32, file *vfs.FileDescription, flags FDFlags) error {
	return f.newFDAt(ctx, fd, nil, file, flags)
}

func (f *FDTable) newFDAt(ctx context.Context, fd int32, file *fs.File, fileVFS2 *vfs.FileDescription, flags FDFlags) error {
	if fd < 0 {
		// Don't accept negative FDs.
		return syscall.EBADF
	}

	// Check the limit for the provided file.
	if limitSet := limits.FromContext(ctx); limitSet != nil {
		if lim := limitSet.Get(limits.NumberOfFiles); lim.Cur != limits.Infinity && uint64(fd) >= lim.Cur {
			return syscall.EMFILE
		}
	}

	// Install the entry.
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setAll(fd, file, fileVFS2, flags)
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

// SetFlagsVFS2 sets the flags for the given file descriptor.
//
// True is returned iff flags were changed.
func (f *FDTable) SetFlagsVFS2(fd int32, flags FDFlags) error {
	if fd < 0 {
		// Don't accept negative FDs.
		return syscall.EBADF
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	file, _, _ := f.getVFS2(fd)
	if file == nil {
		// No file found.
		return syscall.EBADF
	}

	// Update the flags.
	f.setVFS2(fd, file, flags)
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

// GetVFS2 returns a reference to the file and the flags for the FD or nil if no
// file is defined for the given fd.
//
// N.B. Callers are required to use DecRef when they are done.
//
//go:nosplit
func (f *FDTable) GetVFS2(fd int32) (*vfs.FileDescription, FDFlags) {
	if fd < 0 {
		return nil, FDFlags{}
	}

	for {
		file, flags, _ := f.getVFS2(fd)
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

// GetFDs returns a sorted list of valid fds.
//
// Precondition: The caller must be running on the task goroutine, or Task.mu
// must be locked.
func (f *FDTable) GetFDs(ctx context.Context) []int32 {
	fds := make([]int32, 0, int(atomic.LoadInt32(&f.used)))
	f.forEach(ctx, func(fd int32, _ *fs.File, _ *vfs.FileDescription, _ FDFlags) {
		fds = append(fds, fd)
	})
	return fds
}

// GetRefs returns a stable slice of references to all files and bumps the
// reference count on each. The caller must use DecRef on each reference when
// they're done using the slice.
func (f *FDTable) GetRefs(ctx context.Context) []*fs.File {
	files := make([]*fs.File, 0, f.Size())
	f.forEach(ctx, func(_ int32, file *fs.File, _ *vfs.FileDescription, _ FDFlags) {
		file.IncRef() // Acquire a reference for caller.
		files = append(files, file)
	})
	return files
}

// GetRefsVFS2 returns a stable slice of references to all files and bumps the
// reference count on each. The caller must use DecRef on each reference when
// they're done using the slice.
func (f *FDTable) GetRefsVFS2(ctx context.Context) []*vfs.FileDescription {
	files := make([]*vfs.FileDescription, 0, f.Size())
	f.forEach(ctx, func(_ int32, _ *fs.File, file *vfs.FileDescription, _ FDFlags) {
		file.IncRef() // Acquire a reference for caller.
		files = append(files, file)
	})
	return files
}

// Fork returns an independent FDTable.
func (f *FDTable) Fork(ctx context.Context) *FDTable {
	clone := f.k.NewFDTable()

	f.forEach(ctx, func(fd int32, file *fs.File, fileVFS2 *vfs.FileDescription, flags FDFlags) {
		// The set function here will acquire an appropriate table
		// reference for the clone. We don't need anything else.
		switch {
		case file != nil:
			clone.set(fd, file, flags)
		case fileVFS2 != nil:
			clone.setVFS2(fd, fileVFS2, flags)
		}
	})
	return clone
}

// Remove removes an FD from and returns a non-file iff successful.
//
// N.B. Callers are required to use DecRef when they are done.
func (f *FDTable) Remove(fd int32) (*fs.File, *vfs.FileDescription) {
	if fd < 0 {
		return nil, nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Update current available position.
	if fd < f.next {
		f.next = fd
	}

	orig, orig2, _, _ := f.getAll(fd)

	// Add reference for caller.
	switch {
	case orig != nil:
		orig.IncRef()
	case orig2 != nil:
		orig2.IncRef()
	}
	if orig != nil || orig2 != nil {
		f.setAll(fd, nil, nil, FDFlags{}) // Zap entry.
	}
	return orig, orig2
}

// RemoveIf removes all FDs where cond is true.
func (f *FDTable) RemoveIf(ctx context.Context, cond func(*fs.File, *vfs.FileDescription, FDFlags) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.forEach(ctx, func(fd int32, file *fs.File, fileVFS2 *vfs.FileDescription, flags FDFlags) {
		if cond(file, fileVFS2, flags) {
			f.set(fd, nil, FDFlags{}) // Clear from table.
			// Update current available position.
			if fd < f.next {
				f.next = fd
			}
		}
	})
}
