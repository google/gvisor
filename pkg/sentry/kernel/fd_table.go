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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/lock"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
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
	file  *vfs.FileDescription
	flags FDFlags
}

// MaxFdLimit defines the upper limit on the integer value of file descriptors.
const MaxFdLimit int32 = int32(bitmap.MaxBitEntryLimit)

// FDTable is used to manage File references and flags.
//
// +stateify savable
type FDTable struct {
	FDTableRefs

	k *Kernel

	// mu protects below.
	mu fdTableMutex `state:"nosave"`

	// fdBitmap shows which fds are already in use.
	fdBitmap bitmap.Bitmap `state:"nosave"`

	// descriptorTable holds descriptors.
	descriptorTable `state:".(map[int32]descriptor)"`
}

func (f *FDTable) saveDescriptorTable() map[int32]descriptor {
	m := make(map[int32]descriptor)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forEach(context.Background(), func(fd int32, file *vfs.FileDescription, flags FDFlags) {
		m[fd] = descriptor{
			file:  file,
			flags: flags,
		}
	})
	return m
}

func (f *FDTable) loadDescriptorTable(m map[int32]descriptor) {
	ctx := context.Background()
	f.initNoLeakCheck() // Initialize table.
	f.fdBitmap = bitmap.New(uint32(math.MaxUint16))
	for fd, d := range m {
		if fd < 0 {
			panic(fmt.Sprintf("FD is not supposed to be negative. FD: %d", fd))
		}

		if file := f.set(ctx, fd, d.file, d.flags); file != nil {
			panic("file set")
		}
		f.fdBitmap.Add(uint32(fd))
		// Note that we do _not_ need to acquire a extra table reference here. The
		// table reference will already be accounted for in the file, so we drop the
		// reference taken by set above.
		if d.file != nil {
			d.file.DecRef(ctx)
		}
	}
}

// drop drops the table reference.
func (f *FDTable) drop(ctx context.Context, file *vfs.FileDescription) {
	// Release any POSIX lock possibly held by the FDTable.
	if file.SupportsLocks() {
		err := file.UnlockPOSIX(ctx, f, lock.LockRange{0, lock.LockEOF})
		if err != nil && !linuxerr.Equals(linuxerr.ENOLCK, err) {
			panic(fmt.Sprintf("UnlockPOSIX failed: %v", err))
		}
	}

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
		f.RemoveIf(ctx, func(*vfs.FileDescription, FDFlags) bool {
			return true
		})
	})
}

// forEachUpTo iterates over all non-nil files upto maxFds (non-inclusive) in sorted order.
//
// It is the caller's responsibility to acquire an appropriate lock.
func (f *FDTable) forEachUpTo(ctx context.Context, maxFds int32, fn func(fd int32, file *vfs.FileDescription, flags FDFlags)) {
	// retries tracks the number of failed TryIncRef attempts for the same FD.
	retries := 0
	fds := f.fdBitmap.ToSlice()
	// Iterate through the fdBitmap.
	for _, ufd := range fds {
		fd := int32(ufd)
		if fd >= maxFds {
			break
		}
		file, flags, ok := f.get(fd)
		if !ok {
			break
		}
		if file != nil {
			if !file.TryIncRef() {
				retries++
				if retries > 1000 {
					panic(fmt.Sprintf("File in FD table has been destroyed. FD: %d, File: %+v, Impl: %+v", fd, file, file.Impl()))
				}
				continue // Race caught.
			}
			fn(fd, file, flags)
			file.DecRef(ctx)
		}
		retries = 0
	}
}

// forEach iterates over all non-nil files upto maxFd in sorted order.
//
// It is the caller's responsibility to acquire an appropriate lock.
func (f *FDTable) forEach(ctx context.Context, fn func(fd int32, file *vfs.FileDescription, flags FDFlags)) {
	f.forEachUpTo(ctx, MaxFdLimit, fn)
}

// String is a stringer for FDTable.
func (f *FDTable) String() string {
	var buf strings.Builder
	ctx := context.Background()
	files := make(map[int32]*vfs.FileDescription)
	f.mu.Lock()
	// Can't release f.mu from defer, because vfsObj.PathnameWithDeleted
	// should not be called under the fdtable mutex.
	f.forEach(ctx, func(fd int32, file *vfs.FileDescription, flags FDFlags) {
		if file != nil {
			file.IncRef()
			files[fd] = file
		}
	})
	f.mu.Unlock()
	defer func() {
		for _, f := range files {
			f.DecRef(ctx)
		}
	}()

	for fd, file := range files {
		vfsObj := file.Mount().Filesystem().VirtualFilesystem()
		vd := file.VirtualDentry()
		if vd.Dentry() == nil {
			panic(fmt.Sprintf("fd %d (type %T) has nil dentry: %#v", fd, file.Impl(), file))
		}
		name, err := vfsObj.PathnameWithDeleted(ctx, vfs.VirtualDentry{}, file.VirtualDentry())
		if err != nil {
			fmt.Fprintf(&buf, "<err: %v>\n", err)
			continue
		}
		fmt.Fprintf(&buf, "\tfd:%d => name %s\n", fd, name)
	}
	return buf.String()
}

// NewFDs allocates new FDs guaranteed to be the lowest number available
// greater than or equal to the minFD parameter. All files will share the set
// flags. Success is guaranteed to be all or none.
func (f *FDTable) NewFDs(ctx context.Context, minFD int32, files []*vfs.FileDescription, flags FDFlags) (fds []int32, err error) {
	if minFD < 0 {
		// Don't accept negative FDs.
		return nil, unix.EINVAL
	}

	// Default limit.
	end := MaxFdLimit

	// Ensure we don't get past the provided limit.
	if limitSet := limits.FromContext(ctx); limitSet != nil {
		lim := limitSet.Get(limits.NumberOfFiles)
		if lim.Cur != limits.Infinity {
			end = int32(lim.Cur)
		}
		if minFD+int32(len(files)) > end {
			return nil, unix.EMFILE
		}
	}

	f.mu.Lock()

	// max is used as the largest number in fdBitmap + 1.
	max := int32(0)

	if !f.fdBitmap.IsEmpty() {
		max = int32(f.fdBitmap.Maximum())
		max++
	}

	// Adjust max in case it is less than minFD.
	if max < minFD {
		max = minFD
	}
	// Install all entries.
	for len(fds) < len(files) {
		// Try to use free bit in fdBitmap.
		// If all bits in fdBitmap are used, expand fd to the max.
		fd, err := f.fdBitmap.FirstZero(uint32(minFD))
		if err != nil {
			fd = uint32(max)
			max++
		}
		if fd >= uint32(end) {
			break
		}
		f.fdBitmap.Add(fd)
		f.set(ctx, int32(fd), files[len(fds)], flags)
		fds = append(fds, int32(fd))
		minFD = int32(fd)
	}

	// Failure? Unwind existing FDs.
	if len(fds) < len(files) {
		for _, i := range fds {
			f.set(ctx, i, nil, FDFlags{})
			f.fdBitmap.Remove(uint32(i))
		}
		f.mu.Unlock()

		// Drop the reference taken by the call to f.set() that
		// originally installed the file. Don't call f.drop()
		// (generating inotify events, etc.) since the file should
		// appear to have never been inserted into f.
		for _, file := range files[:len(fds)] {
			file.DecRef(ctx)
		}
		return nil, unix.EMFILE
	}

	f.mu.Unlock()
	return fds, nil
}

// NewFD allocates a file descriptor greater than or equal to minFD for
// the given file description. If it succeeds, it takes a reference on file.
func (f *FDTable) NewFD(ctx context.Context, minFD int32, file *vfs.FileDescription, flags FDFlags) (int32, error) {
	files := []*vfs.FileDescription{file}
	fileSlice, error := f.NewFDs(ctx, minFD, files, flags)
	if error != nil {
		return -1, error
	}
	return fileSlice[0], nil
}

// NewFDAt sets the file reference for the given FD. If there is an active
// reference for that FD, the ref count for that existing reference is
// decremented.
func (f *FDTable) NewFDAt(ctx context.Context, fd int32, file *vfs.FileDescription, flags FDFlags) error {
	df, err := f.newFDAt(ctx, fd, file, flags)
	if err != nil {
		return err
	}
	if df != nil {
		f.drop(ctx, df)
	}
	return nil
}

func (f *FDTable) newFDAt(ctx context.Context, fd int32, file *vfs.FileDescription, flags FDFlags) (*vfs.FileDescription, error) {
	if fd < 0 {
		// Don't accept negative FDs.
		return nil, unix.EBADF
	}

	// Check the limit for the provided file.
	if limitSet := limits.FromContext(ctx); limitSet != nil {
		if lim := limitSet.Get(limits.NumberOfFiles); lim.Cur != limits.Infinity && uint64(fd) >= lim.Cur {
			return nil, unix.EMFILE
		}
	}

	// Install the entry.
	f.mu.Lock()
	defer f.mu.Unlock()

	df := f.set(ctx, fd, file, flags)
	// Add fd to fdBitmap.
	if file != nil {
		f.fdBitmap.Add(uint32(fd))
	}

	return df, nil
}

// SetFlags sets the flags for the given file descriptor.
//
// True is returned iff flags were changed.
func (f *FDTable) SetFlags(ctx context.Context, fd int32, flags FDFlags) error {
	if fd < 0 {
		// Don't accept negative FDs.
		return unix.EBADF
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	file, _, _ := f.get(fd)
	if file == nil {
		// No file found.
		return unix.EBADF
	}

	// Update the flags.
	f.set(ctx, fd, file, flags)
	return nil
}

// SetFlagsForRange sets the flags for the given range of file descriptors
// (inclusive: [startFd, endFd]).
func (f *FDTable) SetFlagsForRange(ctx context.Context, startFd int32, endFd int32, flags FDFlags) error {
	if startFd < 0 || startFd > endFd {
		return unix.EBADF
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	for fd, err := f.fdBitmap.FirstOne(uint32(startFd)); err == nil && fd <= uint32(endFd); fd, err = f.fdBitmap.FirstOne(fd + 1) {
		fdI32 := int32(fd)
		file, _, _ := f.get(fdI32)
		f.set(ctx, fdI32, file, flags)
	}

	return nil
}

// Get returns a reference to the file and the flags for the FD or nil if no
// file is defined for the given fd.
//
// N.B. Callers are required to use DecRef when they are done.
//
//go:nosplit
func (f *FDTable) Get(fd int32) (*vfs.FileDescription, FDFlags) {
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

// GetFDs returns a sorted list of valid fds.
//
// Precondition: The caller must be running on the task goroutine, or Task.mu
// must be locked.
func (f *FDTable) GetFDs(ctx context.Context) []int32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	fds := make([]int32, 0, int(f.fdBitmap.GetNumOnes()))
	f.forEach(ctx, func(fd int32, _ *vfs.FileDescription, _ FDFlags) {
		fds = append(fds, fd)
	})
	return fds
}

// Fork returns an independent FDTable, cloning all FDs up to maxFds (non-inclusive).
func (f *FDTable) Fork(ctx context.Context, maxFds int32) *FDTable {
	clone := f.k.NewFDTable()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forEachUpTo(ctx, maxFds, func(fd int32, file *vfs.FileDescription, flags FDFlags) {
		// The set function here will acquire an appropriate table
		// reference for the clone. We don't need anything else.
		if df := clone.set(ctx, fd, file, flags); df != nil {
			panic("file set")
		}
		clone.fdBitmap.Add(uint32(fd))
	})
	return clone
}

// Remove removes an FD from and returns a tuple where one of the files is non-nil
// iff successful.
//
// N.B. Callers are required to use DecRef on the returned file when they are done.
func (f *FDTable) Remove(ctx context.Context, fd int32) *vfs.FileDescription {
	if fd < 0 {
		return nil
	}

	f.mu.Lock()
	file, _, _ := f.get(fd)
	if file != nil {
		// Add reference for caller.
		file.IncRef()
		file = f.set(ctx, fd, nil, FDFlags{}) // Zap entry.
		f.fdBitmap.Remove(uint32(fd))
	}
	f.mu.Unlock()

	if file != nil {
		f.drop(ctx, file)
	}
	return file
}

// RemoveIf removes all FDs where cond is true.
func (f *FDTable) RemoveIf(ctx context.Context, cond func(*vfs.FileDescription, FDFlags) bool) {
	var files []*vfs.FileDescription

	f.mu.Lock()
	f.forEach(ctx, func(fd int32, file *vfs.FileDescription, flags FDFlags) {
		if cond(file, flags) {
			df := f.set(ctx, fd, nil, FDFlags{}) // Clear from table.
			f.fdBitmap.Remove(uint32(fd))
			if df != nil {
				files = append(files, df)
			}
		}
	})
	f.mu.Unlock()

	for _, file := range files {
		f.drop(ctx, file)
	}
}

// RemoveNextInRange removes the next FD that falls within the given range,
// and returns a tuple where one of the files is non-nil iff successful.
//
// N.B. Callers are required to use DecRef on the returned file when they are done.
func (f *FDTable) RemoveNextInRange(ctx context.Context, startFd int32, endFd int32) (int32, *vfs.FileDescription) {
	if startFd < 0 || startFd > endFd {
		return MaxFdLimit, nil
	}

	f.mu.Lock()

	fdUint, err := f.fdBitmap.FirstOne(uint32(startFd))
	fd := int32(fdUint)
	if err != nil || fd > endFd {
		f.mu.Unlock()
		return MaxFdLimit, nil
	}
	file, _, _ := f.get(fd)

	if file != nil {
		// Add reference for caller.
		file.IncRef()
		file = f.set(ctx, fd, nil, FDFlags{}) // Zap entry.
		f.fdBitmap.Remove(uint32(fd))
	}
	f.mu.Unlock()

	if file != nil {
		f.drop(ctx, file)
	}

	return fd, file
}

// GetLastFd returns the last set FD in the FDTable bitmap.
func (f *FDTable) GetLastFd() int32 {
	f.mu.Lock()
	defer f.mu.Unlock()

	last := f.fdBitmap.Maximum()
	if last > bitmap.MaxBitEntryLimit {
		return MaxFdLimit
	}
	return int32(last)
}
