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

package kernel

import (
	"bytes"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/lock"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
)

// FDs is an ordering of FD's that can be made stable.
type FDs []kdefs.FD

func (f FDs) Len() int {
	return len(f)
}

func (f FDs) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

func (f FDs) Less(i, j int) bool {
	return f[i] < f[j]
}

// FDFlags define flags for an individual descriptor.
//
// +stateify savable
type FDFlags struct {
	// CloseOnExec indicates the descriptor should be closed on exec.
	CloseOnExec bool
}

// ToLinuxFileFlags converts a kernel.FDFlags object to a Linux file flags representation.
func (f FDFlags) ToLinuxFileFlags() (mask uint) {
	if f.CloseOnExec {
		mask |= linux.O_CLOEXEC
	}
	return
}

// ToLinuxFDFlags converts a kernel.FDFlags object to a Linux descriptor flags representation.
func (f FDFlags) ToLinuxFDFlags() (mask uint) {
	if f.CloseOnExec {
		mask |= linux.FD_CLOEXEC
	}
	return
}

// descriptor holds the details about a file descriptor, namely a pointer the
// file itself and the descriptor flags.
//
// +stateify savable
type descriptor struct {
	file  *fs.File
	flags FDFlags
}

// FDMap is used to manage File references and flags.
//
// +stateify savable
type FDMap struct {
	refs.AtomicRefCount
	k     *Kernel
	files map[kdefs.FD]descriptor
	mu    sync.RWMutex `state:"nosave"`
	uid   uint64
}

// ID returns a unique identifier for this FDMap.
func (f *FDMap) ID() uint64 {
	return f.uid
}

// NewFDMap allocates a new FDMap that may be used by tasks in k.
func (k *Kernel) NewFDMap() *FDMap {
	return &FDMap{
		k:     k,
		files: make(map[kdefs.FD]descriptor),
		uid:   atomic.AddUint64(&k.fdMapUids, 1),
	}
}

// destroy removes all of the file descriptors from the map.
func (f *FDMap) destroy() {
	f.RemoveIf(func(*fs.File, FDFlags) bool {
		return true
	})
}

// DecRef implements RefCounter.DecRef with destructor f.destroy.
func (f *FDMap) DecRef() {
	f.DecRefWithDestructor(f.destroy)
}

// Size returns the number of file descriptor slots currently allocated.
func (f *FDMap) Size() int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return len(f.files)
}

// String is a stringer for FDMap.
func (f *FDMap) String() string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var b bytes.Buffer
	for k, v := range f.files {
		n, _ := v.file.Dirent.FullName(nil /* root */)
		b.WriteString(fmt.Sprintf("\tfd:%d => name %s\n", k, n))
	}
	return b.String()
}

// NewFDFrom allocates a new FD guaranteed to be the lowest number available
// greater than or equal to from. This property is important as Unix programs
// tend to count on this allocation order.
func (f *FDMap) NewFDFrom(fd kdefs.FD, file *fs.File, flags FDFlags, limitSet *limits.LimitSet) (kdefs.FD, error) {
	if fd < 0 {
		// Don't accept negative FDs.
		return 0, syscall.EINVAL
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Finds the lowest fd not in the handles map.
	lim := limitSet.Get(limits.NumberOfFiles)
	for i := fd; lim.Cur == limits.Infinity || i < kdefs.FD(lim.Cur); i++ {
		if _, ok := f.files[i]; !ok {
			file.IncRef()
			f.files[i] = descriptor{file, flags}
			return i, nil
		}
	}

	return -1, syscall.EMFILE
}

// NewFDAt sets the file reference for the given FD. If there is an
// active reference for that FD, the ref count for that existing reference
// is decremented.
func (f *FDMap) NewFDAt(fd kdefs.FD, file *fs.File, flags FDFlags, limitSet *limits.LimitSet) error {
	if fd < 0 {
		// Don't accept negative FDs.
		return syscall.EBADF
	}

	// In this one case we do not do a defer of the Unlock.  The
	// reason is that we must have done all the work needed for
	// discarding any old open file before we return to the
	// caller. In other words, the DecRef(), below, must have
	// completed by the time we return to the caller to ensure
	// side effects are, in fact, effected. A classic example is
	// dup2(fd1, fd2); if fd2 was already open, it must be closed,
	// and we don't want to resume the caller until it is; we have
	// to block on the DecRef(). Hence we can not just do a 'go
	// oldfile.DecRef()', since there would be no guarantee that
	// it would be done before we the caller resumed. Since we
	// must wait for the DecRef() to finish, and that could take
	// time, it's best to first call f.muUnlock beore so we are
	// not blocking other uses of this FDMap on the DecRef() call.
	f.mu.Lock()
	oldDesc, oldExists := f.files[fd]
	lim := limitSet.Get(limits.NumberOfFiles).Cur
	// if we're closing one then the effective limit is one
	// more than the actual limit.
	if oldExists && lim != limits.Infinity {
		lim++
	}
	if lim != limits.Infinity && fd >= kdefs.FD(lim) {
		f.mu.Unlock()
		return syscall.EMFILE
	}

	file.IncRef()
	f.files[fd] = descriptor{file, flags}
	f.mu.Unlock()

	if oldExists {
		oldDesc.file.DecRef()
	}
	return nil
}

// SetFlags sets the flags for the given file descriptor, if it is valid.
func (f *FDMap) SetFlags(fd kdefs.FD, flags FDFlags) {
	f.mu.Lock()
	defer f.mu.Unlock()

	desc, ok := f.files[fd]
	if !ok {
		return
	}

	f.files[fd] = descriptor{desc.file, flags}
}

// GetDescriptor returns a reference to the file and the flags for the FD. It
// bumps its reference count as well. It returns nil if there is no File
// for the FD, i.e. if the FD is invalid. The caller must use DecRef
// when they are done.
func (f *FDMap) GetDescriptor(fd kdefs.FD) (*fs.File, FDFlags) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if desc, ok := f.files[fd]; ok {
		desc.file.IncRef()
		return desc.file, desc.flags
	}
	return nil, FDFlags{}
}

// GetFile returns a reference to the File for the FD and bumps
// its reference count as well. It returns nil if there is no File
// for the FD, i.e. if the FD is invalid. The caller must use DecRef
// when they are done.
func (f *FDMap) GetFile(fd kdefs.FD) *fs.File {
	f.mu.RLock()
	if desc, ok := f.files[fd]; ok {
		desc.file.IncRef()
		f.mu.RUnlock()
		return desc.file
	}
	f.mu.RUnlock()
	return nil
}

// fds returns an ordering of FDs.
func (f *FDMap) fds() FDs {
	fds := make(FDs, 0, len(f.files))
	for fd := range f.files {
		fds = append(fds, fd)
	}
	sort.Sort(fds)
	return fds
}

// GetFDs returns a list of valid fds.
func (f *FDMap) GetFDs() FDs {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.fds()
}

// GetRefs returns a stable slice of references to all files and bumps the
// reference count on each.  The caller must use DecRef on each reference when
// they're done using the slice.
func (f *FDMap) GetRefs() []*fs.File {
	f.mu.RLock()
	defer f.mu.RUnlock()

	fds := f.fds()
	fs := make([]*fs.File, 0, len(fds))
	for _, fd := range fds {
		desc := f.files[fd]
		desc.file.IncRef()
		fs = append(fs, desc.file)
	}
	return fs
}

// Fork returns an independent FDMap pointing to the same descriptors.
func (f *FDMap) Fork() *FDMap {
	f.mu.RLock()
	defer f.mu.RUnlock()

	clone := f.k.NewFDMap()

	// Grab a extra reference for every file.
	for fd, desc := range f.files {
		desc.file.IncRef()
		clone.files[fd] = desc
	}

	// That's it!
	return clone
}

// unlock releases all file locks held by this FDMap's uid.  Must only be
// called on a non-nil *fs.File.
func (f *FDMap) unlock(file *fs.File) {
	id := lock.UniqueID(f.ID())
	file.Dirent.Inode.LockCtx.Posix.UnlockRegion(id, lock.LockRange{0, lock.LockEOF})
}

// inotifyFileClose generates the appropriate inotify events for f being closed.
func inotifyFileClose(f *fs.File) {
	var ev uint32
	d := f.Dirent

	if fs.IsDir(d.Inode.StableAttr) {
		ev |= linux.IN_ISDIR
	}

	if f.Flags().Write {
		ev |= linux.IN_CLOSE_WRITE
	} else {
		ev |= linux.IN_CLOSE_NOWRITE
	}

	d.InotifyEvent(ev, 0)
}

// Remove removes an FD from the FDMap, and returns (File, true) if a File
// one was found. Callers are expected to decrement the reference count on
// the File. Otherwise returns (nil, false).
func (f *FDMap) Remove(fd kdefs.FD) (*fs.File, bool) {
	f.mu.Lock()
	desc := f.files[fd]
	delete(f.files, fd)
	f.mu.Unlock()
	if desc.file != nil {
		f.unlock(desc.file)
		inotifyFileClose(desc.file)
		return desc.file, true
	}
	return nil, false
}

// RemoveIf removes all FDs where cond is true.
func (f *FDMap) RemoveIf(cond func(*fs.File, FDFlags) bool) {
	var removed []*fs.File
	f.mu.Lock()
	for fd, desc := range f.files {
		if desc.file != nil && cond(desc.file, desc.flags) {
			delete(f.files, fd)
			removed = append(removed, desc.file)
		}
	}
	f.mu.Unlock()

	for _, file := range removed {
		f.unlock(file)
		inotifyFileClose(file)
		file.DecRef()
	}
}
