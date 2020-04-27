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
	"sync/atomic"
	"unsafe"

	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

type descriptorTable struct {
	// slice is a *[]unsafe.Pointer, where each element is actually
	// *descriptor object, updated atomically.
	//
	// Changes to the slice itself requiring holding FDTable.mu.
	slice unsafe.Pointer `state:".(map[int32]*descriptor)"`
}

// init initializes the table.
func (f *FDTable) init() {
	var slice []unsafe.Pointer // Empty slice.
	atomic.StorePointer(&f.slice, unsafe.Pointer(&slice))
}

// get gets a file entry.
//
// The boolean indicates whether this was in range.
//
//go:nosplit
func (f *FDTable) get(fd int32) (*fs.File, FDFlags, bool) {
	file, _, flags, ok := f.getAll(fd)
	return file, flags, ok
}

// getVFS2 gets a file entry.
//
// The boolean indicates whether this was in range.
//
//go:nosplit
func (f *FDTable) getVFS2(fd int32) (*vfs.FileDescription, FDFlags, bool) {
	_, file, flags, ok := f.getAll(fd)
	return file, flags, ok
}

// getAll gets a file entry.
//
// The boolean indicates whether this was in range.
//
//go:nosplit
func (f *FDTable) getAll(fd int32) (*fs.File, *vfs.FileDescription, FDFlags, bool) {
	slice := *(*[]unsafe.Pointer)(atomic.LoadPointer(&f.slice))
	if fd >= int32(len(slice)) {
		return nil, nil, FDFlags{}, false
	}
	d := (*descriptor)(atomic.LoadPointer(&slice[fd]))
	if d == nil {
		return nil, nil, FDFlags{}, true
	}
	if d.file != nil && d.fileVFS2 != nil {
		panic("VFS1 and VFS2 files set")
	}
	return d.file, d.fileVFS2, d.flags, true
}

// set sets an entry.
//
// This handles accounting changes, as well as acquiring and releasing the
// reference needed by the table iff the file is different.
//
// Precondition: mu must be held.
func (f *FDTable) set(fd int32, file *fs.File, flags FDFlags) {
	f.setAll(fd, file, nil, flags)
}

// setVFS2 sets an entry.
//
// This handles accounting changes, as well as acquiring and releasing the
// reference needed by the table iff the file is different.
//
// Precondition: mu must be held.
func (f *FDTable) setVFS2(fd int32, file *vfs.FileDescription, flags FDFlags) {
	f.setAll(fd, nil, file, flags)
}

// setAll sets an entry.
//
// This handles accounting changes, as well as acquiring and releasing the
// reference needed by the table iff the file is different.
//
// Precondition: mu must be held.
func (f *FDTable) setAll(fd int32, file *fs.File, fileVFS2 *vfs.FileDescription, flags FDFlags) {
	if file != nil && fileVFS2 != nil {
		panic("VFS1 and VFS2 files set")
	}

	slice := *(*[]unsafe.Pointer)(atomic.LoadPointer(&f.slice))

	// Grow the table as required.
	if last := int32(len(slice)); fd >= last {
		end := fd + 1
		if end < 2*last {
			end = 2 * last
		}
		slice = append(slice, make([]unsafe.Pointer, end-last)...)
		atomic.StorePointer(&f.slice, unsafe.Pointer(&slice))
	}

	var desc *descriptor
	if file != nil || fileVFS2 != nil {
		desc = &descriptor{
			file:     file,
			fileVFS2: fileVFS2,
			flags:    flags,
		}
	}

	// Update the single element.
	orig := (*descriptor)(atomic.SwapPointer(&slice[fd], unsafe.Pointer(desc)))

	// Acquire a table reference.
	if desc != nil {
		switch {
		case desc.file != nil:
			if orig == nil || desc.file != orig.file {
				desc.file.IncRef()
			}
		case desc.fileVFS2 != nil:
			if orig == nil || desc.fileVFS2 != orig.fileVFS2 {
				desc.fileVFS2.IncRef()
			}
		}
	}

	// Drop the table reference.
	if orig != nil {
		switch {
		case orig.file != nil:
			if desc == nil || desc.file != orig.file {
				f.drop(orig.file)
			}
		case orig.fileVFS2 != nil:
			if desc == nil || desc.fileVFS2 != orig.fileVFS2 {
				f.dropVFS2(orig.fileVFS2)
			}
		}
	}

	// Adjust used.
	switch {
	case orig == nil && desc != nil:
		atomic.AddInt32(&f.used, 1)
	case orig != nil && desc == nil:
		atomic.AddInt32(&f.used, -1)
	}
}
