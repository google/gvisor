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
	"math"
	"sync/atomic"
	"unsafe"

	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/context"
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

// initNoLeakCheck initializes the table without enabling leak checking.
//
// This is used when loading an FDTable after S/R, during which the ref count
// object itself will enable leak checking if necessary.
func (f *FDTable) initNoLeakCheck() {
	var slice []unsafe.Pointer // Empty slice.
	atomic.StorePointer(&f.slice, unsafe.Pointer(&slice))
}

// init initializes the table with leak checking.
func (f *FDTable) init() {
	f.initNoLeakCheck()
	f.InitRefs()
	f.fdBitmap = bitmap.New(uint32(math.MaxUint16))
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

// CurrentMaxFDs returns the number of file descriptors that may be stored in f
// without reallocation.
func (f *FDTable) CurrentMaxFDs() int {
	slice := *(*[]unsafe.Pointer)(atomic.LoadPointer(&f.slice))
	return len(slice)
}

// set sets an entry for VFS1, refer to setAll().
//
// Precondition: mu must be held.
func (f *FDTable) set(ctx context.Context, fd int32, file *fs.File, flags FDFlags) *fs.File {
	dropFile, _ := f.setAll(ctx, fd, file, nil, flags)
	return dropFile
}

// setVFS2 sets an entry for VFS2, refer to setAll().
//
// Precondition: mu must be held.
func (f *FDTable) setVFS2(ctx context.Context, fd int32, file *vfs.FileDescription, flags FDFlags) *vfs.FileDescription {
	_, dropFile := f.setAll(ctx, fd, nil, file, flags)
	return dropFile
}

// setAll sets the file description referred to by fd to file/fileVFS2. If
// file/fileVFS2 are non-nil, it takes a reference on them. If setAll replaces
// an existing file description, it returns it with the FDTable's reference
// transferred to the caller, which must call f.drop/dropVFS2() on the returned
// file after unlocking f.mu.
//
// Precondition: mu must be held.
func (f *FDTable) setAll(ctx context.Context, fd int32, file *fs.File, fileVFS2 *vfs.FileDescription, flags FDFlags) (*fs.File, *vfs.FileDescription) {
	if file != nil && fileVFS2 != nil {
		panic("VFS1 and VFS2 files set")
	}

	slicePtr := (*[]unsafe.Pointer)(atomic.LoadPointer(&f.slice))

	// Grow the table as required.
	if last := int32(len(*slicePtr)); fd >= last {
		end := fd + 1
		if end < 2*last {
			end = 2 * last
		}
		newSlice := append(*slicePtr, make([]unsafe.Pointer, end-last)...)
		slicePtr = &newSlice
		atomic.StorePointer(&f.slice, unsafe.Pointer(slicePtr))
	}

	slice := *slicePtr

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

	if orig != nil {
		switch {
		case orig.file != nil:
			if desc == nil || desc.file != orig.file {
				return orig.file, nil
			}
		case orig.fileVFS2 != nil:
			if desc == nil || desc.fileVFS2 != orig.fileVFS2 {
				return nil, orig.fileVFS2
			}
		}
	}
	return nil, nil
}
