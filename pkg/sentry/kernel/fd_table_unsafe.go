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
func (f *FDTable) get(fd int32) (*vfs.FileDescription, FDFlags, bool) {
	slice := *(*[]unsafe.Pointer)(atomic.LoadPointer(&f.slice))
	if fd >= int32(len(slice)) {
		return nil, FDFlags{}, false
	}
	d := (*descriptor)(atomic.LoadPointer(&slice[fd]))
	if d == nil {
		return nil, FDFlags{}, true
	}
	return d.file, d.flags, true
}

// CurrentMaxFDs returns the number of file descriptors that may be stored in f
// without reallocation.
func (f *FDTable) CurrentMaxFDs() int {
	slice := *(*[]unsafe.Pointer)(atomic.LoadPointer(&f.slice))
	return len(slice)
}

// set sets the file description referred to by fd to file. If
// file is non-nil, it takes a reference on them. If setAll replaces
// an existing file description, it returns it with the FDTable's reference
// transferred to the caller, which must call f.drop on the returned
// file after unlocking f.mu.
//
// Precondition: mu must be held.
func (f *FDTable) set(fd int32, file *vfs.FileDescription, flags FDFlags) *vfs.FileDescription {
	slicePtr := (*[]unsafe.Pointer)(atomic.LoadPointer(&f.slice))

	// Grow the table as required.
	if length := len(*slicePtr); int(fd) >= length {
		newLen := int(fd) + 1
		if newLen < 2*length {
			// Ensure the table at least doubles in size without going over the limit.
			newLen = 2 * length
			if newLen > int(MaxFdLimit) {
				newLen = int(MaxFdLimit)
			}
		}
		newSlice := append(*slicePtr, make([]unsafe.Pointer, newLen-length)...)
		slicePtr = &newSlice
		atomic.StorePointer(&f.slice, unsafe.Pointer(slicePtr))
	}

	slice := *slicePtr

	var desc *descriptor
	if file != nil {
		desc = &descriptor{
			file:  file,
			flags: flags,
		}
	}

	// Update the single element.
	orig := (*descriptor)(atomic.SwapPointer(&slice[fd], unsafe.Pointer(desc)))

	// Acquire a table reference.
	if desc != nil && desc.file != nil {
		if orig == nil || desc.file != orig.file {
			desc.file.IncRef()
		}
	}

	if orig != nil && orig.file != nil {
		if desc == nil || desc.file != orig.file {
			return orig.file
		}
	}
	return nil
}
