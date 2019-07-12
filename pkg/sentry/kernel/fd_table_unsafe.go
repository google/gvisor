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
	"sync/atomic"
	"unsafe"

	"gvisor.dev/gvisor/pkg/sentry/fs"
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

// set sets an entry.
//
// This handles accounting changes, as well as acquiring and releasing the
// reference needed by the table iff the file is different.
//
// Precondition: mu must be held.
func (f *FDTable) set(fd int32, file *fs.File, flags FDFlags) {
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

	// Create the new element.
	var d *descriptor
	if file != nil {
		d = &descriptor{
			file:  file,
			flags: flags,
		}
	}

	// Update the single element.
	orig := (*descriptor)(atomic.SwapPointer(&slice[fd], unsafe.Pointer(d)))

	// Acquire a table reference.
	if file != nil && (orig == nil || file != orig.file) {
		file.IncRef()
	}

	// Drop the table reference.
	if orig != nil && file != orig.file {
		f.drop(orig.file)
	}

	// Adjust used.
	switch {
	case orig == nil && file != nil:
		atomic.AddInt32(&f.used, 1)
	case orig != nil && file == nil:
		atomic.AddInt32(&f.used, -1)
	}
}
