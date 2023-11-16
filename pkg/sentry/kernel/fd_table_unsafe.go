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

	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

type descriptorBucket [fdsPerBucket]descriptorAtomicPtr
type descriptorBucketSlice []descriptorBucketAtomicPtr

// descriptorTable is a two level table. The first level is a slice of
// *descriptorBucket where each bucket is a slice of *descriptor.
//
// All objects are updated atomically.
type descriptorTable struct {
	// Changes to the slice itself requiring holding FDTable.mu.
	slice descriptorBucketSliceAtomicPtr `state:".(map[int32]*descriptor)"`
}

// initNoLeakCheck initializes the table without enabling leak checking.
//
// This is used when loading an FDTable after S/R, during which the ref count
// object itself will enable leak checking if necessary.
func (f *FDTable) initNoLeakCheck() {
	var slice descriptorBucketSlice // Empty slice.
	f.slice.Store(&slice)
}

// init initializes the table with leak checking.
func (f *FDTable) init() {
	f.initNoLeakCheck()
	f.InitRefs()
	f.fdBitmap = bitmap.New(uint32(math.MaxUint16))
}

const (
	// fdsPerBucketShift is chosen in such a way that the size of bucket is
	// equal to one page.
	fdsPerBucketShift = 9
	fdsPerBucket      = 1 << fdsPerBucketShift
	fdsPerBucketMask  = fdsPerBucket - 1
)

// get gets a file entry.
//
// The boolean indicates whether this was in range.
//
//go:nosplit
func (f *FDTable) get(fd int32) (*vfs.FileDescription, FDFlags, bool) {
	slice := *f.slice.Load()
	bucketN := fd >> fdsPerBucketShift
	if bucketN >= int32(len(slice)) {
		return nil, FDFlags{}, false
	}
	bucket := slice[bucketN].Load()
	if bucket == nil {
		return nil, FDFlags{}, false
	}
	d := bucket[fd&fdsPerBucketMask].Load()
	if d == nil {
		return nil, FDFlags{}, true
	}
	return d.file, d.flags, true
}

// CurrentMaxFDs returns the number of file descriptors that may be stored in f
// without reallocation.
func (f *FDTable) CurrentMaxFDs() int {
	slice := *f.slice.Load()
	return len(slice) * fdsPerBucket
}

// set sets the file description referred to by fd to file. If file is non-nil,
// f takes a reference on it. If file is nil, the file entry at fd is cleared.
// If set replaces an existing file description that is different from `file`,
// it returns it with the FDTable's reference transferred to the caller, which
// must call f.drop on the returned file after unlocking f.mu.
//
// Precondition: mu must be held.
func (f *FDTable) set(fd int32, file *vfs.FileDescription, flags FDFlags) *vfs.FileDescription {
	slicePtr := f.slice.Load()

	bucketN := fd >> fdsPerBucketShift
	// Grow the table as required.
	if length := len(*slicePtr); int(bucketN) >= length {
		newLen := int(bucketN) + 1
		if newLen < 2*length {
			// Ensure the table at least doubles in size without going over the limit.
			newLen = 2 * length
			if newLen > int(MaxFdLimit) {
				newLen = int(MaxFdLimit)
			}
		}
		newSlice := append(*slicePtr, make([]descriptorBucketAtomicPtr, newLen-length)...)
		slicePtr = &newSlice
		f.slice.Store(slicePtr)
	}

	slice := *slicePtr

	bucket := slice[bucketN].Load()
	if bucket == nil {
		bucket = &descriptorBucket{}
		slice[bucketN].Store(bucket)
	}

	var desc *descriptor
	if file != nil {
		desc = &descriptor{
			file:  file,
			flags: flags,
		}
	}

	// Update the single element.
	orig := bucket[fd%fdsPerBucket].Swap(desc)

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
