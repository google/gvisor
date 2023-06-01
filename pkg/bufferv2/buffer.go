// Copyright 2022 The gVisor Authors.
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

// Package bufferv2 provides the implementation of a non-contiguous buffer that
// is reference counted, pooled, and copy-on-write. It allows O(1) append,
// and prepend operations.
//
// Deprecated: use package pkg/buffer instead.
package bufferv2

import (
	"gvisor.dev/gvisor/pkg/buffer"
)

const (
	// MaxChunkSize is largest payload size that we pool. Payloads larger than
	// this will be allocated from the heap and garbage collected as normal.
	MaxChunkSize = buffer.MaxChunkSize

	ReadSize = buffer.ReadSize
)

// Buffer is a non-linear buffer.
//
// Deprecated: use package pkg/buffer instead.
type Buffer = buffer.Buffer

// MakeWithData creates a new Buffer initialized with given data. This function
// should be used with caution to avoid unnecessary []byte allocations. When in
// doubt use NewWithView to maximize chunk reuse.
//
// Deprecated: use package pkg/buffer instead.
func MakeWithData(b []byte) Buffer {
	return buffer.MakeWithData(b)
}

// MakeWithView creates a new Buffer initialized with given view. This function
// takes ownership of v.
//
// Deprecated: use package pkg/buffer instead.
func MakeWithView(v *View) Buffer {
	return buffer.MakeWithView(v)
}

// BufferReader implements io methods on Buffer. Users must call Close()
// when finished with the buffer to free the underlying memory.
//
// Deprecated: use package pkg/buffer instead.
type BufferReader = buffer.BufferReader

// Range specifies a range of buffer.
//
// Deprecated: use package pkg/buffer instead.
type Range = buffer.Range

// View is a window into a shared chunk. Views are held by Buffers in
// viewLists to represent contiguous memory.
//
// A View must be created with NewView, NewViewWithData, or Clone. Owners are
// responsible for maintaining ownership over their views. When Views need to be
// shared or copied, the owner should create a new View with Clone. Clone must
// only ever be called on a owned View, not a borrowed one.
//
// Users are responsible for calling Release when finished with their View so
// that its resources can be returned to the pool.
//
// Users must not write directly to slices returned by AsSlice. Instead, they
// must use Write/WriteAt/CopyIn to modify the underlying View. This preserves
// the safety guarantees of copy-on-write.
//
// Deprecated: use package pkg/buffer instead.
type View = buffer.View

// NewView creates a new view with capacity at least as big as cap. It is
// analogous to make([]byte, 0, cap).
//
// Deprecated: use package pkg/buffer instead.
func NewView(cap int) *View {
	return buffer.NewView(cap)
}

// NewViewSize creates a new view with capacity at least as big as size and
// length that is exactly size. It is analogous to make([]byte, size).
//
// Deprecated: use package pkg/buffer instead.
func NewViewSize(size int) *View {
	return buffer.NewViewSize(size)
}

// NewViewWithData creates a new view and initializes it with data. This
// function should be used with caution to avoid unnecessary []byte allocations.
// When in doubt use NewWithView to maximize chunk reuse in production
// environments.
//
// Deprecated: use package pkg/buffer instead.
func NewViewWithData(data []byte) *View {
	return buffer.NewViewWithData(data)
}
