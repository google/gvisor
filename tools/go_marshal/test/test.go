// Copyright 2019 The gVisor Authors.
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

// Package test contains data structures for testing the go_marshal tool.
package test

import (
	// We're intentionally using a package name alias here even though it's not
	// necessary to test the code generator's ability to handle package aliases.
	ex "gvisor.dev/gvisor/tools/go_marshal/test/external"
)

// Type1 is a test data type.
//
// +marshal slice:Type1Slice
type Type1 struct {
	a    Type2
	x, y int64 // Multiple field names.
	b    byte  `marshal:"unaligned"` // Short field.
	c    uint64
	_    uint32  // Unnamed scalar field.
	_    [6]byte // Unnamed vector field, typical padding.
	_    [2]byte
	xs   [8]int32
	as   [10]Type2 `marshal:"unaligned"` // Array of Marshallable objects.
	ss   Type3
}

// Type2 is a test data type.
//
// +marshal
type Type2 struct {
	n int64
	c byte
	_ [7]byte
	m int64
	a int64
}

// Type3 is a test data type.
//
// +marshal
type Type3 struct {
	s int64
	x ex.External // Type defined in another package.
}

// Type4 is a test data type.
//
// +marshal
type Type4 struct {
	c byte
	x int64 `marshal:"unaligned"`
	d byte
	_ [7]byte
}

// Type5 is a test data type.
//
// +marshal
type Type5 struct {
	n int64
	t Type4
	m int64
}

// Type6 is a test data type ends mid-word.
//
// +marshal
type Type6 struct {
	a int64
	b int64
	// If c isn't marked unaligned, analysis fails (as it should, since
	// the unsafe API corrupts Type7).
	c byte `marshal:"unaligned"`
}

// Type7 is a test data type that contains a child struct that ends
// mid-word.
// +marshal
type Type7 struct {
	x Type6
	y int64
}

// Type8 is a test data type which contains an external non-packed field.
//
// +marshal slice:Type8Slice
type Type8 struct {
	a  int64
	np ex.NotPacked
	b  int64
}

// Timespec represents struct timespec in <time.h>.
//
// +marshal
type Timespec struct {
	Sec  int64
	Nsec int64
}

// Stat represents struct stat.
//
// +marshal slice:StatSlice
type Stat struct {
	Dev     uint64
	Ino     uint64
	Nlink   uint64
	Mode    uint32
	UID     uint32
	GID     uint32
	_       int32
	Rdev    uint64
	Size    int64
	Blksize int64
	Blocks  int64
	ATime   Timespec
	MTime   Timespec
	CTime   Timespec
	_       [3]int64
}

// InetAddr is an example marshallable newtype on an array.
//
// +marshal
type InetAddr [4]byte

// SignalSet is an example marshallable newtype on a primitive.
//
// +marshal slice:SignalSetSlice:inner
type SignalSet uint64

// SignalSetAlias is an example newtype on another marshallable type.
//
// +marshal slice:SignalSetAliasSlice
type SignalSetAlias SignalSet

const sizeA = 64
const sizeB = 8

// TestArray is a test data structure on an array with a constant length.
//
// +marshal
type TestArray [sizeA]int32

// TestArray2 is a newtype on an array with a simple arithmetic expression of
// constants for the array length.
//
// +marshal
type TestArray2 [sizeA * sizeB]int32

// TestArray2 is a newtype on an array with a simple arithmetic expression of
// mixed constants and literals for the array length.
//
// +marshal
type TestArray3 [sizeA*sizeB + 12]int32

// Type9 is a test data type containing an array with a non-literal length.
//
// +marshal
type Type9 struct {
	x int64
	y [sizeA]int32
}
