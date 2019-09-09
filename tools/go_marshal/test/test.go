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
// +marshal
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

// Timespec represents struct timespec in <time.h>.
//
// +marshal
type Timespec struct {
	Sec  int64
	Nsec int64
}

// Stat represents struct stat.
//
// +marshal
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
