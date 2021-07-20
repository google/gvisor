// Copyright 2019 The gVisor Authors.

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

//go:build arm64
// +build arm64

package linux

// Constants for open(2).
const (
	O_DIRECTORY = 000040000
	O_NOFOLLOW  = 000100000
	O_DIRECT    = 000200000
	O_LARGEFILE = 000400000
)

// Stat represents struct stat.
//
// +marshal
type Stat struct {
	Dev     uint64
	Ino     uint64
	Mode    uint32
	Nlink   uint32
	UID     uint32
	GID     uint32
	Rdev    uint64
	_       uint64
	Size    int64
	Blksize int32
	_       int32
	Blocks  int64
	ATime   Timespec
	MTime   Timespec
	CTime   Timespec
	_       [2]int32
}
