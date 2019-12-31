// Copyright 2018 The gVisor Authors.

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

package linux

// Constants for open(2).
const (
	O_DIRECT    = 000040000
	O_LARGEFILE = 000100000
	O_DIRECTORY = 000200000
	O_NOFOLLOW  = 000400000
)

// Stat represents struct stat.
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
