// Copyright 2024 The gVisor Authors.
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

//go:build loong64
// +build loong64

package linux

import (
	"structs"
)

// LoongArch64 uses the asm-generic fcntl flags. NOTE: these are NOT identical
// to arm64 -- arm64's asm/fcntl.h overrides O_DIRECTORY/O_DIRECT/O_NOFOLLOW/
// O_LARGEFILE, whereas LoongArch uses the generic values (same as amd64/x86).
const (
	O_DIRECT    = 000040000
	O_LARGEFILE = 000100000
	O_DIRECTORY = 000200000
	O_NOFOLLOW  = 000400000
)

// Stat represents struct stat. LoongArch64 uses the asm-generic stat layout
// (include/uapi/asm-generic/stat.h), identical to arm64.
//
// +marshal
type Stat struct {
	_       structs.HostLayout
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
