// Copyright 2018 Google Inc.
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

package linux

import (
	"fmt"
	"strings"

	"gvisor.googlesource.com/gvisor/pkg/abi"
)

// Constants for open(2).
const (
	O_NONBLOCK = 00004000
	O_CLOEXEC  = 02000000
	O_PATH     = 010000000
)

// Constants for fstatat(2).
const (
	AT_SYMLINK_NOFOLLOW = 0x100
)

// Constants for mount(2).
const (
	MS_RDONLY      = 0x1
	MS_NOSUID      = 0x2
	MS_NODEV       = 0x4
	MS_NOEXEC      = 0x8
	MS_SYNCHRONOUS = 0x10
	MS_REMOUNT     = 0x20
	MS_MANDLOCK    = 0x40
	MS_DIRSYNC     = 0x80
	MS_NOATIME     = 0x400
	MS_NODIRATIME  = 0x800
	MS_BIND        = 0x1000
	MS_MOVE        = 0x2000
	MS_REC         = 0x4000

	MS_POSIXACL    = 0x10000
	MS_UNBINDABLE  = 0x20000
	MS_PRIVATE     = 0x40000
	MS_SLAVE       = 0x80000
	MS_SHARED      = 0x100000
	MS_RELATIME    = 0x200000
	MS_KERNMOUNT   = 0x400000
	MS_I_VERSION   = 0x800000
	MS_STRICTATIME = 0x1000000

	MS_MGC_VAL = 0xC0ED0000
	MS_MGC_MSK = 0xffff0000
)

// Constants for umount2(2).
const (
	MNT_FORCE       = 0x1
	MNT_DETACH      = 0x2
	MNT_EXPIRE      = 0x4
	UMOUNT_NOFOLLOW = 0x8
)

// Constants for unlinkat(2).
const (
	AT_REMOVEDIR = 0x200
)

// Constants for linkat(2) and fchownat(2).
const (
	AT_SYMLINK_FOLLOW = 0x400
	AT_EMPTY_PATH     = 0x1000
)

// Constants for all file-related ...at(2) syscalls.
const (
	AT_FDCWD = -100
)

// Special values for the ns field in utimensat(2).
const (
	UTIME_NOW  = ((1 << 30) - 1)
	UTIME_OMIT = ((1 << 30) - 2)
)

// MaxSymlinkTraversals is the maximum number of links that will be followed by
// the kernel to resolve a symlink.
const MaxSymlinkTraversals = 40

// Constants for flock(2).
const (
	LOCK_SH = 1 // shared lock
	LOCK_EX = 2 // exclusive lock
	LOCK_NB = 4 // or'd with one of the above to prevent blocking
	LOCK_UN = 8 // remove lock
)

// Values for mode_t.
const (
	FileTypeMask        = 0170000
	ModeSocket          = 0140000
	ModeSymlink         = 0120000
	ModeRegular         = 0100000
	ModeBlockDevice     = 060000
	ModeDirectory       = 040000
	ModeCharacterDevice = 020000
	ModeNamedPipe       = 010000

	ModeSetUID = 04000
	ModeSetGID = 02000
	ModeSticky = 01000

	ModeUserAll     = 0700
	ModeUserRead    = 0400
	ModeUserWrite   = 0200
	ModeUserExec    = 0100
	ModeGroupAll    = 0070
	ModeGroupRead   = 0040
	ModeGroupWrite  = 0020
	ModeGroupExec   = 0010
	ModeOtherAll    = 0007
	ModeOtherRead   = 0004
	ModeOtherWrite  = 0002
	ModeOtherExec   = 0001
	PermissionsMask = 0777
)

// Stat represents struct stat.
type Stat struct {
	Dev      uint64
	Ino      uint64
	Nlink    uint64
	Mode     uint32
	UID      uint32
	GID      uint32
	X_pad0   int32
	Rdev     uint64
	Size     int64
	Blksize  int64
	Blocks   int64
	ATime    Timespec
	MTime    Timespec
	CTime    Timespec
	X_unused [3]int64
}

// FileMode represents a mode_t.
type FileMode uint

// Permissions returns just the permission bits.
func (m FileMode) Permissions() FileMode {
	return m & PermissionsMask
}

// FileType returns just the file type bits.
func (m FileMode) FileType() FileMode {
	return m & FileTypeMask
}

// ExtraBits returns everything but the file type and permission bits.
func (m FileMode) ExtraBits() FileMode {
	return m &^ (PermissionsMask | FileTypeMask)
}

// String returns a string representation of m.
func (m FileMode) String() string {
	var s []string
	if ft := m.FileType(); ft != 0 {
		s = append(s, fileType.Parse(uint64(ft)))
	}
	if eb := m.ExtraBits(); eb != 0 {
		s = append(s, modeExtraBits.Parse(uint64(eb)))
	}
	s = append(s, fmt.Sprintf("0o%o", m.Permissions()))
	return strings.Join(s, "|")
}

var modeExtraBits = abi.FlagSet{
	{
		Flag: ModeSetUID,
		Name: "S_ISUID",
	},
	{
		Flag: ModeSetGID,
		Name: "S_ISGID",
	},
	{
		Flag: ModeSticky,
		Name: "S_ISVTX",
	},
}

var fileType = abi.ValueSet{
	{
		Value: ModeSocket,
		Name:  "S_IFSOCK",
	},
	{
		Value: ModeSymlink,
		Name:  "S_IFLINK",
	},
	{
		Value: ModeRegular,
		Name:  "S_IFREG",
	},
	{
		Value: ModeBlockDevice,
		Name:  "S_IFBLK",
	},
	{
		Value: ModeDirectory,
		Name:  "S_IFDIR",
	},
	{
		Value: ModeCharacterDevice,
		Name:  "S_IFCHR",
	},
	{
		Value: ModeNamedPipe,
		Name:  "S_IFIFO",
	},
}
