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

package linux

import (
	"fmt"
	"strings"

	"gvisor.googlesource.com/gvisor/pkg/abi"
	"gvisor.googlesource.com/gvisor/pkg/binary"
)

// Constants for open(2).
const (
	O_ACCMODE   = 00000003
	O_RDONLY    = 00000000
	O_WRONLY    = 00000001
	O_RDWR      = 00000002
	O_CREAT     = 00000100
	O_EXCL      = 00000200
	O_NOCTTY    = 00000400
	O_TRUNC     = 00001000
	O_APPEND    = 00002000
	O_NONBLOCK  = 00004000
	O_ASYNC     = 00020000
	O_DIRECT    = 00040000
	O_LARGEFILE = 00100000
	O_DIRECTORY = 00200000
	O_NOFOLLOW  = 00400000
	O_CLOEXEC   = 02000000
	O_SYNC      = 04010000
	O_PATH      = 010000000
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

// Values for preadv2/pwritev2.
const (
	RWF_HIPRI = 0x00000001
	RWF_DSYNC = 0x00000002
	RWF_SYNC  = 0x00000004
	RWF_VALID = RWF_HIPRI | RWF_DSYNC | RWF_SYNC
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

// SizeOfStat is the size of a Stat struct.
var SizeOfStat = binary.Size(Stat{})

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
	ModeSocket:          "S_IFSOCK",
	ModeSymlink:         "S_IFLINK",
	ModeRegular:         "S_IFREG",
	ModeBlockDevice:     "S_IFBLK",
	ModeDirectory:       "S_IFDIR",
	ModeCharacterDevice: "S_IFCHR",
	ModeNamedPipe:       "S_IFIFO",
}

// Constants for memfd_create(2). Source: include/uapi/linux/memfd.h
const (
	MFD_CLOEXEC       = 0x0001
	MFD_ALLOW_SEALING = 0x0002
)

// Constants related to file seals. Source: include/uapi/{asm-generic,linux}/fcntl.h
const (
	F_LINUX_SPECIFIC_BASE = 1024
	F_ADD_SEALS           = F_LINUX_SPECIFIC_BASE + 9
	F_GET_SEALS           = F_LINUX_SPECIFIC_BASE + 10

	F_SEAL_SEAL   = 0x0001 // Prevent further seals from being set.
	F_SEAL_SHRINK = 0x0002 // Prevent file from shrinking.
	F_SEAL_GROW   = 0x0004 // Prevent file from growing.
	F_SEAL_WRITE  = 0x0008 // Prevent writes.
)
