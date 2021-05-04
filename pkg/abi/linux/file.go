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

	"gvisor.dev/gvisor/pkg/abi"
)

// Constants for open(2).
const (
	O_ACCMODE  = 000000003
	O_RDONLY   = 000000000
	O_WRONLY   = 000000001
	O_RDWR     = 000000002
	O_CREAT    = 000000100
	O_EXCL     = 000000200
	O_NOCTTY   = 000000400
	O_TRUNC    = 000001000
	O_APPEND   = 000002000
	O_NONBLOCK = 000004000
	O_DSYNC    = 000010000
	O_ASYNC    = 000020000
	O_NOATIME  = 001000000
	O_CLOEXEC  = 002000000
	O_SYNC     = 004000000 // __O_SYNC in Linux
	O_PATH     = 010000000
	O_TMPFILE  = 020000000 // __O_TMPFILE in Linux
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
	S_IFMT   = 0170000
	S_IFSOCK = 0140000
	S_IFLNK  = 0120000
	S_IFREG  = 0100000
	S_IFBLK  = 060000
	S_IFDIR  = 040000
	S_IFCHR  = 020000
	S_IFIFO  = 010000

	FileTypeMask        = S_IFMT
	ModeSocket          = S_IFSOCK
	ModeSymlink         = S_IFLNK
	ModeRegular         = S_IFREG
	ModeBlockDevice     = S_IFBLK
	ModeDirectory       = S_IFDIR
	ModeCharacterDevice = S_IFCHR
	ModeNamedPipe       = S_IFIFO

	S_ISUID = 04000
	S_ISGID = 02000
	S_ISVTX = 01000

	ModeSetUID = S_ISUID
	ModeSetGID = S_ISGID
	ModeSticky = S_ISVTX

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

// Values for linux_dirent64.d_type.
const (
	DT_UNKNOWN = 0
	DT_FIFO    = 1
	DT_CHR     = 2
	DT_DIR     = 4
	DT_BLK     = 6
	DT_REG     = 8
	DT_LNK     = 10
	DT_SOCK    = 12
	DT_WHT     = 14
)

// DirentType are the friendly strings for linux_dirent64.d_type.
var DirentType = abi.ValueSet{
	DT_UNKNOWN: "DT_UNKNOWN",
	DT_FIFO:    "DT_FIFO",
	DT_CHR:     "DT_CHR",
	DT_DIR:     "DT_DIR",
	DT_BLK:     "DT_BLK",
	DT_REG:     "DT_REG",
	DT_LNK:     "DT_LNK",
	DT_SOCK:    "DT_SOCK",
	DT_WHT:     "DT_WHT",
}

// Values for preadv2/pwritev2.
const (
	// NOTE(b/120162627): gVisor does not implement the RWF_HIPRI feature, but
	// the flag is accepted as a valid flag argument for preadv2/pwritev2 and
	// silently ignored.
	RWF_HIPRI = 0x00000001
	RWF_DSYNC = 0x00000002
	RWF_SYNC  = 0x00000004
	RWF_VALID = RWF_HIPRI | RWF_DSYNC | RWF_SYNC
)

// SizeOfStat is the size of a Stat struct.
var SizeOfStat = (*Stat)(nil).SizeBytes()

// Flags for statx.
const (
	AT_STATX_SYNC_TYPE    = 0x6000
	AT_STATX_SYNC_AS_STAT = 0x0000
	AT_STATX_FORCE_SYNC   = 0x2000
	AT_STATX_DONT_SYNC    = 0x4000
)

// Mask values for statx.
const (
	STATX_TYPE        = 0x00000001
	STATX_MODE        = 0x00000002
	STATX_NLINK       = 0x00000004
	STATX_UID         = 0x00000008
	STATX_GID         = 0x00000010
	STATX_ATIME       = 0x00000020
	STATX_MTIME       = 0x00000040
	STATX_CTIME       = 0x00000080
	STATX_INO         = 0x00000100
	STATX_SIZE        = 0x00000200
	STATX_BLOCKS      = 0x00000400
	STATX_BASIC_STATS = 0x000007ff
	STATX_BTIME       = 0x00000800
	STATX_ALL         = 0x00000fff
	STATX__RESERVED   = 0x80000000
)

// Bitmasks for Statx.Attributes and Statx.AttributesMask, from
// include/uapi/linux/stat.h.
const (
	STATX_ATTR_COMPRESSED = 0x00000004
	STATX_ATTR_IMMUTABLE  = 0x00000010
	STATX_ATTR_APPEND     = 0x00000020
	STATX_ATTR_NODUMP     = 0x00000040
	STATX_ATTR_ENCRYPTED  = 0x00000800
	STATX_ATTR_AUTOMOUNT  = 0x00001000
)

// Statx represents struct statx.
//
// +marshal
type Statx struct {
	Mask           uint32
	Blksize        uint32
	Attributes     uint64
	Nlink          uint32
	UID            uint32
	GID            uint32
	Mode           uint16
	_              uint16
	Ino            uint64
	Size           uint64
	Blocks         uint64
	AttributesMask uint64
	Atime          StatxTimestamp
	Btime          StatxTimestamp
	Ctime          StatxTimestamp
	Mtime          StatxTimestamp
	RdevMajor      uint32
	RdevMinor      uint32
	DevMajor       uint32
	DevMinor       uint32
}

// SizeOfStatx is the size of a Statx struct.
var SizeOfStatx = (*Statx)(nil).SizeBytes()

// FileMode represents a mode_t.
type FileMode uint16

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

// IsDir returns true if file type represents a directory.
func (m FileMode) IsDir() bool {
	return m.FileType() == S_IFDIR
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

// DirentType maps file types to dirent types appropriate for (struct
// dirent)::d_type.
func (m FileMode) DirentType() uint8 {
	switch m.FileType() {
	case ModeSocket:
		return DT_SOCK
	case ModeSymlink:
		return DT_LNK
	case ModeRegular:
		return DT_REG
	case ModeBlockDevice:
		return DT_BLK
	case ModeDirectory:
		return DT_DIR
	case ModeCharacterDevice:
		return DT_CHR
	case ModeNamedPipe:
		return DT_FIFO
	default:
		return DT_UNKNOWN
	}
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

// Constants related to fallocate(2). Source: include/uapi/linux/falloc.h
const (
	FALLOC_FL_KEEP_SIZE      = 0x01
	FALLOC_FL_PUNCH_HOLE     = 0x02
	FALLOC_FL_NO_HIDE_STALE  = 0x04
	FALLOC_FL_COLLAPSE_RANGE = 0x08
	FALLOC_FL_ZERO_RANGE     = 0x10
	FALLOC_FL_INSERT_RANGE   = 0x20
	FALLOC_FL_UNSHARE_RANGE  = 0x40
)
