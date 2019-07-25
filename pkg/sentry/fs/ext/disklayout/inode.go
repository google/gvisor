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

package disklayout

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

// Special inodes. See https://www.kernel.org/doc/html/latest/filesystems/ext4/overview.html#special-inodes.
const (
	// RootDirInode is the inode number of the root directory inode.
	RootDirInode = 2
)

// The Inode interface must be implemented by structs representing ext inodes.
// The inode stores all the metadata pertaining to the file (except for the
// file name which is held by the directory entry). It does NOT expose all
// fields and should be extended if need be.
//
// Some file systems (e.g. FAT) use the directory entry to store all this
// information. Ext file systems do not so that they can support hard links.
// However, ext4 cheats a little bit and duplicates the file type in the
// directory entry for performance gains.
//
// See https://www.kernel.org/doc/html/latest/filesystems/ext4/dynamic.html#index-nodes.
type Inode interface {
	// Mode returns the linux file mode which is majorly used to extract
	// information like:
	// - File permissions (read/write/execute by user/group/others).
	// - Sticky, set UID and GID bits.
	// - File type.
	//
	// Masks to extract this information are provided in pkg/abi/linux/file.go.
	Mode() linux.FileMode

	// UID returns the owner UID.
	UID() auth.KUID

	// GID returns the owner GID.
	GID() auth.KGID

	// Size returns the size of the file in bytes.
	Size() uint64

	// InodeSize returns the size of this inode struct in bytes.
	// In ext2 and ext3, the inode struct and inode disk record size was fixed at
	// 128 bytes. Ext4 makes it possible for the inode struct to be bigger.
	// However, accessing any field beyond the 128 bytes marker must be verified
	// using this method.
	InodeSize() uint16

	// AccessTime returns the last access time. Shows when the file was last read.
	//
	// If InExtendedAttr is set, then this should NOT be used because the
	// underlying field is used to store the extended attribute value checksum.
	AccessTime() time.Time

	// ChangeTime returns the last change time. Shows when the file meta data
	// (like permissions) was last changed.
	//
	// If InExtendedAttr is set, then this should NOT be used because the
	// underlying field is used to store the lower 32 bits of the attribute
	// value’s reference count.
	ChangeTime() time.Time

	// ModificationTime returns the last modification time. Shows when the file
	// content was last modified.
	//
	// If InExtendedAttr is set, then this should NOT be used because
	// the underlying field contains the number of the inode that owns the
	// extended attribute.
	ModificationTime() time.Time

	// DeletionTime returns the deletion time. Inodes are marked as deleted by
	// writing to the underlying field. FS tools can restore files until they are
	// actually overwritten.
	DeletionTime() time.Time

	// LinksCount returns the number of hard links to this inode.
	//
	// Normally there is an upper limit on the number of hard links:
	//   - ext2/ext3 = 32,000
	//   - ext4      = 65,000
	//
	// This implies that an ext4 directory cannot have more than 64,998
	// subdirectories because each subdirectory will have a hard link to the
	// directory via the `..` entry. The directory has hard link via the `.` entry
	// of its own. And finally the inode is initiated with 1 hard link (itself).
	//
	// The underlying value is reset to 1 if all the following hold:
	//     - Inode is a directory.
	//     - SbDirNlink is enabled.
	//     - Number of hard links is incremented past 64,999.
	// Hard link value of 1 for a directory would indicate that the number of hard
	// links is unknown because a directory can have minimum 2 hard links (itself
	// and `.` entry).
	LinksCount() uint16

	// Flags returns InodeFlags which represents the inode flags.
	Flags() InodeFlags

	// Data returns the underlying inode.i_block array as a slice so it's
	// modifiable. This field is special and is used to store various kinds of
	// things depending on the filesystem version and inode type. The underlying
	// field name in Linux is a little misleading.
	//   - In ext2/ext3, it contains the block map.
	//   - In ext4, it contains the extent tree root node.
	//   - For inline files, it contains the file contents.
	//   - For symlinks, it contains the link path (if it fits here).
	//
	// See https://www.kernel.org/doc/html/latest/filesystems/ext4/dynamic.html#the-contents-of-inode-i-block.
	Data() []byte
}

// Inode flags. This is not comprehensive and flags which were not used in
// the Linux kernel have been excluded.
const (
	// InSync indicates that all writes to the file must be synchronous.
	InSync = 0x8

	// InImmutable indicates that this file is immutable.
	InImmutable = 0x10

	// InAppend indicates that this file can only be appended to.
	InAppend = 0x20

	// InNoDump indicates that teh dump(1) utility should not dump this file.
	InNoDump = 0x40

	// InNoAccessTime indicates that the access time of this inode must not be
	// updated.
	InNoAccessTime = 0x80

	// InIndex indicates that this directory has hashed indexes.
	InIndex = 0x1000

	// InJournalData indicates that file data must always be written through a
	// journal device.
	InJournalData = 0x4000

	// InDirSync indicates that all the directory entiry data must be written
	// synchronously.
	InDirSync = 0x10000

	// InTopDir indicates that this inode is at the top of the directory hierarchy.
	InTopDir = 0x20000

	// InHugeFile indicates that this is a huge file.
	InHugeFile = 0x40000

	// InExtents indicates that this inode uses extents.
	InExtents = 0x80000

	// InExtendedAttr indicates that this inode stores a large extended attribute
	// value in its data blocks.
	InExtendedAttr = 0x200000

	// InInline indicates that this inode has inline data.
	InInline = 0x10000000

	// InReserved indicates that this inode is reserved for the ext4 library.
	InReserved = 0x80000000
)

// InodeFlags represents all possible combinations of inode flags. It aims to
// cover the bit masks and provide a more user-friendly interface.
type InodeFlags struct {
	Sync         bool
	Immutable    bool
	Append       bool
	NoDump       bool
	NoAccessTime bool
	Index        bool
	JournalData  bool
	DirSync      bool
	TopDir       bool
	HugeFile     bool
	Extents      bool
	ExtendedAttr bool
	Inline       bool
	Reserved     bool
}

// ToInt converts inode flags back to its 32-bit rep.
func (f InodeFlags) ToInt() uint32 {
	var res uint32

	if f.Sync {
		res |= InSync
	}
	if f.Immutable {
		res |= InImmutable
	}
	if f.Append {
		res |= InAppend
	}
	if f.NoDump {
		res |= InNoDump
	}
	if f.NoAccessTime {
		res |= InNoAccessTime
	}
	if f.Index {
		res |= InIndex
	}
	if f.JournalData {
		res |= InJournalData
	}
	if f.DirSync {
		res |= InDirSync
	}
	if f.TopDir {
		res |= InTopDir
	}
	if f.HugeFile {
		res |= InHugeFile
	}
	if f.Extents {
		res |= InExtents
	}
	if f.ExtendedAttr {
		res |= InExtendedAttr
	}
	if f.Inline {
		res |= InInline
	}
	if f.Reserved {
		res |= InReserved
	}

	return res
}

// InodeFlagsFromInt converts the integer representation of inode flags to
// a InodeFlags struct.
func InodeFlagsFromInt(f uint32) InodeFlags {
	return InodeFlags{
		Sync:         f&InSync > 0,
		Immutable:    f&InImmutable > 0,
		Append:       f&InAppend > 0,
		NoDump:       f&InNoDump > 0,
		NoAccessTime: f&InNoAccessTime > 0,
		Index:        f&InIndex > 0,
		JournalData:  f&InJournalData > 0,
		DirSync:      f&InDirSync > 0,
		TopDir:       f&InTopDir > 0,
		HugeFile:     f&InHugeFile > 0,
		Extents:      f&InExtents > 0,
		ExtendedAttr: f&InExtendedAttr > 0,
		Inline:       f&InInline > 0,
		Reserved:     f&InReserved > 0,
	}
}

// These masks define how users can view/modify inode flags. The rest of the
// flags are for internal kernel usage only.
const (
	InUserReadFlagMask  = 0x4BDFFF
	InUserWriteFlagMask = 0x4B80FF
)
