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

// BlockGroup represents a Linux ext block group descriptor. An ext file system
// is split into a series of block groups. This provides an access layer to
// information needed to access and use a block group.
//
// See https://www.kernel.org/doc/html/latest/filesystems/ext4/globals.html#block-group-descriptors.
type BlockGroup interface {
	// InodeTable returns the absolute block number of the block containing the
	// inode table. This points to an array of Inode structs. Inode tables are
	// statically allocated at mkfs time. The superblock records the number of
	// inodes per group (length of this table) and the size of each inode struct.
	InodeTable() uint64

	// BlockBitmap returns the absolute block number of the block containing the
	// block bitmap. This bitmap tracks the usage of data blocks within this block
	// group and has its own checksum.
	BlockBitmap() uint64

	// InodeBitmap returns the absolute block number of the block containing the
	// inode bitmap. This bitmap tracks the usage of this group's inode table
	// entries and has its own checksum.
	InodeBitmap() uint64

	// ExclusionBitmap returns the absolute block number of the snapshot exclusion
	// bitmap.
	ExclusionBitmap() uint64

	// FreeBlocksCount returns the number of free blocks in the group.
	FreeBlocksCount() uint32

	// FreeInodesCount returns the number of free inodes in the group.
	FreeInodesCount() uint32

	// DirectoryCount returns the number of inodes that represent directories
	// under this block group.
	DirectoryCount() uint32

	// UnusedInodeCount returns the number of unused inodes beyond the last used
	// inode in this group's inode table. As a result, we needn’t scan past the
	// (InodesPerGroup - UnusedInodeCount())th entry in the inode table.
	UnusedInodeCount() uint32

	// BlockBitmapChecksum returns the block bitmap checksum. This is calculated
	// using crc32c(FS UUID + group number + entire bitmap).
	BlockBitmapChecksum() uint32

	// InodeBitmapChecksum returns the inode bitmap checksum. This is calculated
	// using crc32c(FS UUID + group number + entire bitmap).
	InodeBitmapChecksum() uint32

	// Checksum returns this block group's checksum.
	//
	// If SbMetadataCsum feature is set:
	//     - checksum is crc32c(FS UUID + group number + group descriptor
	//       structure) & 0xFFFF.
	//
	// If SbGdtCsum feature is set:
	//     - checksum is crc16(FS UUID + group number + group descriptor
	//       structure).
	//
	// SbMetadataCsum and SbGdtCsum should not be both set.
	// If they are, Linux warns and asks to run fsck.
	Checksum() uint16

	// Flags returns BGFlags which represents the block group flags.
	Flags() BGFlags
}

// These are the different block group flags.
const (
	// BgInodeUninit indicates that inode table and bitmap are not initialized.
	BgInodeUninit uint16 = 0x1

	// BgBlockUninit indicates that block bitmap is not initialized.
	BgBlockUninit uint16 = 0x2

	// BgInodeZeroed indicates that inode table is zeroed.
	BgInodeZeroed uint16 = 0x4
)

// BGFlags represents all the different combinations of block group flags.
type BGFlags struct {
	InodeUninit bool
	BlockUninit bool
	InodeZeroed bool
}

// ToInt converts a BGFlags struct back to its 16-bit representation.
func (f BGFlags) ToInt() uint16 {
	var res uint16

	if f.InodeUninit {
		res |= BgInodeUninit
	}
	if f.BlockUninit {
		res |= BgBlockUninit
	}
	if f.InodeZeroed {
		res |= BgInodeZeroed
	}

	return res
}

// BGFlagsFromInt converts the 16-bit flag representation to a BGFlags struct.
func BGFlagsFromInt(flags uint16) BGFlags {
	return BGFlags{
		InodeUninit: flags&BgInodeUninit > 0,
		BlockUninit: flags&BgBlockUninit > 0,
		InodeZeroed: flags&BgInodeZeroed > 0,
	}
}
