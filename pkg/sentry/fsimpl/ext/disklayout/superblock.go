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

const (
	// SbOffset is the absolute offset at which the superblock is placed.
	SbOffset = 1024
)

// SuperBlock should be implemented by structs representing the ext superblock.
// The superblock holds a lot of information about the enclosing filesystem.
// This interface aims to provide access methods to important information held
// by the superblock. It does NOT expose all fields of the superblock, only the
// ones necessary. This can be expanded when need be.
//
// Location and replication:
//     - The superblock is located at offset 1024 in block group 0.
//     - Redundant copies of the superblock and group descriptors are kept in
//       all groups if SbSparse feature flag is NOT set. If it is set, the
//       replicas only exist in groups whose group number is either 0 or a
//       power of 3, 5, or 7.
//     - There is also a sparse superblock feature v2 in which there are just
//       two replicas saved in the block groups pointed by sb.s_backup_bgs.
//
// Replicas should eventually be updated if the superblock is updated.
//
// See https://www.kernel.org/doc/html/latest/filesystems/ext4/globals.html#super-block.
type SuperBlock interface {
	// InodesCount returns the total number of inodes in this filesystem.
	InodesCount() uint32

	// BlocksCount returns the total number of data blocks in this filesystem.
	BlocksCount() uint64

	// FreeBlocksCount returns the number of free blocks in this filesystem.
	FreeBlocksCount() uint64

	// FreeInodesCount returns the number of free inodes in this filesystem.
	FreeInodesCount() uint32

	// MountCount returns the number of mounts since the last fsck.
	MountCount() uint16

	// MaxMountCount returns the number of mounts allowed beyond which a fsck is
	// needed.
	MaxMountCount() uint16

	// FirstDataBlock returns the absolute block number of the first data block,
	// which contains the super block itself.
	//
	// If the filesystem has 1kb data blocks then this should return 1. For all
	// other configurations, this typically returns 0.
	FirstDataBlock() uint32

	// BlockSize returns the size of one data block in this filesystem.
	// This can be calculated by 2^(10 + sb.s_log_block_size). This ensures that
	// the smallest block size is 1kb.
	BlockSize() uint64

	// BlocksPerGroup returns the number of data blocks in a block group.
	BlocksPerGroup() uint32

	// ClusterSize returns block cluster size (set during mkfs time by admin).
	// This can be calculated by 2^(10 + sb.s_log_cluster_size). This ensures that
	// the smallest cluster size is 1kb.
	//
	// sb.s_log_cluster_size must equal sb.s_log_block_size if bigalloc feature
	// is NOT set and consequently BlockSize() = ClusterSize() in that case.
	ClusterSize() uint64

	// ClustersPerGroup returns:
	//     - number of clusters per group        if bigalloc is enabled.
	//     - BlocksPerGroup()                    otherwise.
	ClustersPerGroup() uint32

	// InodeSize returns the size of the inode disk record size in bytes. Use this
	// to iterate over inode arrays on disk.
	//
	// In ext2 and ext3:
	//     - Each inode had a disk record of 128 bytes.
	//     - The inode struct size was fixed at 128 bytes.
	//
	// In ext4 its possible to allocate larger on-disk inodes:
	//     - Inode disk record size = sb.s_inode_size (function return value).
	//                              = 256 (default)
	//     - Inode struct size = 128 + inode.i_extra_isize.
	//                         = 128 + 32 = 160 (default)
	InodeSize() uint16

	// InodesPerGroup returns the number of inodes in a block group.
	InodesPerGroup() uint32

	// BgDescSize returns the size of the block group descriptor struct.
	//
	// In ext2, ext3, ext4 (without 64-bit feature), the block group descriptor
	// is only 32 bytes long.
	// In ext4 with 64-bit feature, the block group descriptor expands to AT LEAST
	// 64 bytes. It might be bigger than that.
	BgDescSize() uint16

	// CompatibleFeatures returns the CompatFeatures struct which holds all the
	// compatible features this fs supports.
	CompatibleFeatures() CompatFeatures

	// IncompatibleFeatures returns the CompatFeatures struct which holds all the
	// incompatible features this fs supports.
	IncompatibleFeatures() IncompatFeatures

	// ReadOnlyCompatibleFeatures returns the CompatFeatures struct which holds all the
	// readonly compatible features this fs supports.
	ReadOnlyCompatibleFeatures() RoCompatFeatures

	// Magic() returns the magic signature which must be 0xef53.
	Magic() uint16

	// Revision returns the superblock revision. Superblock struct fields from
	// offset 0x54 till 0x150 should only be used if superblock has DynamicRev.
	Revision() SbRevision
}

// SbRevision is the type for superblock revisions.
type SbRevision uint32

// Super block revisions.
const (
	// OldRev is the good old (original) format.
	OldRev SbRevision = 0

	// DynamicRev is v2 format w/ dynamic inode sizes.
	DynamicRev SbRevision = 1
)

// Superblock compatible features.
// This is not exhaustive, unused features are not listed.
const (
	// SbDirPrealloc indicates directory preallocation.
	SbDirPrealloc = 0x1

	// SbHasJournal indicates the presence of a journal. jbd2 should only work
	// with this being set.
	SbHasJournal = 0x4

	// SbExtAttr indicates extended attributes support.
	SbExtAttr = 0x8

	// SbResizeInode indicates that the fs has reserved GDT blocks (right after
	// group descriptors) for fs expansion.
	SbResizeInode = 0x10

	// SbDirIndex indicates that the fs has directory indices.
	SbDirIndex = 0x20

	// SbSparseV2 stands for Sparse superblock version 2.
	SbSparseV2 = 0x200
)

// CompatFeatures represents a superblock's compatible feature set. If the
// kernel does not understand any of these feature, it can still read/write
// to this fs.
type CompatFeatures struct {
	DirPrealloc bool
	HasJournal  bool
	ExtAttr     bool
	ResizeInode bool
	DirIndex    bool
	SparseV2    bool
}

// ToInt converts superblock compatible features back to its 32-bit rep.
func (f CompatFeatures) ToInt() uint32 {
	var res uint32

	if f.DirPrealloc {
		res |= SbDirPrealloc
	}
	if f.HasJournal {
		res |= SbHasJournal
	}
	if f.ExtAttr {
		res |= SbExtAttr
	}
	if f.ResizeInode {
		res |= SbResizeInode
	}
	if f.DirIndex {
		res |= SbDirIndex
	}
	if f.SparseV2 {
		res |= SbSparseV2
	}

	return res
}

// CompatFeaturesFromInt converts the integer representation of superblock
// compatible features to CompatFeatures struct.
func CompatFeaturesFromInt(f uint32) CompatFeatures {
	return CompatFeatures{
		DirPrealloc: f&SbDirPrealloc > 0,
		HasJournal:  f&SbHasJournal > 0,
		ExtAttr:     f&SbExtAttr > 0,
		ResizeInode: f&SbResizeInode > 0,
		DirIndex:    f&SbDirIndex > 0,
		SparseV2:    f&SbSparseV2 > 0,
	}
}

// Superblock incompatible features.
// This is not exhaustive, unused features are not listed.
const (
	// SbDirentFileType indicates that directory entries record the file type.
	// We should use struct DirentNew for dirents then.
	SbDirentFileType = 0x2

	// SbRecovery indicates that the filesystem needs recovery.
	SbRecovery = 0x4

	// SbJournalDev indicates that the filesystem has a separate journal device.
	SbJournalDev = 0x8

	// SbMetaBG indicates that the filesystem is using Meta block groups. Moves
	// the group descriptors from the congested first block group into the first
	// group of each metablock group to increase the maximum block groups limit
	// and hence support much larger filesystems.
	//
	// See https://www.kernel.org/doc/html/latest/filesystems/ext4/overview.html#meta-block-groups.
	SbMetaBG = 0x10

	// SbExtents indicates that the filesystem uses extents. Must be set in ext4
	// filesystems.
	SbExtents = 0x40

	// SbIs64Bit indicates that this filesystem addresses blocks with 64-bits.
	// Hence can support 2^64 data blocks.
	SbIs64Bit = 0x80

	// SbMMP indicates that this filesystem has multiple mount protection.
	//
	// See https://www.kernel.org/doc/html/latest/filesystems/ext4/globals.html#multiple-mount-protection.
	SbMMP = 0x100

	// SbFlexBg indicates that this filesystem has flexible block groups. Several
	// block groups are tied into one logical block group so that all the metadata
	// for the block groups (bitmaps and inode tables) are close together for
	// faster loading. Consequently, large files will be continuous on disk.
	// However, this does not affect the placement of redundant superblocks and
	// group descriptors.
	//
	// See https://www.kernel.org/doc/html/latest/filesystems/ext4/overview.html#flexible-block-groups.
	SbFlexBg = 0x200

	// SbLargeDir shows that large directory enabled. Directory htree can be 3
	// levels deep. Directory htrees are allowed to be 2 levels deep otherwise.
	SbLargeDir = 0x4000

	// SbInlineData allows inline data in inodes for really small files.
	SbInlineData = 0x8000

	// SbEncrypted indicates that this fs contains encrypted inodes.
	SbEncrypted = 0x10000
)

// IncompatFeatures represents a superblock's incompatible feature set. If the
// kernel does not understand any of these feature, it should refuse to mount.
type IncompatFeatures struct {
	DirentFileType bool
	Recovery       bool
	JournalDev     bool
	MetaBG         bool
	Extents        bool
	Is64Bit        bool
	MMP            bool
	FlexBg         bool
	LargeDir       bool
	InlineData     bool
	Encrypted      bool
}

// ToInt converts superblock incompatible features back to its 32-bit rep.
func (f IncompatFeatures) ToInt() uint32 {
	var res uint32

	if f.DirentFileType {
		res |= SbDirentFileType
	}
	if f.Recovery {
		res |= SbRecovery
	}
	if f.JournalDev {
		res |= SbJournalDev
	}
	if f.MetaBG {
		res |= SbMetaBG
	}
	if f.Extents {
		res |= SbExtents
	}
	if f.Is64Bit {
		res |= SbIs64Bit
	}
	if f.MMP {
		res |= SbMMP
	}
	if f.FlexBg {
		res |= SbFlexBg
	}
	if f.LargeDir {
		res |= SbLargeDir
	}
	if f.InlineData {
		res |= SbInlineData
	}
	if f.Encrypted {
		res |= SbEncrypted
	}

	return res
}

// IncompatFeaturesFromInt converts the integer representation of superblock
// incompatible features to IncompatFeatures struct.
func IncompatFeaturesFromInt(f uint32) IncompatFeatures {
	return IncompatFeatures{
		DirentFileType: f&SbDirentFileType > 0,
		Recovery:       f&SbRecovery > 0,
		JournalDev:     f&SbJournalDev > 0,
		MetaBG:         f&SbMetaBG > 0,
		Extents:        f&SbExtents > 0,
		Is64Bit:        f&SbIs64Bit > 0,
		MMP:            f&SbMMP > 0,
		FlexBg:         f&SbFlexBg > 0,
		LargeDir:       f&SbLargeDir > 0,
		InlineData:     f&SbInlineData > 0,
		Encrypted:      f&SbEncrypted > 0,
	}
}

// Superblock readonly compatible features.
// This is not exhaustive, unused features are not listed.
const (
	// SbSparse indicates sparse superblocks. Only groups with number either 0 or
	// a power of 3, 5, or 7 will have redundant copies of the superblock and
	// block descriptors.
	SbSparse = 0x1

	// SbLargeFile indicates that this fs has been used to store a file >= 2GiB.
	SbLargeFile = 0x2

	// SbHugeFile indicates that this fs contains files whose sizes are
	// represented in units of logicals blocks, not 512-byte sectors.
	SbHugeFile = 0x8

	// SbGdtCsum indicates that group descriptors have checksums.
	SbGdtCsum = 0x10

	// SbDirNlink indicates that the new subdirectory limit is 64,999. Ext3 has a
	// 32,000 subdirectory limit.
	SbDirNlink = 0x20

	// SbExtraIsize indicates that large inodes exist on this filesystem.
	SbExtraIsize = 0x40

	// SbHasSnapshot indicates the existence of a snapshot.
	SbHasSnapshot = 0x80

	// SbQuota enables usage tracking for all quota types.
	SbQuota = 0x100

	// SbBigalloc maps to the bigalloc feature. When set, the minimum allocation
	// unit becomes a cluster rather than a data block. Then block bitmaps track
	// clusters, not data blocks.
	//
	// See https://www.kernel.org/doc/html/latest/filesystems/ext4/overview.html#bigalloc.
	SbBigalloc = 0x200

	// SbMetadataCsum indicates that the fs supports metadata checksumming.
	SbMetadataCsum = 0x400

	// SbReadOnly marks this filesystem as readonly. Should refuse to mount in
	// read/write mode.
	SbReadOnly = 0x1000
)

// RoCompatFeatures represents a superblock's readonly compatible feature set.
// If the kernel does not understand any of these feature, it can still mount
// readonly. But if the user wants to mount read/write, the kernel should
// refuse to mount.
type RoCompatFeatures struct {
	Sparse       bool
	LargeFile    bool
	HugeFile     bool
	GdtCsum      bool
	DirNlink     bool
	ExtraIsize   bool
	HasSnapshot  bool
	Quota        bool
	Bigalloc     bool
	MetadataCsum bool
	ReadOnly     bool
}

// ToInt converts superblock readonly compatible features to its 32-bit rep.
func (f RoCompatFeatures) ToInt() uint32 {
	var res uint32

	if f.Sparse {
		res |= SbSparse
	}
	if f.LargeFile {
		res |= SbLargeFile
	}
	if f.HugeFile {
		res |= SbHugeFile
	}
	if f.GdtCsum {
		res |= SbGdtCsum
	}
	if f.DirNlink {
		res |= SbDirNlink
	}
	if f.ExtraIsize {
		res |= SbExtraIsize
	}
	if f.HasSnapshot {
		res |= SbHasSnapshot
	}
	if f.Quota {
		res |= SbQuota
	}
	if f.Bigalloc {
		res |= SbBigalloc
	}
	if f.MetadataCsum {
		res |= SbMetadataCsum
	}
	if f.ReadOnly {
		res |= SbReadOnly
	}

	return res
}

// RoCompatFeaturesFromInt converts the integer representation of superblock
// readonly compatible features to RoCompatFeatures struct.
func RoCompatFeaturesFromInt(f uint32) RoCompatFeatures {
	return RoCompatFeatures{
		Sparse:       f&SbSparse > 0,
		LargeFile:    f&SbLargeFile > 0,
		HugeFile:     f&SbHugeFile > 0,
		GdtCsum:      f&SbGdtCsum > 0,
		DirNlink:     f&SbDirNlink > 0,
		ExtraIsize:   f&SbExtraIsize > 0,
		HasSnapshot:  f&SbHasSnapshot > 0,
		Quota:        f&SbQuota > 0,
		Bigalloc:     f&SbBigalloc > 0,
		MetadataCsum: f&SbMetadataCsum > 0,
		ReadOnly:     f&SbReadOnly > 0,
	}
}
