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

// BlockGroup64Bit emulates struct ext4_group_desc in fs/ext4/ext4.h.
// It is the block group descriptor struct for 64-bit ext4 filesystems.
// It implements BlockGroup interface. It is an extension of the 32-bit
// version of BlockGroup.
//
// The suffix `Hi` here stands for upper bits because they represent the upper
// half of the fields.
type BlockGroup64Bit struct {
	// We embed the 32-bit struct here because 64-bit version is just an extension
	// of the 32-bit version.
	BlockGroup32Bit

	// 64-bit specific fields.
	BlockBitmapHi         uint32
	InodeBitmapHi         uint32
	InodeTableHi          uint32
	FreeBlocksCountHi     uint16
	FreeInodesCountHi     uint16
	UsedDirsCountHi       uint16
	ItableUnusedHi        uint16
	ExcludeBitmapHi       uint32
	BlockBitmapChecksumHi uint16
	InodeBitmapChecksumHi uint16
	_                     uint32 // Padding to 64 bytes.
}

// Methods to override. Checksum() and Flags() are not overridden.

// InodeTable implements BlockGroup.InodeTable.
func (bg *BlockGroup64Bit) InodeTable() uint64 {
	return (uint64(bg.InodeTableHi) << 32) | uint64(bg.InodeTableLo)
}

// BlockBitmap implements BlockGroup.BlockBitmap.
func (bg *BlockGroup64Bit) BlockBitmap() uint64 {
	return (uint64(bg.BlockBitmapHi) << 32) | uint64(bg.BlockBitmapLo)
}

// InodeBitmap implements BlockGroup.InodeBitmap.
func (bg *BlockGroup64Bit) InodeBitmap() uint64 {
	return (uint64(bg.InodeBitmapHi) << 32) | uint64(bg.InodeBitmapLo)
}

// ExclusionBitmap implements BlockGroup.ExclusionBitmap.
func (bg *BlockGroup64Bit) ExclusionBitmap() uint64 {
	return (uint64(bg.ExcludeBitmapHi) << 32) | uint64(bg.ExcludeBitmapLo)
}

// FreeBlocksCount implements BlockGroup.FreeBlocksCount.
func (bg *BlockGroup64Bit) FreeBlocksCount() uint32 {
	return (uint32(bg.FreeBlocksCountHi) << 16) | uint32(bg.FreeBlocksCountLo)
}

// FreeInodesCount implements BlockGroup.FreeInodesCount.
func (bg *BlockGroup64Bit) FreeInodesCount() uint32 {
	return (uint32(bg.FreeInodesCountHi) << 16) | uint32(bg.FreeInodesCountLo)
}

// DirectoryCount implements BlockGroup.DirectoryCount.
func (bg *BlockGroup64Bit) DirectoryCount() uint32 {
	return (uint32(bg.UsedDirsCountHi) << 16) | uint32(bg.UsedDirsCountLo)
}

// UnusedInodeCount implements BlockGroup.UnusedInodeCount.
func (bg *BlockGroup64Bit) UnusedInodeCount() uint32 {
	return (uint32(bg.ItableUnusedHi) << 16) | uint32(bg.ItableUnusedLo)
}

// BlockBitmapChecksum implements BlockGroup.BlockBitmapChecksum.
func (bg *BlockGroup64Bit) BlockBitmapChecksum() uint32 {
	return (uint32(bg.BlockBitmapChecksumHi) << 16) | uint32(bg.BlockBitmapChecksumLo)
}

// InodeBitmapChecksum implements BlockGroup.InodeBitmapChecksum.
func (bg *BlockGroup64Bit) InodeBitmapChecksum() uint32 {
	return (uint32(bg.InodeBitmapChecksumHi) << 16) | uint32(bg.InodeBitmapChecksumLo)
}
