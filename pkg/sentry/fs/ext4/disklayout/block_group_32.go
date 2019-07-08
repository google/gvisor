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

// BlockGroup32Bit emulates the first half of struct ext4_group_desc in
// fs/ext4/ext4.h. It is the block group descriptor struct for ext2, ext3 and
// 32-bit ext4 filesystems. It implements BlockGroup interface.
type BlockGroup32Bit struct {
	BlockBitmapLo         uint32
	InodeBitmapLo         uint32
	InodeTableLo          uint32
	FreeBlocksCountLo     uint16
	FreeInodesCountLo     uint16
	UsedDirsCountLo       uint16
	FlagsRaw              uint16
	ExcludeBitmapLo       uint32
	BlockBitmapChecksumLo uint16
	InodeBitmapChecksumLo uint16
	ItableUnusedLo        uint16
	ChecksumRaw           uint16
}

// Compiles only if BlockGroup32Bit implements BlockGroup.
var _ BlockGroup = (*BlockGroup32Bit)(nil)

// InodeTable implements BlockGroup.InodeTable.
func (bg *BlockGroup32Bit) InodeTable() uint64 { return uint64(bg.InodeTableLo) }

// BlockBitmap implements BlockGroup.BlockBitmap.
func (bg *BlockGroup32Bit) BlockBitmap() uint64 { return uint64(bg.BlockBitmapLo) }

// InodeBitmap implements BlockGroup.InodeBitmap.
func (bg *BlockGroup32Bit) InodeBitmap() uint64 { return uint64(bg.InodeBitmapLo) }

// ExclusionBitmap implements BlockGroup.ExclusionBitmap.
func (bg *BlockGroup32Bit) ExclusionBitmap() uint64 { return uint64(bg.ExcludeBitmapLo) }

// FreeBlocksCount implements BlockGroup.FreeBlocksCount.
func (bg *BlockGroup32Bit) FreeBlocksCount() uint32 { return uint32(bg.FreeBlocksCountLo) }

// FreeInodesCount implements BlockGroup.FreeInodesCount.
func (bg *BlockGroup32Bit) FreeInodesCount() uint32 { return uint32(bg.FreeInodesCountLo) }

// DirectoryCount implements BlockGroup.DirectoryCount.
func (bg *BlockGroup32Bit) DirectoryCount() uint32 { return uint32(bg.UsedDirsCountLo) }

// UnusedInodeCount implements BlockGroup.UnusedInodeCount.
func (bg *BlockGroup32Bit) UnusedInodeCount() uint32 { return uint32(bg.ItableUnusedLo) }

// BlockBitmapChecksum implements BlockGroup.BlockBitmapChecksum.
func (bg *BlockGroup32Bit) BlockBitmapChecksum() uint32 { return uint32(bg.BlockBitmapChecksumLo) }

// InodeBitmapChecksum implements BlockGroup.InodeBitmapChecksum.
func (bg *BlockGroup32Bit) InodeBitmapChecksum() uint32 { return uint32(bg.InodeBitmapChecksumLo) }

// Checksum implements BlockGroup.Checksum.
func (bg *BlockGroup32Bit) Checksum() uint16 { return bg.ChecksumRaw }

// Flags implements BlockGroup.Flags.
func (bg *BlockGroup32Bit) Flags() BGFlags { return BGFlagsFromInt(bg.FlagsRaw) }
