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

// SuperBlockOld implements SuperBlock and represents the old version of the
// superblock struct. Should be used only if RevLevel = OldRev.
type SuperBlockOld struct {
	InodesCountRaw      uint32
	BlocksCountLo       uint32
	ReservedBlocksCount uint32
	FreeBlocksCountLo   uint32
	FreeInodesCountRaw  uint32
	FirstDataBlockRaw   uint32
	LogBlockSize        uint32
	LogClusterSize      uint32
	BlocksPerGroupRaw   uint32
	ClustersPerGroupRaw uint32
	InodesPerGroupRaw   uint32
	Mtime               uint32
	Wtime               uint32
	MountCountRaw       uint16
	MaxMountCountRaw    uint16
	MagicRaw            uint16
	State               uint16
	Errors              uint16
	MinorRevLevel       uint16
	LastCheck           uint32
	CheckInterval       uint32
	CreatorOS           uint32
	RevLevel            uint32
	DefResUID           uint16
	DefResGID           uint16
}

// Compiles only if SuperBlockOld implements SuperBlock.
var _ SuperBlock = (*SuperBlockOld)(nil)

// InodesCount implements SuperBlock.InodesCount.
func (sb *SuperBlockOld) InodesCount() uint32 { return sb.InodesCountRaw }

// BlocksCount implements SuperBlock.BlocksCount.
func (sb *SuperBlockOld) BlocksCount() uint64 { return uint64(sb.BlocksCountLo) }

// FreeBlocksCount implements SuperBlock.FreeBlocksCount.
func (sb *SuperBlockOld) FreeBlocksCount() uint64 { return uint64(sb.FreeBlocksCountLo) }

// FreeInodesCount implements SuperBlock.FreeInodesCount.
func (sb *SuperBlockOld) FreeInodesCount() uint32 { return sb.FreeInodesCountRaw }

// MountCount implements SuperBlock.MountCount.
func (sb *SuperBlockOld) MountCount() uint16 { return sb.MountCountRaw }

// MaxMountCount implements SuperBlock.MaxMountCount.
func (sb *SuperBlockOld) MaxMountCount() uint16 { return sb.MaxMountCountRaw }

// FirstDataBlock implements SuperBlock.FirstDataBlock.
func (sb *SuperBlockOld) FirstDataBlock() uint32 { return sb.FirstDataBlockRaw }

// BlockSize implements SuperBlock.BlockSize.
func (sb *SuperBlockOld) BlockSize() uint64 { return 1 << (10 + sb.LogBlockSize) }

// BlocksPerGroup implements SuperBlock.BlocksPerGroup.
func (sb *SuperBlockOld) BlocksPerGroup() uint32 { return sb.BlocksPerGroupRaw }

// ClusterSize implements SuperBlock.ClusterSize.
func (sb *SuperBlockOld) ClusterSize() uint64 { return 1 << (10 + sb.LogClusterSize) }

// ClustersPerGroup implements SuperBlock.ClustersPerGroup.
func (sb *SuperBlockOld) ClustersPerGroup() uint32 { return sb.ClustersPerGroupRaw }

// InodeSize implements SuperBlock.InodeSize.
func (sb *SuperBlockOld) InodeSize() uint16 { return OldInodeSize }

// InodesPerGroup implements SuperBlock.InodesPerGroup.
func (sb *SuperBlockOld) InodesPerGroup() uint32 { return sb.InodesPerGroupRaw }

// BgDescSize implements SuperBlock.BgDescSize.
func (sb *SuperBlockOld) BgDescSize() uint16 { return 32 }

// CompatibleFeatures implements SuperBlock.CompatibleFeatures.
func (sb *SuperBlockOld) CompatibleFeatures() CompatFeatures { return CompatFeatures{} }

// IncompatibleFeatures implements SuperBlock.IncompatibleFeatures.
func (sb *SuperBlockOld) IncompatibleFeatures() IncompatFeatures { return IncompatFeatures{} }

// ReadOnlyCompatibleFeatures implements SuperBlock.ReadOnlyCompatibleFeatures.
func (sb *SuperBlockOld) ReadOnlyCompatibleFeatures() RoCompatFeatures { return RoCompatFeatures{} }

// Magic implements SuperBlock.Magic.
func (sb *SuperBlockOld) Magic() uint16 { return sb.MagicRaw }

// Revision implements SuperBlock.Revision.
func (sb *SuperBlockOld) Revision() SbRevision { return SbRevision(sb.RevLevel) }
