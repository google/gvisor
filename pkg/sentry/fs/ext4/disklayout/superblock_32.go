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

// SuperBlock32Bit implements SuperBlock and represents the 32-bit version of
// the ext4_super_block struct in fs/ext4/ext4.h.
//
// The suffix `Raw` has been added to indicate that the field does not have a
// counterpart in the 64-bit version and to resolve name collision with the
// interface.
type SuperBlock32Bit struct {
	// We embed the old superblock struct here because the 32-bit version is just
	// an extension of the old version.
	SuperBlockOld

	FirstInode         uint32
	InodeSizeRaw       uint16
	BlockGroupNumber   uint16
	FeatureCompat      uint32
	FeatureIncompat    uint32
	FeatureRoCompat    uint32
	UUID               [16]byte
	VolumeName         [16]byte
	LastMounted        [64]byte
	AlgoUsageBitmap    uint32
	PreallocBlocks     uint8
	PreallocDirBlocks  uint8
	ReservedGdtBlocks  uint16
	JournalUUID        [16]byte
	JournalInum        uint32
	JournalDev         uint32
	LastOrphan         uint32
	HashSeed           [4]uint32
	DefaultHashVersion uint8
	JnlBackupType      uint8
	BgDescSizeRaw      uint16
	DefaultMountOpts   uint32
	FirstMetaBg        uint32
	MkfsTime           uint32
	JnlBlocks          [17]uint32
}

// Only override methods which change based on the additional fields above.
// Not overriding SuperBlock.BgDescSize because it would still return 32 here.

// InodeSize implements SuperBlock.InodeSize.
func (sb *SuperBlock32Bit) InodeSize() uint16 {
	return sb.InodeSizeRaw
}

// CompatibleFeatures implements SuperBlock.CompatibleFeatures.
func (sb *SuperBlock32Bit) CompatibleFeatures() CompatFeatures {
	return CompatFeaturesFromInt(sb.FeatureCompat)
}

// IncompatibleFeatures implements SuperBlock.IncompatibleFeatures.
func (sb *SuperBlock32Bit) IncompatibleFeatures() IncompatFeatures {
	return IncompatFeaturesFromInt(sb.FeatureIncompat)
}

// ReadOnlyCompatibleFeatures implements SuperBlock.ReadOnlyCompatibleFeatures.
func (sb *SuperBlock32Bit) ReadOnlyCompatibleFeatures() RoCompatFeatures {
	return RoCompatFeaturesFromInt(sb.FeatureRoCompat)
}
