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

// SuperBlock64Bit implements SuperBlock and represents the 64-bit version of
// the ext4_super_block struct in fs/ext4/ext4.h. This sums up to be exactly
// 1024 bytes (smallest possible block size) and hence the superblock always
// fits in no more than one data block. Should only be used when the 64-bit
// feature is set.
type SuperBlock64Bit struct {
	// We embed the 32-bit struct here because 64-bit version is just an extension
	// of the 32-bit version.
	SuperBlock32Bit

	BlocksCountHi           uint32
	ReservedBlocksCountHi   uint32
	FreeBlocksCountHi       uint32
	MinInodeSize            uint16
	WantInodeSize           uint16
	Flags                   uint32
	RaidStride              uint16
	MmpInterval             uint16
	MmpBlock                uint64
	RaidStripeWidth         uint32
	LogGroupsPerFlex        uint8
	ChecksumType            uint8
	_                       uint16
	KbytesWritten           uint64
	SnapshotInum            uint32
	SnapshotID              uint32
	SnapshotRsrvBlocksCount uint64
	SnapshotList            uint32
	ErrorCount              uint32
	FirstErrorTime          uint32
	FirstErrorInode         uint32
	FirstErrorBlock         uint64
	FirstErrorFunction      [32]byte
	FirstErrorLine          uint32
	LastErrorTime           uint32
	LastErrorInode          uint32
	LastErrorLine           uint32
	LastErrorBlock          uint64
	LastErrorFunction       [32]byte
	MountOpts               [64]byte
	UserQuotaInum           uint32
	GroupQuotaInum          uint32
	OverheadBlocks          uint32
	BackupBgs               [2]uint32
	EncryptAlgos            [4]uint8
	EncryptPwSalt           [16]uint8
	LostFoundInode          uint32
	ProjectQuotaInode       uint32
	ChecksumSeed            uint32
	WtimeHi                 uint8
	MtimeHi                 uint8
	MkfsTimeHi              uint8
	LastCheckHi             uint8
	FirstErrorTimeHi        uint8
	LastErrorTimeHi         uint8
	_                       [2]uint8
	Encoding                uint16
	EncodingFlags           uint16
	_                       [95]uint32
	Checksum                uint32
}

// Compiles only if SuperBlock64Bit implements SuperBlock.
var _ SuperBlock = (*SuperBlock64Bit)(nil)

// Only override methods which change based on the 64-bit feature.

// BlocksCount implements SuperBlock.BlocksCount.
func (sb *SuperBlock64Bit) BlocksCount() uint64 {
	return (uint64(sb.BlocksCountHi) << 32) | uint64(sb.BlocksCountLo)
}

// FreeBlocksCount implements SuperBlock.FreeBlocksCount.
func (sb *SuperBlock64Bit) FreeBlocksCount() uint64 {
	return (uint64(sb.FreeBlocksCountHi) << 32) | uint64(sb.FreeBlocksCountLo)
}

// BgDescSize implements SuperBlock.BgDescSize.
func (sb *SuperBlock64Bit) BgDescSize() uint16 { return sb.BgDescSizeRaw }
