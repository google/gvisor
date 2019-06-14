package goext4

import (
	"fmt"
	"io"
	"strconv"

	"encoding/binary"
)

const (
	// BlockGroupDescriptorSize is EXT4_MIN_DESC_SIZE_64BIT in /fs/ext4/ext4.h .
	BlockGroupDescriptorSize = 64
)

const (
	// BgdFlagInodeTableAndBitmapNotInitialized indicates that inode table/bitmap is not in use.
	BgdFlagInodeTableAndBitmapNotInitialized = uint16(0x1)
	// BgdFlagBitmapNotInitialized indicates that block bitmap is not in use.
	BgdFlagBitmapNotInitialized = uint16(0x2)
	// BgdFlagInodeTableZeroed indicates that the on-disk itable is initialized to zero.
	BgdFlagInodeTableZeroed = uint16(0x4)
)

// BlockGroupDescriptorData is the structure of a blocks group descriptor
type BlockGroupDescriptorData struct {
	BgBlockBitmapLo     uint32 /* Blocks bitmap block */
	BgInodeBitmapLo     uint32 /* Inodes bitmap block */
	BgInodeTableLo      uint32 /* Inodes table block */
	BgFreeBlocksCountLo uint16 /* Free blocks count */
	BgFreeInodesCountLo uint16 /* Free inodes count */
	BgUsedDirsCountLo   uint16 /* Directories count */
	BgFlags             uint16 /* EXT4_BG_flags (INODE_UNINIT, etc) */
	BgExcludeBitmapLo   uint32 /* Lower 32-bits of location of snapshot exclusion bitmap. */
	BgBlockBitmapCsumLo uint16 /* Lower 16-bits of the block bitmap checksum. */
	BgInodeBitmapCsumLo uint16 /* Lower 16-bits of the inode bitmap checksum. */
	BgItableUnusedLo    uint16 /* Unused inodes count */
	BgChecksum          uint16 /* crc16(sb_uuid+group+desc) */
	BgBlockBitmapHi     uint32 /* Blocks bitmap block MSB */
	BgInodeBitmapHi     uint32 /* Inodes bitmap block MSB */
	BgInodeTableHi      uint32 /* Inodes table block MSB */
	BgFreeBlocksCountHi uint16 /* Free blocks count MSB */
	BgFreeInodesCountHi uint16 /* Free inodes count MSB */
	BgUsedDirsCountHi   uint16 /* Directories count MSB */
	BgItableUnusedHi    uint16 /* Unused inodes count MSB */
	BgExcludeBitmapHi   uint32 /* Upper 32-bits of location of snapshot exclusion bitmap. */
	BgBlockBitmapCsumHi uint16 /* Upper 16-bits of the block bitmap checksum. */
	BgInodeBitmapCsumHi uint16 /* Upper 16-bits of the inode bitmap checksum. */
	BgReserved2         uint32 /* Padding to 64 bytes. */
}

// BlockGroupDescriptor holds pointers to the fs superblock and block descriptor data
type BlockGroupDescriptor struct {
	data *BlockGroupDescriptorData
	sb   *Superblock
}

// NewBlockGroupDescriptorWithReader reads a Block Descriptor using the
// io.Reader object. Expects the io.Reader to positioned correctly.
func NewBlockGroupDescriptorWithReader(r io.Reader, sb *Superblock) (bgd *BlockGroupDescriptor, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = WrapError(state)
		}
	}()

	bgdd := new(BlockGroupDescriptorData)

	err = binary.Read(r, binary.LittleEndian, bgdd)
	if err != nil {
		panic(err)
	}

	bgd = &BlockGroupDescriptor{
		data: bgdd,
		sb:   sb,
	}

	return bgd, nil
}

// Data is a getter for BlockGroupDescriptor.data .
func (bgd *BlockGroupDescriptor) Data() *BlockGroupDescriptorData {
	return bgd.data
}

// Superblock is a getter for BlockGroupDescriptor.sb .
func (bgd *BlockGroupDescriptor) Superblock() *Superblock {
	return bgd.sb
}

// Dump prints out the BlockGroupDescriptor object contents.
func (bgd *BlockGroupDescriptor) Dump() {
	fmt.Printf("BgBlockBitmapHi: (%d)\n", bgd.data.BgBlockBitmapHi)
	fmt.Printf("BgBlockBitmapLo: (%d)\n", bgd.data.BgBlockBitmapLo)
	fmt.Printf("BgChecksum: [%04x]\n", bgd.data.BgChecksum)
	fmt.Printf("BgFlags: (%s)\n", strconv.FormatInt(int64(bgd.data.BgFlags), 2))
	fmt.Printf("BgFreeBlocksCountHi: (%d)\n", bgd.data.BgFreeBlocksCountHi)
	fmt.Printf("BgFreeBlocksCountLo: (%d)\n", bgd.data.BgFreeBlocksCountLo)
	fmt.Printf("BgFreeInodesCountHi: (%d)\n", bgd.data.BgFreeInodesCountHi)
	fmt.Printf("BgFreeInodesCountLo: (%d)\n", bgd.data.BgFreeInodesCountLo)
	fmt.Printf("BgInodeBitmapHi: (%d)\n", bgd.data.BgInodeBitmapHi)
	fmt.Printf("BgInodeBitmapLo: (%d)\n", bgd.data.BgInodeBitmapLo)
	fmt.Printf("BgInodeTableHi: (%d)\n", bgd.data.BgInodeTableHi)
	fmt.Printf("BgInodeTableLo: (%d)\n", bgd.data.BgInodeTableLo)
	fmt.Printf("BgItableUnusedHi: (%d)\n", bgd.data.BgItableUnusedHi)
	fmt.Printf("BgItableUnusedLo: (%d)\n", bgd.data.BgItableUnusedLo)
	fmt.Printf("BgUsedDirsCountHi: (%d)\n", bgd.data.BgUsedDirsCountHi)
	fmt.Printf("BgUsedDirsCountLo: (%d)\n", bgd.data.BgUsedDirsCountLo)
	fmt.Printf("BgExcludeBitmapHi: (%d)\n", bgd.data.BgExcludeBitmapHi)
	fmt.Printf("BgBlockBitmapCsumHi: (%d)\n", bgd.data.BgBlockBitmapCsumHi)
	fmt.Printf("BgInodeBitmapCsumHi: (%d)\n", bgd.data.BgInodeBitmapCsumHi)

	fmt.Printf("InodeTableBlock: (%d)\n", bgd.InodeTableBlock())
}

// IsInodeTableAndBitmapNotInitialized tells if the inode table/bitmap is not in use.
func (bgd *BlockGroupDescriptor) IsInodeTableAndBitmapNotInitialized() bool {
	return (bgd.data.BgFlags & BgdFlagInodeTableAndBitmapNotInitialized) > 0
}

// IsBitmapNotInitialized tells if the block bitmap is not in use.
func (bgd *BlockGroupDescriptor) IsBitmapNotInitialized() bool {
	return (bgd.data.BgFlags & BgdFlagBitmapNotInitialized) > 0
}

// IsInodeTableZeroed tells if the on-disk itable is initialized to zero.
func (bgd *BlockGroupDescriptor) IsInodeTableZeroed() bool {
	return (bgd.data.BgFlags & BgdFlagInodeTableZeroed) > 0
}

// InodeTableBlock returns the absolute block number of the inode-table.
func (bgd *BlockGroupDescriptor) InodeTableBlock() uint64 {
	if bgd.sb.Is64Bit() {
		return (uint64(bgd.data.BgInodeTableHi) << 32) | uint64(bgd.data.BgInodeTableLo)
	}

	return uint64(bgd.data.BgInodeTableLo)
}

// InodeBitmapBlock returns the inode's bitmap block
func (bgd *BlockGroupDescriptor) InodeBitmapBlock() uint64 {
	if bgd.sb.Is64Bit() == true {
		return (uint64(bgd.data.BgInodeBitmapHi) << 32) | uint64(bgd.data.BgInodeBitmapLo)
	}

	return uint64(bgd.data.BgInodeBitmapLo)
}
