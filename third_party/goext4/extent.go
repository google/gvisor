package goext4

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"math"

	"encoding/binary"
)

// See fs/ext4/ext4_extents.h .
// The contents of this file attempt to emulate linux ext4 extents.

// Constants defined in fs/ext4/ext4_extents.h .
const (
	ExtentMagic            = uint16(0xf30A)
	ExtentHeaderSize       = 12 // sizeof(ext4_extent_header)
	ExtentIndexAndLeafSize = 12
)

// ExtentHeaderNode is the header struct which is the first 12 bytes of
// i_block array in ext4_inode. Each block (leaves and indexes), even
// inode-stored has header.
type ExtentHeaderNode struct {
	EhMagic      uint16 /* probably will support different formats */
	EhEntryCount uint16 /* number of valid entries */
	EhMax        uint16 /* capacity of store in entries */
	EhDepth      uint16 /* has tree real underlying blocks? */
	EhGeneration uint32 /* generation of the tree */
}

func (eh *ExtentHeaderNode) String() string {
	return fmt.Sprintf("ExtentHeaderNode<ENTRIES=(%d) MAX=(%d) DEPTH=(%d)>", eh.EhEntryCount, eh.EhMax, eh.EhDepth)
}

// ExtentIndexNode is the index on-disk structure.
// It's used at all the levels except the bottom.
type ExtentIndexNode struct {
	EiLogicalBlock        uint32 /* index covers logical blocks from 'block' */
	EiLeafPhysicalBlockLo uint32 /* pointer to the physical block of the next level. leaf or next index could be there */
	EiLeafPhysicalBlockHi uint16 /* high 16 bits of physical block */
	EiUnused              uint16
}

// LeafPhysicalBlock combines the low and high parts of a leaf physical block
// number into a filesystem-wide blocks number.
func (ein *ExtentIndexNode) LeafPhysicalBlock() uint64 {
	return (uint64(ein.EiLeafPhysicalBlockHi) << 32) | uint64(ein.EiLeafPhysicalBlockLo)
}

func (ein *ExtentIndexNode) String() string {
	return fmt.Sprintf("ExtentIndexNode<FILE-LBLOCK=(%d) LEAF-PBLOCK=(%d)>", ein.EiLogicalBlock, ein.LeafPhysicalBlock())
}

// ExtentLeafNode is the extent on-disk structure.
// It's used at the bottom of the tree.
type ExtentLeafNode struct {
	EeFirstLogicalBlock    uint32 /* first logical block extent covers */
	EeLogicalBlockCount    uint16 /* number of blocks covered by extent */
	EeStartPhysicalBlockHi uint16 /* high 16 bits of physical block */
	EeStartPhysicalBlockLo uint32 /* low 32 bits of physical block */
}

// StartPhysicalBlock combines the low and high parts of physical block number
// into a filesystem-wide blocks number.
func (eln *ExtentLeafNode) StartPhysicalBlock() uint64 {
	return (uint64(eln.EeStartPhysicalBlockHi) << 32) | uint64(eln.EeStartPhysicalBlockLo)
}

func (eln *ExtentLeafNode) String() string {
	return fmt.Sprintf("ExtentLeafNode<FIRST-LBLOCK=(%d) LBLOCK-COUNT=(%d) START-PBLOCK=(%d)>", eln.EeFirstLogicalBlock, eln.EeLogicalBlockCount, eln.StartPhysicalBlock())
}

const (
	// ExtentChecksumTailSize is sizeof(ext4_extent_tail) in linux ext4.
	ExtentChecksumTailSize = 4
)

// ExtentTail attempts to emulate ext4_extent_tail in linux ext4.
type ExtentTail struct {
	EbChecksum uint32
}

// ExtentNavigator exposes methods to navigate an inode's data blocks
type ExtentNavigator struct {
	rs    io.ReadSeeker
	inode *Inode
}

// NewExtentNavigatorWithReadSeeker initializes ExtentNavigator
func NewExtentNavigatorWithReadSeeker(rs io.ReadSeeker, inode *Inode) *ExtentNavigator {
	return &ExtentNavigator{
		rs:    rs,
		inode: inode,
	}
}

// Read returns the inode data from the given offset to the end of the logical
// block that it's found in. User has to ensure that offset is not more than
// inode size.
//
// "logical", meaning that (0) refers to the first block of this inode's data.
func (en *ExtentNavigator) Read(offset uint64) (data []byte, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = WrapError(state)
		}
	}()

	// If the inode is not using extents, its data is stored in inode.i_block.
	if !en.inode.Flag(InodeFlagExtents) {
		if en.inode.Size() > uint64(len(en.inode.Data().IBlock)) {
			log.Panicf("Inode size is %v bytes but does not use extents", en.inode.Size())
		}

		length := en.inode.Size() - offset
		data = make([]byte, length)

		copy(data, en.inode.Data().IBlock[offset:en.inode.Size()])
		return
	}

	sb := en.inode.BlockGroupDescriptor().Superblock()

	blockSize := uint64(sb.BlockSize())
	lBlockNumber := offset / blockSize
	pBlockOffset := offset % blockSize

	inodeIblock := en.inode.Data().IBlock[:]
	pBlockNumber, err := en.parseHeader(inodeIblock, lBlockNumber, false)
	if err != nil {
		panic(err)
	}

	// We'll return whichever data we got between the offset and the end of
	// that immediate physical block.
	rawPBlockData, err := sb.ReadPhysicalBlock(pBlockNumber, blockSize)
	if err != nil {
		panic(err)
	}

	// If the inode's data stops mid-block, take just that amount.
	dataLength := uint64(math.Min(float64(en.inode.Size()-offset), float64(blockSize-pBlockOffset)))

	return rawPBlockData[pBlockOffset : pBlockOffset+dataLength], nil
}

// parseHeader parses the extent header and then recursively processes the
// array of index-nodes or array of leaf-nodes following it.
//
// `hasTailChecksum` will be true for any of the arrays of extent structs that
// we read after the first. Those are located in the inode's IBlock data,
// which is already covered by the inode checksum.
func (en *ExtentNavigator) parseHeader(extentHeaderData []byte, lBlock uint64, hasTailChecksum bool) (dataPBlock uint64, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = WrapError(state)
		}
	}()

	b := bytes.NewBuffer(extentHeaderData)

	// TODO(dustin): Pass this in as another argument and only parse if we receive a nil. Except for the first one, we'll otherwise double-parse every header struct.
	eh := new(ExtentHeaderNode)

	err = binary.Read(b, binary.LittleEndian, eh)
	if err != nil {
		panic(err)
	}

	if eh.EhMagic != ExtentMagic {
		log.Panicf("extent-header magic-bytes not correct: (%04x)", eh.EhMagic)
	}

	if eh.EhDepth == 0 {
		// Our nodes are leaf nodes.

		leafNodes := make([]ExtentLeafNode, eh.EhEntryCount)

		err = binary.Read(b, binary.LittleEndian, &leafNodes)
		if err != nil {
			panic(err)
		}

		if hasTailChecksum == true {
			et := new(ExtentTail)

			err := binary.Read(b, binary.LittleEndian, et)
			if err != nil {
				panic(err)
			}

			// TODO(dustin): Finish implementing checksums.
		}

		// Forward through the leaf-nodes on this level until we find one that
		// extends beyond the logical-block we wanted.

		var hit *ExtentLeafNode
		for i, eln := range leafNodes {
			if uint64(eln.EeFirstLogicalBlock+uint32(eln.EeLogicalBlockCount)) > lBlock {
				hit = &leafNodes[i]
				break
			}
		}

		blockExtOffset := lBlock - uint64(hit.EeFirstLogicalBlock)
		pBlock := hit.StartPhysicalBlock() + blockExtOffset

		return pBlock, nil
	}

	// Our nodes are interior/index nodes.

	indexNodes := make([]ExtentIndexNode, eh.EhEntryCount)

	err = binary.Read(b, binary.LittleEndian, &indexNodes)
	if err != nil {
		panic(err)
	}

	if hasTailChecksum == true {
		et := new(ExtentTail)

		err := binary.Read(b, binary.LittleEndian, et)
		if err != nil {
			panic(err)
		}

		// TODO(dustin): Finish implementing checksums.
	}

	var hit *ExtentIndexNode
	for i, ein := range indexNodes {
		if uint64(ein.EiLogicalBlock) <= lBlock {
			hit = &indexNodes[i]
		} else {
			break
		}
	}

	if hit == nil {
		log.Panicf("None of the index nodes at the current level of the "+
			"extent-tree for inode had a logical-block less "+
			"than what was requested (%d): %s", lBlock, en.inode.String())
	}

	pBlock := hit.LeafPhysicalBlock()

	// TODO(dustin): Refactor this to prevent reparsing the data in the next recursion when we're already parsing it here.

	// Do a preliminary read of the header to establish how much data we
	// really need.

	sb := en.inode.BlockGroupDescriptor().Superblock()

	data, err := sb.ReadPhysicalBlock(pBlock, uint64(ExtentHeaderSize))
	if err != nil {
		panic(err)
	}

	nonleafHeaderBuffer := bytes.NewBuffer(data)

	nextEh := new(ExtentHeaderNode)

	err = binary.Read(nonleafHeaderBuffer, binary.LittleEndian, nextEh)
	if err != nil {
		panic(err)
	}

	// Now, read the full data for our child extents.

	childExtentsLength := ExtentHeaderSize + ExtentIndexAndLeafSize*nextEh.EhEntryCount + ExtentChecksumTailSize

	childExtentData, err := sb.ReadPhysicalBlock(pBlock, uint64(childExtentsLength))
	if err != nil {
		panic(err)
	}

	dataPBlock, err = en.parseHeader(childExtentData, lBlock, true)
	if err != nil {
		panic(err)
	}

	return dataPBlock, nil
}
