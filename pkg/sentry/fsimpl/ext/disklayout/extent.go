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

// Extents were introduced in ext4 and provide huge performance gains in terms
// data locality and reduced metadata block usage. Extents are organized in
// extent trees. The root node is contained in inode.BlocksRaw.
//
// Terminology:
//   - Physical Block:
//       Filesystem data block which is addressed normally wrt the entire
//       filesystem (addressed with 48 bits).
//
//   - File Block:
//       Data block containing *only* file data and addressed wrt to the file
//       with only 32 bits. The (i)th file block contains file data from
//       byte (i * sb.BlockSize()) to ((i+1) * sb.BlockSize()).

const (
	// ExtentHeaderSize is the size of the header of an extent tree node.
	ExtentHeaderSize = 12

	// ExtentEntrySize is the size of an entry in an extent tree node.
	// This size is the same for both leaf and internal nodes.
	ExtentEntrySize = 12

	// ExtentMagic is the magic number which must be present in the header.
	ExtentMagic = 0xf30a
)

// ExtentEntryPair couples an in-memory ExtendNode with the ExtentEntry that
// points to it. We want to cache these structs in memory to avoid repeated
// disk reads.
//
// Note: This struct itself does not represent an on-disk struct.
type ExtentEntryPair struct {
	// Entry points to the child node on disk.
	Entry ExtentEntry
	// Node points to child node in memory. Is nil if the current node is a leaf.
	Node *ExtentNode
}

// ExtentNode represents an extent tree node. For internal nodes, all Entries
// will be ExtendIdxs. For leaf nodes, they will all be Extents.
//
// Note: This struct itself does not represent an on-disk struct.
type ExtentNode struct {
	Header  ExtentHeader
	Entries []ExtentEntryPair
}

// ExtentEntry represents an extent tree node entry. The entry can either be
// an ExtentIdx or Extent itself. This exists to simplify navigation logic.
type ExtentEntry interface {
	// FileBlock returns the first file block number covered by this entry.
	FileBlock() uint32

	// PhysicalBlock returns the child physical block that this entry points to.
	PhysicalBlock() uint64
}

// ExtentHeader emulates the ext4_extent_header struct in ext4. Each extent
// tree node begins with this and is followed by `NumEntries` number of:
//   - Extent         if `Depth` == 0
//   - ExtentIdx      otherwise
type ExtentHeader struct {
	// Magic in the extent magic number, must be 0xf30a.
	Magic uint16

	// NumEntries indicates the number of valid entries following the header.
	NumEntries uint16

	// MaxEntries that could follow the header. Used while adding entries.
	MaxEntries uint16

	// Height represents the distance of this node from the farthest leaf. Please
	// note that Linux incorrectly calls this `Depth` (which means the distance
	// of the node from the root).
	Height uint16
	_      uint32
}

// ExtentIdx emulates the ext4_extent_idx struct in ext4. Only present in
// internal nodes. Sorted in ascending order based on FirstFileBlock since
// Linux does a binary search on this. This points to a block containing the
// child node.
type ExtentIdx struct {
	FirstFileBlock uint32
	ChildBlockLo   uint32
	ChildBlockHi   uint16
	_              uint16
}

// Compiles only if ExtentIdx implements ExtentEntry.
var _ ExtentEntry = (*ExtentIdx)(nil)

// FileBlock implements ExtentEntry.FileBlock.
func (ei *ExtentIdx) FileBlock() uint32 {
	return ei.FirstFileBlock
}

// PhysicalBlock implements ExtentEntry.PhysicalBlock. It returns the
// physical block number of the child block.
func (ei *ExtentIdx) PhysicalBlock() uint64 {
	return (uint64(ei.ChildBlockHi) << 32) | uint64(ei.ChildBlockLo)
}

// Extent represents the ext4_extent struct in ext4. Only present in leaf
// nodes. Sorted in ascending order based on FirstFileBlock since Linux does a
// binary search on this. This points to an array of data blocks containing the
// file data. It covers `Length` data blocks starting from `StartBlock`.
type Extent struct {
	FirstFileBlock uint32
	Length         uint16
	StartBlockHi   uint16
	StartBlockLo   uint32
}

// Compiles only if Extent implements ExtentEntry.
var _ ExtentEntry = (*Extent)(nil)

// FileBlock implements ExtentEntry.FileBlock.
func (e *Extent) FileBlock() uint32 {
	return e.FirstFileBlock
}

// PhysicalBlock implements ExtentEntry.PhysicalBlock. It returns the
// physical block number of the first data block this extent covers.
func (e *Extent) PhysicalBlock() uint64 {
	return (uint64(e.StartBlockHi) << 32) | uint64(e.StartBlockLo)
}
