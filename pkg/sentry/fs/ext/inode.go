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

package ext

import (
	"io"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/sentry/fs/ext/disklayout"
	"gvisor.dev/gvisor/pkg/syserror"
)

// inode represents an ext inode.
type inode struct {
	// refs is a reference count. refs is accessed using atomic memory operations.
	refs int64

	// inodeNum is the inode number of this inode on disk. This is used to
	// identify inodes within the ext filesystem.
	inodeNum uint32

	// diskInode gives us access to the inode struct on disk. Immutable.
	diskInode disklayout.Inode

	// root is the root extent node. This lives in the 60 byte diskInode.Blocks().
	// Immutable. Nil if the inode does not use extents.
	root *disklayout.ExtentNode
}

// incRef increments the inode ref count.
func (in *inode) incRef() {
	atomic.AddInt64(&in.refs, 1)
}

// tryIncRef tries to increment the ref count. Returns true if successful.
func (in *inode) tryIncRef() bool {
	for {
		refs := atomic.LoadInt64(&in.refs)
		if refs == 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(&in.refs, refs, refs+1) {
			return true
		}
	}
}

// decRef decrements the inode ref count and releases the inode resources if
// the ref count hits 0.
//
// Preconditions: Must have locked fs.mu.
func (in *inode) decRef(fs *filesystem) {
	if refs := atomic.AddInt64(&in.refs, -1); refs == 0 {
		delete(fs.inodeCache, in.inodeNum)
	} else if refs < 0 {
		panic("ext.inode.decRef() called without holding a reference")
	}
}

// newInode is the inode constructor. Reads the inode off disk. Identifies
// inodes based on the absolute inode number on disk.
//
// Preconditions: Must hold the mutex of the filesystem containing dev.
func newInode(dev io.ReadSeeker, sb disklayout.SuperBlock, bgs []disklayout.BlockGroup, inodeNum uint32) (*inode, error) {
	if inodeNum == 0 {
		panic("inode number 0 on ext filesystems is not possible")
	}

	in := &inode{refs: 1, inodeNum: inodeNum}
	inodeRecordSize := sb.InodeSize()
	if inodeRecordSize == disklayout.OldInodeSize {
		in.diskInode = &disklayout.InodeOld{}
	} else {
		in.diskInode = &disklayout.InodeNew{}
	}

	// Calculate where the inode is actually placed.
	inodesPerGrp := sb.InodesPerGroup()
	blkSize := sb.BlockSize()
	inodeTableOff := bgs[getBGNum(inodeNum, inodesPerGrp)].InodeTable() * blkSize
	inodeOff := inodeTableOff + uint64(uint32(inodeRecordSize)*getBGOff(inodeNum, inodesPerGrp))

	// Read it from disk and figure out which type of inode this is.
	if err := readFromDisk(dev, int64(inodeOff), in.diskInode); err != nil {
		return nil, err
	}

	if in.diskInode.Flags().Extents {
		in.buildExtTree(dev, blkSize)
	}

	return in, nil
}

// getBGNum returns the block group number that a given inode belongs to.
func getBGNum(inodeNum uint32, inodesPerGrp uint32) uint32 {
	return (inodeNum - 1) / inodesPerGrp
}

// getBGOff returns the offset at which the given inode lives in the block
// group's inode table, i.e. the index of the inode in the inode table.
func getBGOff(inodeNum uint32, inodesPerGrp uint32) uint32 {
	return (inodeNum - 1) % inodesPerGrp
}

// buildExtTree builds the extent tree by reading it from disk by doing
// running a simple DFS. It first reads the root node from the inode struct in
// memory. Then it recursively builds the rest of the tree by reading it off
// disk.
//
// Preconditions:
//   - Must hold the mutex of the filesystem containing dev.
//   - Inode flag InExtents must be set.
func (in *inode) buildExtTree(dev io.ReadSeeker, blkSize uint64) error {
	rootNodeData := in.diskInode.Data()

	var rootHeader disklayout.ExtentHeader
	binary.Unmarshal(rootNodeData[:disklayout.ExtentStructsSize], binary.LittleEndian, &rootHeader)

	// Root node can not have more than 4 entries: 60 bytes = 1 header + 4 entries.
	if rootHeader.NumEntries > 4 {
		// read(2) specifies that EINVAL should be returned if the file is unsuitable
		// for reading.
		return syserror.EINVAL
	}

	rootEntries := make([]disklayout.ExtentEntryPair, rootHeader.NumEntries)
	for i, off := uint16(0), disklayout.ExtentStructsSize; i < rootHeader.NumEntries; i, off = i+1, off+disklayout.ExtentStructsSize {
		var curEntry disklayout.ExtentEntry
		if rootHeader.Height == 0 {
			// Leaf node.
			curEntry = &disklayout.Extent{}
		} else {
			// Internal node.
			curEntry = &disklayout.ExtentIdx{}
		}
		binary.Unmarshal(rootNodeData[off:off+disklayout.ExtentStructsSize], binary.LittleEndian, curEntry)
		rootEntries[i].Entry = curEntry
	}

	// If this node is internal, perform DFS.
	if rootHeader.Height > 0 {
		for i := uint16(0); i < rootHeader.NumEntries; i++ {
			var err error
			if rootEntries[i].Node, err = buildExtTreeFromDisk(dev, rootEntries[i].Entry, blkSize); err != nil {
				return err
			}
		}
	}

	in.root = &disklayout.ExtentNode{rootHeader, rootEntries}
	return nil
}

// buildExtTreeFromDisk reads the extent tree nodes from disk and recursively
// builds the tree. Performs a simple DFS. It returns the ExtentNode pointed to
// by the ExtentEntry.
//
// Preconditions: Must hold the mutex of the filesystem containing dev.
func buildExtTreeFromDisk(dev io.ReadSeeker, entry disklayout.ExtentEntry, blkSize uint64) (*disklayout.ExtentNode, error) {
	var header disklayout.ExtentHeader
	off := entry.PhysicalBlock() * blkSize
	if err := readFromDisk(dev, int64(off), &header); err != nil {
		return nil, err
	}

	entries := make([]disklayout.ExtentEntryPair, header.NumEntries)
	for i, off := uint16(0), off+disklayout.ExtentStructsSize; i < header.NumEntries; i, off = i+1, off+disklayout.ExtentStructsSize {
		var curEntry disklayout.ExtentEntry
		if header.Height == 0 {
			// Leaf node.
			curEntry = &disklayout.Extent{}
		} else {
			// Internal node.
			curEntry = &disklayout.ExtentIdx{}
		}

		if err := readFromDisk(dev, int64(off), curEntry); err != nil {
			return nil, err
		}
		entries[i].Entry = curEntry
	}

	// If this node is internal, perform DFS.
	if header.Height > 0 {
		for i := uint16(0); i < header.NumEntries; i++ {
			var err error
			entries[i].Node, err = buildExtTreeFromDisk(dev, entries[i].Entry, blkSize)
			if err != nil {
				return nil, err
			}
		}
	}

	return &disklayout.ExtentNode{header, entries}, nil
}
