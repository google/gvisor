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
	"sort"

	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/sentry/fs/ext/disklayout"
	"gvisor.dev/gvisor/pkg/syserror"
)

// extentFile is a type of regular file which uses extents to store file data.
type extentFile struct {
	regFile regularFile

	// root is the root extent node. This lives in the 60 byte diskInode.Data().
	// Immutable.
	root disklayout.ExtentNode
}

// Compiles only if extentFile implements io.ReaderAt.
var _ io.ReaderAt = (*extentFile)(nil)

// newExtentFile is the extent file constructor. It reads the entire extent
// tree into memory.
// TODO(b/134676337): Build extent tree on demand to reduce memory usage.
func newExtentFile(regFile regularFile) (*extentFile, error) {
	file := &extentFile{regFile: regFile}
	file.regFile.impl = file
	err := file.buildExtTree()
	if err != nil {
		return nil, err
	}
	return file, nil
}

// buildExtTree builds the extent tree by reading it from disk by doing
// running a simple DFS. It first reads the root node from the inode struct in
// memory. Then it recursively builds the rest of the tree by reading it off
// disk.
//
// Precondition: inode flag InExtents must be set.
func (f *extentFile) buildExtTree() error {
	rootNodeData := f.regFile.inode.diskInode.Data()

	binary.Unmarshal(rootNodeData[:disklayout.ExtentStructsSize], binary.LittleEndian, &f.root.Header)

	// Root node can not have more than 4 entries: 60 bytes = 1 header + 4 entries.
	if f.root.Header.NumEntries > 4 {
		// read(2) specifies that EINVAL should be returned if the file is unsuitable
		// for reading.
		return syserror.EINVAL
	}

	f.root.Entries = make([]disklayout.ExtentEntryPair, f.root.Header.NumEntries)
	for i, off := uint16(0), disklayout.ExtentStructsSize; i < f.root.Header.NumEntries; i, off = i+1, off+disklayout.ExtentStructsSize {
		var curEntry disklayout.ExtentEntry
		if f.root.Header.Height == 0 {
			// Leaf node.
			curEntry = &disklayout.Extent{}
		} else {
			// Internal node.
			curEntry = &disklayout.ExtentIdx{}
		}
		binary.Unmarshal(rootNodeData[off:off+disklayout.ExtentStructsSize], binary.LittleEndian, curEntry)
		f.root.Entries[i].Entry = curEntry
	}

	// If this node is internal, perform DFS.
	if f.root.Header.Height > 0 {
		for i := uint16(0); i < f.root.Header.NumEntries; i++ {
			var err error
			if f.root.Entries[i].Node, err = f.buildExtTreeFromDisk(f.root.Entries[i].Entry); err != nil {
				return err
			}
		}
	}

	return nil
}

// buildExtTreeFromDisk reads the extent tree nodes from disk and recursively
// builds the tree. Performs a simple DFS. It returns the ExtentNode pointed to
// by the ExtentEntry.
func (f *extentFile) buildExtTreeFromDisk(entry disklayout.ExtentEntry) (*disklayout.ExtentNode, error) {
	var header disklayout.ExtentHeader
	off := entry.PhysicalBlock() * f.regFile.inode.blkSize
	err := readFromDisk(f.regFile.inode.dev, int64(off), &header)
	if err != nil {
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

		err := readFromDisk(f.regFile.inode.dev, int64(off), curEntry)
		if err != nil {
			return nil, err
		}
		entries[i].Entry = curEntry
	}

	// If this node is internal, perform DFS.
	if header.Height > 0 {
		for i := uint16(0); i < header.NumEntries; i++ {
			var err error
			entries[i].Node, err = f.buildExtTreeFromDisk(entries[i].Entry)
			if err != nil {
				return nil, err
			}
		}
	}

	return &disklayout.ExtentNode{header, entries}, nil
}

// ReadAt implements io.ReaderAt.ReadAt.
func (f *extentFile) ReadAt(dst []byte, off int64) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}

	if off < 0 {
		return 0, syserror.EINVAL
	}

	if uint64(off) >= f.regFile.inode.diskInode.Size() {
		return 0, io.EOF
	}

	return f.read(&f.root, uint64(off), dst)
}

// read is the recursive step of extentFile.ReadAt which traverses the extent
// tree from the node passed and reads file data.
func (f *extentFile) read(node *disklayout.ExtentNode, off uint64, dst []byte) (int, error) {
	// Perform a binary search for the node covering bytes starting at r.fileOff.
	// A highly fragmented filesystem can have upto 340 entries and so linear
	// search should be avoided. Finds the first entry which does not cover the
	// file block we want and subtracts 1 to get the desired index.
	fileBlk := uint32(off / f.regFile.inode.blkSize)
	n := len(node.Entries)
	found := sort.Search(n, func(i int) bool {
		return node.Entries[i].Entry.FileBlock() > fileBlk
	}) - 1

	// We should be in this recursive step only if the data we want exists under
	// the current node.
	if found < 0 {
		panic("searching for a file block in an extent entry which does not cover it")
	}

	read := 0
	toRead := len(dst)
	var curR int
	var err error
	for i := found; i < n && read < toRead; i++ {
		if node.Header.Height == 0 {
			curR, err = f.readFromExtent(node.Entries[i].Entry.(*disklayout.Extent), off, dst[read:])
		} else {
			curR, err = f.read(node.Entries[i].Node, off, dst[read:])
		}

		read += curR
		off += uint64(curR)
		if err != nil {
			return read, err
		}
	}

	return read, nil
}

// readFromExtent reads file data from the extent. It takes advantage of the
// sequential nature of extents and reads file data from multiple blocks in one
// call.
//
// A non-nil error indicates that this is a partial read and there is probably
// more to read from this extent. The caller should propagate the error upward
// and not move to the next extent in the tree.
//
// A subsequent call to extentReader.Read should continue reading from where we
// left off as expected.
func (f *extentFile) readFromExtent(ex *disklayout.Extent, off uint64, dst []byte) (int, error) {
	curFileBlk := uint32(off / f.regFile.inode.blkSize)
	exFirstFileBlk := ex.FileBlock()
	exLastFileBlk := exFirstFileBlk + uint32(ex.Length) // This is exclusive.

	// We should be in this recursive step only if the data we want exists under
	// the current extent.
	if curFileBlk < exFirstFileBlk || exLastFileBlk <= curFileBlk {
		panic("searching for a file block in an extent which does not cover it")
	}

	curPhyBlk := uint64(curFileBlk-exFirstFileBlk) + ex.PhysicalBlock()
	readStart := curPhyBlk*f.regFile.inode.blkSize + (off % f.regFile.inode.blkSize)

	endPhyBlk := ex.PhysicalBlock() + uint64(ex.Length)
	extentEnd := endPhyBlk * f.regFile.inode.blkSize // This is exclusive.

	toRead := int(extentEnd - readStart)
	if len(dst) < toRead {
		toRead = len(dst)
	}

	n, _ := f.regFile.inode.dev.ReadAt(dst[:toRead], int64(readStart))
	if n < toRead {
		return n, syserror.EIO
	}
	return n, nil
}
