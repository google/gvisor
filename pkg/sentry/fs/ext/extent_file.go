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

// Compiles only if extentFile implements fileReader.
var _ fileReader = (*extentFile)(nil)

// Read implements fileReader.getFileReader.
func (f *extentFile) getFileReader(dev io.ReadSeeker, blkSize uint64, offset uint64) io.Reader {
	panic("unimplemented")
}

// newExtentFile is the extent file constructor. It reads the entire extent
// tree into memory.
//
// Preconditions: Must hold the mutex of the filesystem containing dev.
// TODO(b/134676337): Build extent tree on demand to reduce memory usage.
func newExtentFile(dev io.ReadSeeker, blkSize uint64, regFile regularFile) (*extentFile, error) {
	file := &extentFile{regFile: regFile}
	file.regFile.impl = file
	err := file.buildExtTree(dev, blkSize)
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
// Preconditions:
//   - Must hold the mutex of the filesystem containing dev.
//   - Inode flag InExtents must be set.
func (f *extentFile) buildExtTree(dev io.ReadSeeker, blkSize uint64) error {
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
			if f.root.Entries[i].Node, err = buildExtTreeFromDisk(dev, f.root.Entries[i].Entry, blkSize); err != nil {
				return err
			}
		}
	}

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
	err := readFromDisk(dev, int64(off), &header)
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

		err := readFromDisk(dev, int64(off), curEntry)
		if err != nil {
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
