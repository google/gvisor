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
	"bytes"
	"io"
	"math/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/sentry/fs/ext/disklayout"
)

const (
	// mockExtentBlkSize is the mock block size used for testing.
	// No block has more than 1 header + 4 entries.
	mockExtentBlkSize = uint64(64)
)

// The tree described below looks like:
//
//            0.{Head}[Idx][Idx]
//                     /     \
//                    /       \
//      1.{Head}[Ext][Ext]  2.{Head}[Idx]
//               /    |               \
//           [Phy]  [Phy, Phy]    3.{Head}[Ext]
//                                          |
//                                    [Phy, Phy, Phy]
//
// Legend:
//   - Head = ExtentHeader
//   - Idx  = ExtentIdx
//   - Ext  = Extent
//   - Phy  = Physical Block
//
// Please note that ext4 might not construct extent trees looking like this.
// This is purely for testing the tree traversal logic.
var (
	node3 = &disklayout.ExtentNode{
		Header: disklayout.ExtentHeader{
			Magic:      disklayout.ExtentMagic,
			NumEntries: 1,
			MaxEntries: 4,
			Height:     0,
		},
		Entries: []disklayout.ExtentEntryPair{
			{
				Entry: &disklayout.Extent{
					FirstFileBlock: 3,
					Length:         3,
					StartBlockLo:   6,
				},
				Node: nil,
			},
		},
	}

	node2 = &disklayout.ExtentNode{
		Header: disklayout.ExtentHeader{
			Magic:      disklayout.ExtentMagic,
			NumEntries: 1,
			MaxEntries: 4,
			Height:     1,
		},
		Entries: []disklayout.ExtentEntryPair{
			{
				Entry: &disklayout.ExtentIdx{
					FirstFileBlock: 3,
					ChildBlockLo:   2,
				},
				Node: node3,
			},
		},
	}

	node1 = &disklayout.ExtentNode{
		Header: disklayout.ExtentHeader{
			Magic:      disklayout.ExtentMagic,
			NumEntries: 2,
			MaxEntries: 4,
			Height:     0,
		},
		Entries: []disklayout.ExtentEntryPair{
			{
				Entry: &disklayout.Extent{
					FirstFileBlock: 0,
					Length:         1,
					StartBlockLo:   3,
				},
				Node: nil,
			},
			{
				Entry: &disklayout.Extent{
					FirstFileBlock: 1,
					Length:         2,
					StartBlockLo:   4,
				},
				Node: nil,
			},
		},
	}

	node0 = &disklayout.ExtentNode{
		Header: disklayout.ExtentHeader{
			Magic:      disklayout.ExtentMagic,
			NumEntries: 2,
			MaxEntries: 4,
			Height:     2,
		},
		Entries: []disklayout.ExtentEntryPair{
			{
				Entry: &disklayout.ExtentIdx{
					FirstFileBlock: 0,
					ChildBlockLo:   0,
				},
				Node: node1,
			},
			{
				Entry: &disklayout.ExtentIdx{
					FirstFileBlock: 3,
					ChildBlockLo:   1,
				},
				Node: node2,
			},
		},
	}
)

// TestExtentReader stress tests extentReader functionality. It performs random
// length reads from all possible positions in the extent tree.
func TestExtentReader(t *testing.T) {
	dev, mockExtentFile, want := extentTreeSetUp(t, node0)
	n := len(want)

	for from := 0; from < n; from++ {
		fileReader := mockExtentFile.getFileReader(dev, mockExtentBlkSize, uint64(from))
		got := make([]byte, n-from)

		if read, err := io.ReadFull(fileReader, got); err != nil {
			t.Fatalf("file read operation from offset %d to %d only read %d bytes: %v", from, n, read, err)
		}

		if diff := cmp.Diff(got, want[from:]); diff != "" {
			t.Fatalf("file data from offset %d to %d mismatched (-want +got):\n%s", from, n, diff)
		}
	}
}

// TestBuildExtentTree tests the extent tree building logic.
func TestBuildExtentTree(t *testing.T) {
	_, mockExtentFile, _ := extentTreeSetUp(t, node0)

	opt := cmpopts.IgnoreUnexported(disklayout.ExtentIdx{}, disklayout.ExtentHeader{})
	if diff := cmp.Diff(&mockExtentFile.root, node0, opt); diff != "" {
		t.Errorf("extent tree mismatch (-want +got):\n%s", diff)
	}
}

// extentTreeSetUp writes the passed extent tree to a mock disk as an extent
// tree. It also constucts a mock extent file with the same tree built in it.
// It also writes random data file data and returns it.
func extentTreeSetUp(t *testing.T, root *disklayout.ExtentNode) (io.ReaderAt, *extentFile, []byte) {
	t.Helper()

	mockDisk := make([]byte, mockExtentBlkSize*10)
	mockExtentFile := &extentFile{
		regFile: regularFile{
			inode: inode{
				diskInode: &disklayout.InodeNew{
					InodeOld: disklayout.InodeOld{
						SizeLo: uint32(mockExtentBlkSize) * getNumPhyBlks(root),
					},
				},
			},
		},
	}

	fileData := writeTree(&mockExtentFile.regFile.inode, mockDisk, node0, mockExtentBlkSize)

	r := bytes.NewReader(mockDisk)
	if err := mockExtentFile.buildExtTree(r, mockExtentBlkSize); err != nil {
		t.Fatalf("inode.buildExtTree failed: %v", err)
	}
	return r, mockExtentFile, fileData
}

// writeTree writes the tree represented by `root` to the inode and disk. It
// also writes random file data on disk.
func writeTree(in *inode, disk []byte, root *disklayout.ExtentNode, mockExtentBlkSize uint64) []byte {
	rootData := binary.Marshal(nil, binary.LittleEndian, root.Header)
	for _, ep := range root.Entries {
		rootData = binary.Marshal(rootData, binary.LittleEndian, ep.Entry)
	}

	copy(in.diskInode.Data(), rootData)

	var fileData []byte
	for _, ep := range root.Entries {
		if root.Header.Height == 0 {
			fileData = append(fileData, writeFileDataToExtent(disk, ep.Entry.(*disklayout.Extent))...)
		} else {
			fileData = append(fileData, writeTreeToDisk(disk, ep)...)
		}
	}
	return fileData
}

// writeTreeToDisk is the recursive step for writeTree which writes the tree
// on the disk only. Also writes random file data on disk.
func writeTreeToDisk(disk []byte, curNode disklayout.ExtentEntryPair) []byte {
	nodeData := binary.Marshal(nil, binary.LittleEndian, curNode.Node.Header)
	for _, ep := range curNode.Node.Entries {
		nodeData = binary.Marshal(nodeData, binary.LittleEndian, ep.Entry)
	}

	copy(disk[curNode.Entry.PhysicalBlock()*mockExtentBlkSize:], nodeData)

	var fileData []byte
	for _, ep := range curNode.Node.Entries {
		if curNode.Node.Header.Height == 0 {
			fileData = append(fileData, writeFileDataToExtent(disk, ep.Entry.(*disklayout.Extent))...)
		} else {
			fileData = append(fileData, writeTreeToDisk(disk, ep)...)
		}
	}
	return fileData
}

// writeFileDataToExtent writes random bytes to the blocks on disk that the
// passed extent points to.
func writeFileDataToExtent(disk []byte, ex *disklayout.Extent) []byte {
	phyExStartBlk := ex.PhysicalBlock()
	phyExStartOff := phyExStartBlk * mockExtentBlkSize
	phyExEndOff := phyExStartOff + uint64(ex.Length)*mockExtentBlkSize
	rand.Read(disk[phyExStartOff:phyExEndOff])
	return disk[phyExStartOff:phyExEndOff]
}

// getNumPhyBlks returns the number of physical blocks covered under the node.
func getNumPhyBlks(node *disklayout.ExtentNode) uint32 {
	var res uint32
	for _, ep := range node.Entries {
		if node.Header.Height == 0 {
			res += uint32(ep.Entry.(*disklayout.Extent).Length)
		} else {
			res += getNumPhyBlks(ep.Node)
		}
	}
	return res
}
