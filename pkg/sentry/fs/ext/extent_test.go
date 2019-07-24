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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/sentry/fs/ext/disklayout"
)

// TestExtentTree tests the extent tree building logic.
//
// Test tree:
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
func TestExtentTree(t *testing.T) {
	blkSize := uint64(64) // No block has more than 1 header + 4 entries.
	mockDisk := make([]byte, blkSize*10)
	mockInode := &inode{diskInode: &disklayout.InodeNew{}}

	node3 := &disklayout.ExtentNode{
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

	node2 := &disklayout.ExtentNode{
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

	node1 := &disklayout.ExtentNode{
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

	node0 := &disklayout.ExtentNode{
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

	writeTree(mockInode, mockDisk, node0, blkSize)

	r := bytes.NewReader(mockDisk)
	if err := mockInode.buildExtTree(r, blkSize); err != nil {
		t.Fatalf("inode.buildExtTree failed: %v", err)
	}

	opt := cmpopts.IgnoreUnexported(disklayout.ExtentIdx{}, disklayout.ExtentHeader{})
	if diff := cmp.Diff(mockInode.root, node0, opt); diff != "" {
		t.Errorf("extent tree mismatch (-want +got):\n%s", diff)
	}
}

// writeTree writes the tree represented by `root` to the inode and disk passed.
func writeTree(in *inode, disk []byte, root *disklayout.ExtentNode, blkSize uint64) {
	rootData := binary.Marshal(nil, binary.LittleEndian, root.Header)
	for _, ep := range root.Entries {
		rootData = binary.Marshal(rootData, binary.LittleEndian, ep.Entry)
	}

	copy(in.diskInode.Data(), rootData)

	if root.Header.Height > 0 {
		for _, ep := range root.Entries {
			writeTreeToDisk(disk, ep, blkSize)
		}
	}
}

// writeTreeToDisk is the recursive step for writeTree which writes the tree
// on the disk only.
func writeTreeToDisk(disk []byte, curNode disklayout.ExtentEntryPair, blkSize uint64) {
	nodeData := binary.Marshal(nil, binary.LittleEndian, curNode.Node.Header)
	for _, ep := range curNode.Node.Entries {
		nodeData = binary.Marshal(nodeData, binary.LittleEndian, ep.Entry)
	}

	copy(disk[curNode.Entry.PhysicalBlock()*blkSize:], nodeData)

	if curNode.Node.Header.Height > 0 {
		for _, ep := range curNode.Node.Entries {
			writeTreeToDisk(disk, ep, blkSize)
		}
	}
}
