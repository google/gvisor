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
	"math/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/ext/disklayout"
)

// These consts are for mocking the block map tree.
const (
	mockBMBlkSize  = uint32(16)
	mockBMDiskSize = 2500
)

// TestBlockMapReader stress tests block map reader functionality. It performs
// random length reads from all possible positions in the block map structure.
func TestBlockMapReader(t *testing.T) {
	mockBMFile, want := blockMapSetUp(t)
	n := len(want)

	for from := 0; from < n; from++ {
		got := make([]byte, n-from)

		if read, err := mockBMFile.ReadAt(got, int64(from)); err != nil {
			t.Fatalf("file read operation from offset %d to %d only read %d bytes: %v", from, n, read, err)
		}

		if diff := cmp.Diff(got, want[from:]); diff != "" {
			t.Fatalf("file data from offset %d to %d mismatched (-want +got):\n%s", from, n, diff)
		}
	}
}

// blkNumGen is a number generator which gives block numbers for building the
// block map file on disk. It gives unique numbers in a random order which
// facilitates in creating an extremely fragmented filesystem.
type blkNumGen struct {
	nums []uint32
}

// newBlkNumGen is the blkNumGen constructor.
func newBlkNumGen() *blkNumGen {
	blkNums := &blkNumGen{}
	lim := mockBMDiskSize / mockBMBlkSize
	blkNums.nums = make([]uint32, lim)
	for i := uint32(0); i < lim; i++ {
		blkNums.nums[i] = i
	}

	rand.Shuffle(int(lim), func(i, j int) {
		blkNums.nums[i], blkNums.nums[j] = blkNums.nums[j], blkNums.nums[i]
	})
	return blkNums
}

// next returns the next random block number.
func (n *blkNumGen) next() uint32 {
	ret := n.nums[0]
	n.nums = n.nums[1:]
	return ret
}

// blockMapSetUp creates a mock disk and a block map file. It initializes the
// block map file with 12 direct block, 1 indirect block, 1 double indirect
// block and 1 triple indirect block (basically fill it till the rim). It
// initializes the disk to reflect the inode. Also returns the file data that
// the inode covers and that is written to disk.
func blockMapSetUp(t *testing.T) (*blockMapFile, []byte) {
	mockDisk := make([]byte, mockBMDiskSize)
	var fileData []byte
	blkNums := newBlkNumGen()
	off := 0
	data := make([]byte, (numDirectBlks+3)*(*primitive.Uint32)(nil).SizeBytes())

	// Write the direct blocks.
	for i := 0; i < numDirectBlks; i++ {
		curBlkNum := primitive.Uint32(blkNums.next())
		curBlkNum.MarshalBytes(data[off:])
		off += curBlkNum.SizeBytes()
		fileData = append(fileData, writeFileDataToBlock(mockDisk, uint32(curBlkNum), 0, blkNums)...)
	}

	// Write to indirect block.
	indirectBlk := primitive.Uint32(blkNums.next())
	indirectBlk.MarshalBytes(data[off:])
	off += indirectBlk.SizeBytes()
	fileData = append(fileData, writeFileDataToBlock(mockDisk, uint32(indirectBlk), 1, blkNums)...)

	// Write to double indirect block.
	doublyIndirectBlk := primitive.Uint32(blkNums.next())
	doublyIndirectBlk.MarshalBytes(data[off:])
	off += doublyIndirectBlk.SizeBytes()
	fileData = append(fileData, writeFileDataToBlock(mockDisk, uint32(doublyIndirectBlk), 2, blkNums)...)

	// Write to triple indirect block.
	triplyIndirectBlk := primitive.Uint32(blkNums.next())
	triplyIndirectBlk.MarshalBytes(data[off:])
	fileData = append(fileData, writeFileDataToBlock(mockDisk, uint32(triplyIndirectBlk), 3, blkNums)...)

	args := inodeArgs{
		fs: &filesystem{
			dev: bytes.NewReader(mockDisk),
		},
		diskInode: &disklayout.InodeNew{
			InodeOld: disklayout.InodeOld{
				SizeLo: getMockBMFileFize(),
			},
		},
		blkSize: uint64(mockBMBlkSize),
	}
	copy(args.diskInode.Data(), data)

	mockFile, err := newBlockMapFile(args)
	if err != nil {
		t.Fatalf("newBlockMapFile failed: %v", err)
	}
	return mockFile, fileData
}

// writeFileDataToBlock writes random bytes to the block on disk.
func writeFileDataToBlock(disk []byte, blkNum uint32, height uint, blkNums *blkNumGen) []byte {
	if height == 0 {
		start := blkNum * mockBMBlkSize
		end := start + mockBMBlkSize
		rand.Read(disk[start:end])
		return disk[start:end]
	}

	var fileData []byte
	for off := blkNum * mockBMBlkSize; off < (blkNum+1)*mockBMBlkSize; off += 4 {
		curBlkNum := primitive.Uint32(blkNums.next())
		curBlkNum.MarshalBytes(disk[off : off+4])
		fileData = append(fileData, writeFileDataToBlock(disk, uint32(curBlkNum), height-1, blkNums)...)
	}
	return fileData
}

// getMockBMFileFize gets the size of the mock block map file which is used for
// testing.
func getMockBMFileFize() uint32 {
	return uint32(numDirectBlks*getCoverage(uint64(mockBMBlkSize), 0) + getCoverage(uint64(mockBMBlkSize), 1) + getCoverage(uint64(mockBMBlkSize), 2) + getCoverage(uint64(mockBMBlkSize), 3))
}
