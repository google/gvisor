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
	"math"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/syserror"
)

const (
	// numDirectBlks is the number of direct blocks in ext block map inodes.
	numDirectBlks = 12
)

// blockMapFile is a type of regular file which uses direct/indirect block
// addressing to store file data. This was deprecated in ext4.
type blockMapFile struct {
	regFile regularFile

	// directBlks are the direct blocks numbers. The physical blocks pointed by
	// these holds file data. Contains file blocks 0 to 11.
	directBlks [numDirectBlks]primitive.Uint32

	// indirectBlk is the physical block which contains (blkSize/4) direct block
	// numbers (as uint32 integers).
	indirectBlk primitive.Uint32

	// doubleIndirectBlk is the physical block which contains (blkSize/4) indirect
	// block numbers (as uint32 integers).
	doubleIndirectBlk primitive.Uint32

	// tripleIndirectBlk is the physical block which contains (blkSize/4) doubly
	// indirect block numbers (as uint32 integers).
	tripleIndirectBlk primitive.Uint32

	// coverage at (i)th index indicates the amount of file data a node at
	// height (i) covers. Height 0 is the direct block.
	coverage [4]uint64
}

// Compiles only if blockMapFile implements io.ReaderAt.
var _ io.ReaderAt = (*blockMapFile)(nil)

// newBlockMapFile is the blockMapFile constructor. It initializes the file to
// physical blocks map with (at most) the first 12 (direct) blocks.
func newBlockMapFile(args inodeArgs) (*blockMapFile, error) {
	file := &blockMapFile{}
	file.regFile.impl = file
	file.regFile.inode.init(args, &file.regFile)

	for i := uint(0); i < 4; i++ {
		file.coverage[i] = getCoverage(file.regFile.inode.blkSize, i)
	}

	blkMap := file.regFile.inode.diskInode.Data()
	for i := 0; i < numDirectBlks; i++ {
		file.directBlks[i].UnmarshalBytes(blkMap[i*4 : (i+1)*4])
	}
	file.indirectBlk.UnmarshalBytes(blkMap[numDirectBlks*4 : (numDirectBlks+1)*4])
	file.doubleIndirectBlk.UnmarshalBytes(blkMap[(numDirectBlks+1)*4 : (numDirectBlks+2)*4])
	file.tripleIndirectBlk.UnmarshalBytes(blkMap[(numDirectBlks+2)*4 : (numDirectBlks+3)*4])
	return file, nil
}

// ReadAt implements io.ReaderAt.ReadAt.
func (f *blockMapFile) ReadAt(dst []byte, off int64) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}

	if off < 0 {
		return 0, linuxerr.EINVAL
	}

	offset := uint64(off)
	size := f.regFile.inode.diskInode.Size()
	if offset >= size {
		return 0, io.EOF
	}

	// dirBlksEnd is the file offset until which direct blocks cover file data.
	// Direct blocks cover 0 <= file offset < dirBlksEnd.
	dirBlksEnd := numDirectBlks * f.coverage[0]

	// indirBlkEnd is the file offset until which the indirect block covers file
	// data. The indirect block covers dirBlksEnd <= file offset < indirBlkEnd.
	indirBlkEnd := dirBlksEnd + f.coverage[1]

	// doubIndirBlkEnd is the file offset until which the double indirect block
	// covers file data. The double indirect block covers the range
	// indirBlkEnd <= file offset < doubIndirBlkEnd.
	doubIndirBlkEnd := indirBlkEnd + f.coverage[2]

	read := 0
	toRead := len(dst)
	if uint64(toRead)+offset > size {
		toRead = int(size - offset)
	}
	for read < toRead {
		var err error
		var curR int

		// Figure out which block to delegate the read to.
		switch {
		case offset < dirBlksEnd:
			// Direct block.
			curR, err = f.read(uint32(f.directBlks[offset/f.regFile.inode.blkSize]), offset%f.regFile.inode.blkSize, 0, dst[read:])
		case offset < indirBlkEnd:
			// Indirect block.
			curR, err = f.read(uint32(f.indirectBlk), offset-dirBlksEnd, 1, dst[read:])
		case offset < doubIndirBlkEnd:
			// Doubly indirect block.
			curR, err = f.read(uint32(f.doubleIndirectBlk), offset-indirBlkEnd, 2, dst[read:])
		default:
			// Triply indirect block.
			curR, err = f.read(uint32(f.tripleIndirectBlk), offset-doubIndirBlkEnd, 3, dst[read:])
		}

		read += curR
		offset += uint64(curR)
		if err != nil {
			return read, err
		}
	}

	if read < len(dst) {
		return read, io.EOF
	}
	return read, nil
}

// read is the recursive step of the ReadAt function. It relies on knowing the
// current node's location on disk (curPhyBlk) and its height in the block map
// tree. A height of 0 shows that the current node is actually holding file
// data. relFileOff tells the offset from which we need to start to reading
// under the current node. It is completely relative to the current node.
func (f *blockMapFile) read(curPhyBlk uint32, relFileOff uint64, height uint, dst []byte) (int, error) {
	curPhyBlkOff := int64(curPhyBlk) * int64(f.regFile.inode.blkSize)
	if height == 0 {
		toRead := int(f.regFile.inode.blkSize - relFileOff)
		if len(dst) < toRead {
			toRead = len(dst)
		}

		n, _ := f.regFile.inode.fs.dev.ReadAt(dst[:toRead], curPhyBlkOff+int64(relFileOff))
		if n < toRead {
			return n, syserror.EIO
		}
		return n, nil
	}

	childCov := f.coverage[height-1]
	startIdx := relFileOff / childCov
	endIdx := f.regFile.inode.blkSize / 4 // This is exclusive.
	wantEndIdx := (relFileOff + uint64(len(dst))) / childCov
	wantEndIdx++ // Make this exclusive.
	if wantEndIdx < endIdx {
		endIdx = wantEndIdx
	}

	read := 0
	curChildOff := relFileOff % childCov
	for i := startIdx; i < endIdx; i++ {
		var childPhyBlk primitive.Uint32
		err := readFromDisk(f.regFile.inode.fs.dev, curPhyBlkOff+int64(i*4), &childPhyBlk)
		if err != nil {
			return read, err
		}

		n, err := f.read(uint32(childPhyBlk), curChildOff, height-1, dst[read:])
		read += n
		if err != nil {
			return read, err
		}

		curChildOff = 0
	}

	return read, nil
}

// getCoverage returns the number of bytes a node at the given height covers.
// Height 0 is the file data block itself. Height 1 is the indirect block.
//
// Formula: blkSize * ((blkSize / 4)^height)
func getCoverage(blkSize uint64, height uint) uint64 {
	return blkSize * uint64(math.Pow(float64(blkSize/4), float64(height)))
}
