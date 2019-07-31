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

	"gvisor.dev/gvisor/pkg/binary"
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
	directBlks [numDirectBlks]uint32

	// indirectBlk is the physical block which contains (blkSize/4) direct block
	// numbers (as uint32 integers).
	indirectBlk uint32

	// doubleIndirectBlk is the physical block which contains (blkSize/4) indirect
	// block numbers (as uint32 integers).
	doubleIndirectBlk uint32

	// tripleIndirectBlk is the physical block which contains (blkSize/4) doubly
	// indirect block numbers (as uint32 integers).
	tripleIndirectBlk uint32

	// coverage at (i)th index indicates the amount of file data a node at
	// height (i) covers. Height 0 is the direct block.
	coverage [4]uint64
}

// Compiles only if blockMapFile implements fileReader.
var _ fileReader = (*blockMapFile)(nil)

// Read implements fileReader.getFileReader.
func (f *blockMapFile) getFileReader(dev io.ReaderAt, blkSize uint64, offset uint64) io.Reader {
	return &blockMapReader{
		dev:     dev,
		file:    f,
		fileOff: offset,
		blkSize: blkSize,
	}
}

// newBlockMapFile is the blockMapFile constructor. It initializes the file to
// physical blocks map with (at most) the first 12 (direct) blocks.
func newBlockMapFile(blkSize uint64, regFile regularFile) (*blockMapFile, error) {
	file := &blockMapFile{regFile: regFile}
	file.regFile.impl = file

	for i := uint(0); i < 4; i++ {
		file.coverage[i] = getCoverage(blkSize, i)
	}

	blkMap := regFile.inode.diskInode.Data()
	binary.Unmarshal(blkMap[:numDirectBlks*4], binary.LittleEndian, &file.directBlks)
	binary.Unmarshal(blkMap[numDirectBlks*4:(numDirectBlks+1)*4], binary.LittleEndian, &file.indirectBlk)
	binary.Unmarshal(blkMap[(numDirectBlks+1)*4:(numDirectBlks+2)*4], binary.LittleEndian, &file.doubleIndirectBlk)
	binary.Unmarshal(blkMap[(numDirectBlks+2)*4:(numDirectBlks+3)*4], binary.LittleEndian, &file.tripleIndirectBlk)
	return file, nil
}

// blockMapReader implements io.Reader which will fetch fill data from the
// block maps and build the blockMapFile.fileToPhyBlks array if required.
type blockMapReader struct {
	dev     io.ReaderAt
	file    *blockMapFile
	fileOff uint64
	blkSize uint64
}

// Compiles only if blockMapReader implements io.Reader.
var _ io.Reader = (*blockMapReader)(nil)

// Read implements io.Reader.Read.
func (r *blockMapReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}

	if r.fileOff >= r.file.regFile.inode.diskInode.Size() {
		return 0, io.EOF
	}

	// dirBlksEnd is the file offset until which direct blocks cover file data.
	// Direct blocks cover 0 <= file offset < dirBlksEnd.
	dirBlksEnd := numDirectBlks * r.file.coverage[0]

	// indirBlkEnd is the file offset until which the indirect block covers file
	// data. The indirect block covers dirBlksEnd <= file offset < indirBlkEnd.
	indirBlkEnd := dirBlksEnd + r.file.coverage[1]

	// doubIndirBlkEnd is the file offset until which the double indirect block
	// covers file data. The double indirect block covers the range
	// indirBlkEnd <= file offset < doubIndirBlkEnd.
	doubIndirBlkEnd := indirBlkEnd + r.file.coverage[2]

	read := 0
	toRead := len(dst)
	for read < toRead {
		var err error
		var curR int

		// Figure out which block to delegate the read to.
		switch {
		case r.fileOff < dirBlksEnd:
			// Direct block.
			curR, err = r.read(r.file.directBlks[r.fileOff/r.blkSize], r.fileOff%r.blkSize, 0, dst[read:])
		case r.fileOff < indirBlkEnd:
			// Indirect block.
			curR, err = r.read(r.file.indirectBlk, r.fileOff-dirBlksEnd, 1, dst[read:])
		case r.fileOff < doubIndirBlkEnd:
			// Doubly indirect block.
			curR, err = r.read(r.file.doubleIndirectBlk, r.fileOff-indirBlkEnd, 2, dst[read:])
		default:
			// Triply indirect block.
			curR, err = r.read(r.file.tripleIndirectBlk, r.fileOff-doubIndirBlkEnd, 3, dst[read:])
		}

		read += curR
		if err != nil {
			return read, err
		}
	}

	return read, nil
}

// read is the recursive step of the Read function. It relies on knowing the
// current node's location on disk (curPhyBlk) and its height in the block map
// tree. A height of 0 shows that the current node is actually holding file
// data. relFileOff tells the offset from which we need to start to reading
// under the current node. It is completely relative to the current node.
func (r *blockMapReader) read(curPhyBlk uint32, relFileOff uint64, height uint, dst []byte) (int, error) {
	curPhyBlkOff := int64(curPhyBlk) * int64(r.blkSize)
	if height == 0 {
		toRead := int(r.blkSize - relFileOff)
		if len(dst) < toRead {
			toRead = len(dst)
		}

		n, _ := r.dev.ReadAt(dst[:toRead], curPhyBlkOff+int64(relFileOff))
		r.fileOff += uint64(n)
		if n < toRead {
			return n, syserror.EIO
		}
		return n, nil
	}

	childCov := r.file.coverage[height-1]
	startIdx := relFileOff / childCov
	endIdx := r.blkSize / 4 // This is exclusive.
	wantEndIdx := (relFileOff + uint64(len(dst))) / childCov
	wantEndIdx++ // Make this exclusive.
	if wantEndIdx < endIdx {
		endIdx = wantEndIdx
	}

	read := 0
	curChildOff := relFileOff % childCov
	for i := startIdx; i < endIdx; i++ {
		var childPhyBlk uint32
		if err := readFromDisk(r.dev, curPhyBlkOff+int64(i*4), &childPhyBlk); err != nil {
			return read, err
		}

		n, err := r.read(childPhyBlk, curChildOff, height-1, dst[read:])
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
