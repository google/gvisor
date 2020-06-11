// Copyright 2020 The gVisor Authors.
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

// Package merkletree implements Merkle tree generating and verification.
package merkletree

import (
	"crypto/sha256"
	"io"

	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// sha256DigestSize specifies the digest size of a SHA256 hash.
	sha256DigestSize = 32
)

// Size defines the scale of a Merkle tree.
type Size struct {
	// blockSize is the size of a data block to be hashed.
	blockSize int64
	// digestSize is the size of a generated hash.
	digestSize int64
	// hashesPerBlock is the number of hashes in a block. For example, if
	// blockSize is 4096 bytes, and digestSize is 32 bytes, there will be 128
	// hashesPerBlock. Therefore 128 hashes in a lower level will be put into a
	// block and generate a single hash in an upper level.
	hashesPerBlock int64
	// levelStart is the start block index of each level. The number of levels in
	// the tree is the length of the slice. The leafs (level 0) are hashes of
	// blocks in the input data. The levels above are hashes of lower level
	// hashes.  The highest level is the root hash.
	levelStart []int64
}

// MakeSize initializes and returns a new Size object describing the structure
// of a tree. dataSize specifies the number of the file system size in bytes.
func MakeSize(dataSize int64) Size {
	size := Size{
		blockSize: usermem.PageSize,
		// TODO(b/156980949): Allow config other hash methods (SHA384/SHA512).
		digestSize:     sha256DigestSize,
		hashesPerBlock: usermem.PageSize / sha256DigestSize,
	}
	numBlocks := (dataSize + size.blockSize - 1) / size.blockSize
	level := int64(0)
	offset := int64(0)

	// Calcuate the number of levels in the Merkle tree and the beginning offset
	// of each level. Level 0 is the level directly above the data blocks, while
	// level NumLevels - 1 is the root.
	for numBlocks > 1 {
		size.levelStart = append(size.levelStart, offset)
		// Round numBlocks up to fill up a block.
		numBlocks += (size.hashesPerBlock - numBlocks%size.hashesPerBlock) % size.hashesPerBlock
		offset += numBlocks / size.hashesPerBlock
		numBlocks = numBlocks / size.hashesPerBlock
		level++
	}
	size.levelStart = append(size.levelStart, offset)
	return size
}

// Generate constructs a Merkle tree for the contents of data. The output is
// written to treeWriter. The treeReader should be able to read the tree after
// it has been written. That is, treeWriter and treeReader should point to the
// same underlying data but have separate cursors.
func Generate(data io.Reader, dataSize int64, treeReader io.Reader, treeWriter io.Writer) ([]byte, error) {
	size := MakeSize(dataSize)

	numBlocks := (dataSize + size.blockSize - 1) / size.blockSize

	var root []byte
	for level := 0; level < len(size.levelStart); level++ {
		for i := int64(0); i < numBlocks; i++ {
			buf := make([]byte, size.blockSize)
			var (
				n   int
				err error
			)
			if level == 0 {
				// Read data block from the target file since level 0 is directly above
				// the raw data block.
				n, err = data.Read(buf)
			} else {
				// Read data block from the tree file since levels higher than 0 are
				// hashing the lower level hashes.
				n, err = treeReader.Read(buf)
			}

			// err is populated as long as the bytes read is smaller than the buffer
			// size. This could be the case if we are reading the last block, and
			// break in that case. If this is the last block, the end of the block
			// will be zero-padded.
			if n == 0 && err == io.EOF {
				break
			} else if err != nil && err != io.EOF {
				return nil, err
			}
			// Hash the bytes in buf.
			digest := sha256.Sum256(buf)

			if level == len(size.levelStart)-1 {
				root = digest[:]
			}

			// Write the generated hash to the end of the tree file.
			if _, err = treeWriter.Write(digest[:]); err != nil {
				return nil, err
			}
		}
		// If the genereated digests do not round up to a block, zero-padding the
		// remaining of the last block. But no need to do so for root.
		if level != len(size.levelStart)-1 && numBlocks%size.hashesPerBlock != 0 {
			zeroBuf := make([]byte, size.blockSize-(numBlocks%size.hashesPerBlock)*size.digestSize)
			if _, err := treeWriter.Write(zeroBuf[:]); err != nil {
				return nil, err
			}
		}
		numBlocks = (numBlocks + size.hashesPerBlock - 1) / size.hashesPerBlock
	}
	return root, nil
}
