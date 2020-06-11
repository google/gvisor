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
