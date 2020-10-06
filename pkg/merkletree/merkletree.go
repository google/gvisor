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
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// sha256DigestSize specifies the digest size of a SHA256 hash.
	sha256DigestSize = 32
)

// DigestSize returns the size (in bytes) of a digest.
// TODO(b/156980949): Allow config other hash methods (SHA384/SHA512).
func DigestSize() int {
	return sha256DigestSize
}

// Layout defines the scale of a Merkle tree.
type Layout struct {
	// blockSize is the size of a data block to be hashed.
	blockSize int64
	// digestSize is the size of a generated hash.
	digestSize int64
	// levelOffset contains the offset of the beginning of each level in
	// bytes. The number of levels in the tree is the length of the slice.
	// The leaf nodes (level 0) contain hashes of blocks of the input data.
	// Each level N contains hashes of the blocks in level N-1. The highest
	// level is the root hash.
	levelOffset []int64
}

// InitLayout initializes and returns a new Layout object describing the structure
// of a tree. dataSize specifies the size of input data in bytes.
func InitLayout(dataSize int64, dataAndTreeInSameFile bool) Layout {
	layout := Layout{
		blockSize: usermem.PageSize,
		// TODO(b/156980949): Allow config other hash methods (SHA384/SHA512).
		digestSize: sha256DigestSize,
	}

	// treeStart is the offset (in bytes) of the first level of the tree in
	// the file. If data and tree are in different files, treeStart should
	// be zero. If data is in the same file as the tree, treeStart points
	// to the block after the last data block (which may be zero-padded).
	var treeStart int64
	if dataAndTreeInSameFile {
		treeStart = dataSize
		if dataSize%layout.blockSize != 0 {
			treeStart += layout.blockSize - dataSize%layout.blockSize
		}
	}

	numBlocks := (dataSize + layout.blockSize - 1) / layout.blockSize
	level := 0
	offset := int64(0)

	// Calculate the number of levels in the Merkle tree and the beginning
	// offset of each level. Level 0 consists of the leaf nodes that
	// contain the hashes of the data blocks, while level numLevels - 1 is
	// the root.
	for numBlocks > 1 {
		layout.levelOffset = append(layout.levelOffset, treeStart+offset*layout.blockSize)
		// Round numBlocks up to fill up a block.
		numBlocks += (layout.hashesPerBlock() - numBlocks%layout.hashesPerBlock()) % layout.hashesPerBlock()
		offset += numBlocks / layout.hashesPerBlock()
		numBlocks = numBlocks / layout.hashesPerBlock()
		level++
	}
	layout.levelOffset = append(layout.levelOffset, treeStart+offset*layout.blockSize)

	return layout
}

// hashesPerBlock() returns the number of digests in each block.  For example,
// if blockSize is 4096 bytes, and digestSize is 32 bytes, there will be 128
// hashesPerBlock. Therefore 128 hashes in one level will be combined in one
// hash in the level above.
func (layout Layout) hashesPerBlock() int64 {
	return layout.blockSize / layout.digestSize
}

// numLevels returns the total number of levels in the Merkle tree.
func (layout Layout) numLevels() int {
	return len(layout.levelOffset)
}

// rootLevel returns the level of the root hash.
func (layout Layout) rootLevel() int {
	return layout.numLevels() - 1
}

// digestOffset finds the offset of a digest from the beginning of the tree.
// The target digest is at level of the tree, with index from the beginning of
// the current level.
func (layout Layout) digestOffset(level int, index int64) int64 {
	return layout.levelOffset[level] + index*layout.digestSize
}

// blockOffset finds the offset of a block from the beginning of the tree.  The
// target block is at level of the tree, with index from the beginning of the
// current level.
func (layout Layout) blockOffset(level int, index int64) int64 {
	return layout.levelOffset[level] + index*layout.blockSize
}

// Generate constructs a Merkle tree for the contents of data. The output is
// written to treeWriter. The treeReader should be able to read the tree after
// it has been written. That is, treeWriter and treeReader should point to the
// same underlying data but have separate cursors.
// Generate will modify the cursor for data, but always restores it to its
// original position upon exit. The cursor for tree is modified and not
// restored.
func Generate(data io.ReadSeeker, dataSize int64, treeReader io.ReadSeeker, treeWriter io.WriteSeeker, dataAndTreeInSameFile bool) ([]byte, error) {
	layout := InitLayout(dataSize, dataAndTreeInSameFile)

	numBlocks := (dataSize + layout.blockSize - 1) / layout.blockSize

	// If the data is in the same file as the tree, zero pad the last data
	// block.
	bytesInLastBlock := dataSize % layout.blockSize
	if dataAndTreeInSameFile && bytesInLastBlock != 0 {
		zeroBuf := make([]byte, layout.blockSize-bytesInLastBlock)
		if _, err := treeWriter.Seek(0, io.SeekEnd); err != nil && err != io.EOF {
			return nil, err
		}
		if _, err := treeWriter.Write(zeroBuf); err != nil {
			return nil, err
		}
	}

	// Store the current offset, so we can set it back once verification
	// finishes.
	origOffset, err := data.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	defer data.Seek(origOffset, io.SeekStart)

	// Read from the beginning of both data and treeReader.
	if _, err := data.Seek(0, io.SeekStart); err != nil && err != io.EOF {
		return nil, err
	}

	if _, err := treeReader.Seek(0, io.SeekStart); err != nil && err != io.EOF {
		return nil, err
	}

	var root []byte
	for level := 0; level < layout.numLevels(); level++ {
		for i := int64(0); i < numBlocks; i++ {
			buf := make([]byte, layout.blockSize)
			var (
				n   int
				err error
			)
			if level == 0 {
				// Read data block from the target file since level 0 includes hashes
				// of blocks in the input data.
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

			if level == layout.rootLevel() {
				root = digest[:]
			}

			// Write the generated hash to the end of the tree file.
			if _, err = treeWriter.Write(digest[:]); err != nil {
				return nil, err
			}
		}
		// If the generated digests do not round up to a block, zero-padding the
		// remaining of the last block. But no need to do so for root.
		if level != layout.rootLevel() && numBlocks%layout.hashesPerBlock() != 0 {
			zeroBuf := make([]byte, layout.blockSize-(numBlocks%layout.hashesPerBlock())*layout.digestSize)
			if _, err := treeWriter.Write(zeroBuf[:]); err != nil {
				return nil, err
			}
		}
		numBlocks = (numBlocks + layout.hashesPerBlock() - 1) / layout.hashesPerBlock()
	}
	return root, nil
}

// Verify verifies the content read from data with offset. The content is
// verified against tree. If content spans across multiple blocks, each block is
// verified. Verification fails if the hash of the data does not match the tree
// at any level, or if the final root hash does not match expectedRoot.
// Once the data is verified, it will be written using w.
// Verify will modify the cursor for data, but always restores it to its
// original position upon exit. The cursor for tree is modified and not
// restored.
func Verify(w io.Writer, data, tree io.ReadSeeker, dataSize int64, readOffset int64, readSize int64, expectedRoot []byte, dataAndTreeInSameFile bool) (int64, error) {
	if readSize <= 0 {
		return 0, fmt.Errorf("Unexpected read size: %d", readSize)
	}
	layout := InitLayout(int64(dataSize), dataAndTreeInSameFile)

	// Calculate the index of blocks that includes the target range in input
	// data.
	firstDataBlock := readOffset / layout.blockSize
	lastDataBlock := (readOffset + readSize - 1) / layout.blockSize

	// Store the current offset, so we can set it back once verification
	// finishes.
	origOffset, err := data.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, fmt.Errorf("Find current data offset failed: %v", err)
	}
	defer data.Seek(origOffset, io.SeekStart)

	// Move to the first block that contains target data.
	if _, err := data.Seek(firstDataBlock*layout.blockSize, io.SeekStart); err != nil {
		return 0, fmt.Errorf("Seek to datablock start failed: %v", err)
	}

	buf := make([]byte, layout.blockSize)
	var readErr error
	total := int64(0)
	for i := firstDataBlock; i <= lastDataBlock; i++ {
		// Read a block that includes all or part of target range in
		// input data.
		bytesRead, err := data.Read(buf)
		readErr = err
		// If at the end of input data and all previous blocks are
		// verified, return the verified input data and EOF.
		if readErr == io.EOF && bytesRead == 0 {
			break
		}
		if readErr != nil && readErr != io.EOF {
			return 0, fmt.Errorf("Read from data failed: %v", err)
		}
		// If this is the end of file, zero the remaining bytes in buf,
		// otherwise they are still from the previous block.
		// TODO(b/162908070): Investigate possible issues with zero
		// padding the data.
		if bytesRead < len(buf) {
			for j := bytesRead; j < len(buf); j++ {
				buf[j] = 0
			}
		}
		if err := verifyBlock(tree, layout, buf, i, expectedRoot); err != nil {
			return 0, err
		}
		// startOff is the beginning of the read range within the
		// current data block. Note that for all blocks other than the
		// first, startOff should be 0.
		startOff := int64(0)
		if i == firstDataBlock {
			startOff = readOffset % layout.blockSize
		}
		// endOff is the end of the read range within the current data
		// block. Note that for all blocks other than the last,  endOff
		// should be the block size.
		endOff := layout.blockSize
		if i == lastDataBlock {
			endOff = (readOffset+readSize-1)%layout.blockSize + 1
		}
		// If the provided size exceeds the end of input data, we should
		// only copy the parts in buf that's part of input data.
		if startOff > int64(bytesRead) {
			startOff = int64(bytesRead)
		}
		if endOff > int64(bytesRead) {
			endOff = int64(bytesRead)
		}
		n, err := w.Write(buf[startOff:endOff])
		if err != nil {
			return total, err
		}
		total += int64(n)

	}
	return total, readErr
}

// verifyBlock verifies a block against tree. index is the number of block in
// original data. The block is verified through each level of the tree. It
// fails if the calculated hash from block is different from any level of
// hashes stored in tree. And the final root hash is compared with
// expectedRoot.  verifyBlock modifies the cursor for tree. Users needs to
// maintain the cursor if intended.
func verifyBlock(tree io.ReadSeeker, layout Layout, dataBlock []byte, blockIndex int64, expectedRoot []byte) error {
	if len(dataBlock) != int(layout.blockSize) {
		return fmt.Errorf("incorrect block size")
	}

	expectedDigest := make([]byte, layout.digestSize)
	treeBlock := make([]byte, layout.blockSize)
	var digest []byte
	for level := 0; level < layout.numLevels(); level++ {
		// Calculate hash.
		if level == 0 {
			digestArray := sha256.Sum256(dataBlock)
			digest = digestArray[:]
		} else {
			// Read a block in previous level that contains the
			// hash we just generated, and generate a next level
			// hash from it.
			if _, err := tree.Seek(layout.blockOffset(level-1, blockIndex), io.SeekStart); err != nil {
				return err
			}
			if _, err := tree.Read(treeBlock); err != nil {
				return err
			}
			digestArray := sha256.Sum256(treeBlock)
			digest = digestArray[:]
		}

		// Move to stored hash for the current block, read the digest
		// and store in expectedDigest.
		if _, err := tree.Seek(layout.digestOffset(level, blockIndex), io.SeekStart); err != nil {
			return err
		}
		if _, err := tree.Read(expectedDigest); err != nil {
			return err
		}

		if !bytes.Equal(digest, expectedDigest) {
			return fmt.Errorf("Verification failed")
		}

		// If this is the root layer, no need to generate next level
		// hash.
		if level == layout.rootLevel() {
			break
		}
		blockIndex = blockIndex / layout.hashesPerBlock()
	}

	// Verification for the tree succeeded. Now compare the root hash in the
	// tree with expectedRoot.
	if !bytes.Equal(digest[:], expectedRoot) {
		return fmt.Errorf("Verification failed")
	}
	return nil
}
