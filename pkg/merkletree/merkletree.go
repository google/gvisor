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
	"crypto/sha512"
	"encoding/gob"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"

	"gvisor.dev/gvisor/pkg/hostarch"
)

const (
	// sha256DigestSize specifies the digest size of a SHA256 hash.
	sha256DigestSize = 32
	// sha512DigestSize specifies the digest size of a SHA512 hash.
	sha512DigestSize = 64
)

// DigestSize returns the size (in bytes) of a digest.
func DigestSize(hashAlgorithm int) int {
	switch hashAlgorithm {
	case linux.FS_VERITY_HASH_ALG_SHA256:
		return sha256DigestSize
	case linux.FS_VERITY_HASH_ALG_SHA512:
		return sha512DigestSize
	default:
		return -1
	}
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
func InitLayout(dataSize int64, hashAlgorithms int, dataAndTreeInSameFile bool) (Layout, error) {
	layout := Layout{
		blockSize: hostarch.PageSize,
	}

	switch hashAlgorithms {
	case linux.FS_VERITY_HASH_ALG_SHA256:
		layout.digestSize = sha256DigestSize
	case linux.FS_VERITY_HASH_ALG_SHA512:
		layout.digestSize = sha512DigestSize
	default:
		return Layout{}, fmt.Errorf("unexpected hash algorithms")
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

	return layout, nil
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

// VerityDescriptor is a struct that is serialized and hashed to get a file's
// root hash, which contains the root hash of the raw content and the file's
// meatadata.
type VerityDescriptor struct {
	Name          string
	FileSize      int64
	Mode          uint32
	UID           uint32
	GID           uint32
	Children      []string
	SymlinkTarget string
	RootHash      []byte
}

func (d *VerityDescriptor) encode() []byte {
	b := new(bytes.Buffer)
	e := gob.NewEncoder(b)
	e.Encode(d)
	return b.Bytes()
}

// verify generates a hash from d, and compares it with expected.
func (d *VerityDescriptor) verify(expected []byte, hashAlgorithms int) error {
	h, err := hashData(d.encode(), hashAlgorithms)
	if err != nil {
		return err
	}
	if !bytes.Equal(h[:], expected) {
		return fmt.Errorf("unexpected root hash")
	}
	return nil

}

// hashData hashes data and returns the result hash based on the hash
// algorithms.
func hashData(data []byte, hashAlgorithms int) ([]byte, error) {
	var digest []byte
	switch hashAlgorithms {
	case linux.FS_VERITY_HASH_ALG_SHA256:
		digestArray := sha256.Sum256(data)
		digest = digestArray[:]
	case linux.FS_VERITY_HASH_ALG_SHA512:
		digestArray := sha512.Sum512(data)
		digest = digestArray[:]
	default:
		return nil, fmt.Errorf("unexpected hash algorithms")
	}
	return digest, nil
}

// GenerateParams contains the parameters used to generate a Merkle tree for a
// given file.
type GenerateParams struct {
	// File is a reader of the file to be hashed.
	File io.ReaderAt
	// Size is the size of the file.
	Size int64
	// Name is the name of the target file.
	Name string
	// Mode is the mode of the target file.
	Mode uint32
	// UID is the user ID of the target file.
	UID uint32
	// GID is the group ID of the target file.
	GID uint32
	// Children is a map of children names for a directory. It should be
	// empty for a regular file.
	Children []string
	// SymlinkTarget is the target path of a symlink file, or "" if the file is not a symlink.
	SymlinkTarget string
	// HashAlgorithms is the algorithms used to hash data.
	HashAlgorithms int
	// TreeReader is a reader for the Merkle tree.
	TreeReader io.ReaderAt
	// TreeWriter is a writer for the Merkle tree.
	TreeWriter io.Writer
	// DataAndTreeInSameFile is true if data and Merkle tree are in the same
	// file, or false if Merkle tree is a separate file from data.
	DataAndTreeInSameFile bool
}

// Generate constructs a Merkle tree for the contents of params.File. The
// output is written to params.TreeWriter.
//
// Generate returns a hash of a VerityDescriptor, which contains the file
// metadata and the hash from file content.
func Generate(params *GenerateParams) ([]byte, error) {
	descriptor := VerityDescriptor{
		FileSize:      params.Size,
		Name:          params.Name,
		Mode:          params.Mode,
		UID:           params.UID,
		GID:           params.GID,
		Children:      params.Children,
		SymlinkTarget: params.SymlinkTarget,
	}

	// If file is a symlink do not generate root hash for file content.
	if params.SymlinkTarget != "" {
		return hashData(descriptor.encode(), params.HashAlgorithms)
	}

	layout, err := InitLayout(params.Size, params.HashAlgorithms, params.DataAndTreeInSameFile)
	if err != nil {
		return nil, err
	}

	numBlocks := (params.Size + layout.blockSize - 1) / layout.blockSize

	// If the data is in the same file as the tree, zero pad the last data
	// block.
	bytesInLastBlock := params.Size % layout.blockSize
	if params.DataAndTreeInSameFile && bytesInLastBlock != 0 {
		zeroBuf := make([]byte, layout.blockSize-bytesInLastBlock)
		if _, err := params.TreeWriter.Write(zeroBuf); err != nil {
			return nil, err
		}
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
				n, err = params.File.ReadAt(buf, i*layout.blockSize)
			} else {
				// Read data block from the tree file since levels higher than 0 are
				// hashing the lower level hashes.
				n, err = params.TreeReader.ReadAt(buf, layout.blockOffset(level-1, i))
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
			digest, err := hashData(buf, params.HashAlgorithms)
			if err != nil {
				return nil, err
			}

			if level == layout.rootLevel() {
				root = digest
			}

			// Write the generated hash to the end of the tree file.
			if _, err = params.TreeWriter.Write(digest[:]); err != nil {
				return nil, err
			}
		}
		// If the generated digests do not round up to a block, zero-padding the
		// remaining of the last block. But no need to do so for root.
		if level != layout.rootLevel() && numBlocks%layout.hashesPerBlock() != 0 {
			zeroBuf := make([]byte, layout.blockSize-(numBlocks%layout.hashesPerBlock())*layout.digestSize)
			if _, err := params.TreeWriter.Write(zeroBuf[:]); err != nil {
				return nil, err
			}
		}
		numBlocks = (numBlocks + layout.hashesPerBlock() - 1) / layout.hashesPerBlock()
	}
	descriptor.RootHash = root
	return hashData(descriptor.encode(), params.HashAlgorithms)
}

// VerifyParams contains the params used to verify a portion of a file against
// a Merkle tree.
type VerifyParams struct {
	// Out will be filled with verified data.
	Out io.Writer
	// File is a handler on the file to be verified.
	File io.ReaderAt
	// tree is a handler on the Merkle tree used to verify file.
	Tree io.ReaderAt
	// Size is the size of the file.
	Size int64
	// Name is the name of the target file.
	Name string
	// Mode is the mode of the target file.
	Mode uint32
	// UID is the user ID of the target file.
	UID uint32
	// GID is the group ID of the target file.
	GID uint32
	// Children is a map of children names for a directory. It should be
	// empty for a regular file.
	Children []string
	// SymlinkTarget is the target path of a symlink file, or "" if the file is not a symlink.
	SymlinkTarget string
	// HashAlgorithms is the algorithms used to hash data.
	HashAlgorithms int
	// ReadOffset is the offset of the data range to be verified.
	ReadOffset int64
	// ReadSize is the size of the data range to be verified.
	ReadSize int64
	// Expected is a trusted hash for the file. It is compared with the
	// calculated root hash to verify the content.
	Expected []byte
	// DataAndTreeInSameFile is true if data and Merkle tree are in the same
	// file, or false if Merkle tree is a separate file from data.
	DataAndTreeInSameFile bool
}

// verifyMetadata verifies the metadata by hashing a descriptor that contains
// the metadata and compare the generated hash with expected.
//
// For verifyMetadata, params.data is not needed. It only accesses params.tree
// for the raw root hash.
func verifyMetadata(params *VerifyParams, layout *Layout) error {
	var root []byte
	// Only read the root hash if we expect that the file is not a symlink and its
	// Merkle tree file is non-empty.
	if params.Size != 0 && params.SymlinkTarget == "" {
		root = make([]byte, layout.digestSize)
		if _, err := params.Tree.ReadAt(root, layout.blockOffset(layout.rootLevel(), 0 /* index */)); err != nil {
			return fmt.Errorf("failed to read root hash: %w", err)
		}
	}
	descriptor := VerityDescriptor{
		Name:          params.Name,
		FileSize:      params.Size,
		Mode:          params.Mode,
		UID:           params.UID,
		GID:           params.GID,
		Children:      params.Children,
		SymlinkTarget: params.SymlinkTarget,
		RootHash:      root,
	}
	return descriptor.verify(params.Expected, params.HashAlgorithms)
}

// Verify verifies the content read from data with offset. The content is
// verified against tree. If content spans across multiple blocks, each block is
// verified. Verification fails if the hash of the data does not match the tree
// at any level, or if the final root hash does not match expected.
// Once the data is verified, it will be written using params.Out.
//
// Verify checks for both target file content and metadata. If readSize is 0,
// only metadata is checked.
func Verify(params *VerifyParams) (int64, error) {
	if params.ReadSize < 0 {
		return 0, fmt.Errorf("unexpected read size: %d", params.ReadSize)
	}
	layout, err := InitLayout(int64(params.Size), params.HashAlgorithms, params.DataAndTreeInSameFile)
	if err != nil {
		return 0, err
	}
	if params.ReadSize == 0 {
		return 0, verifyMetadata(params, &layout)
	}

	// Calculate the index of blocks that includes the target range in input
	// data.
	firstDataBlock := params.ReadOffset / layout.blockSize
	lastDataBlock := (params.ReadOffset + params.ReadSize - 1) / layout.blockSize

	size := (lastDataBlock - firstDataBlock + 1) * layout.blockSize
	retBuf := make([]byte, size)
	n, err := params.File.ReadAt(retBuf, firstDataBlock*layout.blockSize)
	if err != nil && err != io.EOF {
		return 0, err
	}
	total := int64(n)
	bytesRead := int64(0)

	for i := firstDataBlock; i <= lastDataBlock; i++ {
		// Reach the end of file during verification.
		if total <= 0 {
			return bytesRead, io.EOF
		}
		// Read a block that includes all or part of target range in
		// input data.
		buf := retBuf[(i-firstDataBlock)*layout.blockSize : (i-firstDataBlock+1)*layout.blockSize]

		descriptor := VerityDescriptor{
			Name:          params.Name,
			FileSize:      params.Size,
			Mode:          params.Mode,
			UID:           params.UID,
			GID:           params.GID,
			SymlinkTarget: params.SymlinkTarget,
			Children:      params.Children,
		}
		if err := verifyBlock(params.Tree, &descriptor, &layout, buf, i, params.HashAlgorithms, params.Expected); err != nil {
			return bytesRead, err
		}

		// startOff is the beginning of the read range within the
		// current data block. Note that for all blocks other than the
		// first, startOff should be 0.
		startOff := int64(0)
		if i == firstDataBlock {
			startOff = params.ReadOffset % layout.blockSize
		}
		// endOff is the end of the read range within the current data
		// block. Note that for all blocks other than the last,  endOff
		// should be the block size.
		endOff := layout.blockSize
		if i == lastDataBlock {
			endOff = (params.ReadOffset+params.ReadSize-1)%layout.blockSize + 1
		}

		// If the provided size exceeds the end of input data, we should
		// only copy the parts in buf that's part of input data.
		if startOff > total {
			startOff = total
		}
		if endOff > total {
			endOff = total
		}

		n, err := params.Out.Write(buf[startOff:endOff])
		if err != nil {
			return bytesRead, err
		}
		bytesRead += int64(n)
		total -= endOff
	}
	return bytesRead, nil
}

// verifyBlock verifies a block against tree. index is the number of block in
// original data. The block is verified through each level of the tree. It
// fails if the calculated hash from block is different from any level of
// hashes stored in tree. And the final root hash is compared with
// expected.
func verifyBlock(tree io.ReaderAt, descriptor *VerityDescriptor, layout *Layout, dataBlock []byte, blockIndex int64, hashAlgorithms int, expected []byte) error {
	if len(dataBlock) != int(layout.blockSize) {
		return fmt.Errorf("incorrect block size")
	}

	expectedDigest := make([]byte, layout.digestSize)
	treeBlock := make([]byte, layout.blockSize)
	var digest []byte
	for level := 0; level < layout.numLevels(); level++ {
		// Calculate hash.
		if level == 0 {
			h, err := hashData(dataBlock, hashAlgorithms)
			if err != nil {
				return err
			}
			digest = h
		} else {
			// Read a block in previous level that contains the
			// hash we just generated, and generate a next level
			// hash from it.
			if _, err := tree.ReadAt(treeBlock, layout.blockOffset(level-1, blockIndex)); err != nil {
				return err
			}
			h, err := hashData(treeBlock, hashAlgorithms)
			if err != nil {
				return err
			}
			digest = h
		}

		// Read the digest for the current block and store in
		// expectedDigest.
		if _, err := tree.ReadAt(expectedDigest, layout.digestOffset(level, blockIndex)); err != nil {
			return err
		}

		if !bytes.Equal(digest, expectedDigest) {
			return fmt.Errorf("verification failed")
		}
		blockIndex = blockIndex / layout.hashesPerBlock()
	}

	// Verification for the tree succeeded. Now hash the descriptor with
	// the root hash and compare it with expected.
	descriptor.RootHash = digest
	return descriptor.verify(expected, hashAlgorithms)
}
