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
	"sync"

	"gvisor.dev/gvisor/pkg/binary"
)

// blockMapFile is a type of regular file which uses direct/indirect block
// addressing to store file data. This was deprecated in ext4.
type blockMapFile struct {
	regFile regularFile

	// mu serializes changes to fileToPhysBlks.
	mu sync.RWMutex

	// fileToPhysBlks maps the file block numbers to the physical block numbers.
	// the physical block number for the (i)th file block is stored in the (i)th
	// index. This is initialized (at max) with the first 12 entries. The rest
	// have to be read in from disk when required. Protected by mu.
	fileToPhysBlks []uint32
}

// Compiles only if blockMapFile implements fileReader.
var _ fileReader = (*blockMapFile)(nil)

// Read implements fileReader.getFileReader.
func (f *blockMapFile) getFileReader(dev io.ReaderAt, blkSize uint64, offset uint64) io.Reader {
	panic("unimplemented")
}

// newBlockMapFile is the blockMapFile constructor. It initializes the file to
// physical blocks map with (at most) the first 12 (direct) blocks.
func newBlockMapFile(blkSize uint64, regFile regularFile) (*blockMapFile, error) {
	file := &blockMapFile{regFile: regFile}
	file.regFile.impl = file

	toFill := uint64(12)
	blksUsed := regFile.blksUsed(blkSize)
	if blksUsed < toFill {
		toFill = blksUsed
	}

	blkMap := regFile.inode.diskInode.Data()
	file.fileToPhysBlks = make([]uint32, toFill)
	for i := uint64(0); i < toFill; i++ {
		binary.Unmarshal(blkMap[i*4:(i+1)*4], binary.LittleEndian, &file.fileToPhysBlks[i])
	}
	return file, nil
}
