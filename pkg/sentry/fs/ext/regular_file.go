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
)

// regularFile represents a regular file's inode. This too follows the
// inheritance pattern prevelant in the vfs layer described in
// pkg/sentry/vfs/README.md.
type regularFile struct {
	inode inode

	// This is immutable. The first field of fileReader implementations must be
	// regularFile to ensure temporality.
	impl io.ReaderAt
}

// newRegularFile is the regularFile constructor. It figures out what kind of
// file this is and initializes the fileReader.
func newRegularFile(inode inode) (*regularFile, error) {
	regFile := regularFile{
		inode: inode,
	}

	inodeFlags := inode.diskInode.Flags()

	if inodeFlags.Extents {
		file, err := newExtentFile(regFile)
		if err != nil {
			return nil, err
		}

		file.regFile.inode.impl = &file.regFile
		return &file.regFile, nil
	}

	if inodeFlags.Inline {
		if inode.diskInode.Size() > 60 {
			panic("ext fs: inline file larger than 60 bytes")
		}

		file := newInlineFile(regFile)
		file.regFile.inode.impl = &file.regFile
		return &file.regFile, nil
	}

	file, err := newBlockMapFile(regFile)
	if err != nil {
		return nil, err
	}
	file.regFile.inode.impl = &file.regFile
	return &file.regFile, nil
}

func (f *regularFile) blksUsed(blkSize uint64) uint64 {
	return (f.inode.diskInode.Size() + blkSize - 1) / blkSize
}
