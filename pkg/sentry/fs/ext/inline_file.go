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

// inlineFile is a type of regular file. All the data here is stored in the
// inode.Data() array.
type inlineFile struct {
	regFile regularFile
}

// Compiles only if inlineFile implements io.ReaderAt.
var _ io.ReaderAt = (*inlineFile)(nil)

// newInlineFile is the inlineFile constructor.
func newInlineFile(regFile regularFile) *inlineFile {
	file := &inlineFile{regFile: regFile}
	file.regFile.impl = file
	return file
}

// ReadAt implements io.ReaderAt.ReadAt.
func (f *inlineFile) ReadAt(dst []byte, off int64) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}

	size := f.regFile.inode.diskInode.Size()
	if uint64(off) >= size {
		return 0, io.EOF
	}

	to := uint64(off) + uint64(len(dst))
	if to > size {
		to = size
	}

	n := copy(dst, f.regFile.inode.diskInode.Data()[off:to])
	return n, nil
}
