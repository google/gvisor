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

// Compiles only if inlineFile implements fileReader.
var _ fileReader = (*inlineFile)(nil)

// getFileReader implements fileReader.getFileReader.
func (f *inlineFile) getFileReader(_ io.ReaderAt, _ uint64, offset uint64) io.Reader {
	diskInode := f.regFile.inode.diskInode
	return &inlineReader{offset: offset, data: diskInode.Data()[:diskInode.Size()]}
}

// newInlineFile is the inlineFile constructor.
func newInlineFile(regFile regularFile) *inlineFile {
	file := &inlineFile{regFile: regFile}
	file.regFile.impl = file
	return file
}

// inlineReader implements io.Reader which can read the underlying data. This
// is not thread safe.
type inlineReader struct {
	offset uint64
	data   []byte
}

// Compiles only if inlineReader implements io.Reader.
var _ io.Reader = (*inlineReader)(nil)

// Read implements io.Reader.Read.
func (r *inlineReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}

	if int(r.offset) >= len(r.data) {
		return 0, io.EOF
	}

	n := copy(dst, r.data[r.offset:])
	r.offset += uint64(n)
	return n, nil
}
