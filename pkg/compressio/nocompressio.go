// Copyright 2023 The gVisor Authors.
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

package compressio

import (
	"io"
)

// NewSimpleReader returns a new (uncompressed) reader. If key is non-nil, the data stream
// is assumed to contain expected hash values. See package comments for
// details.
func NewSimpleReader(in io.Reader, key []byte) (*Reader, error) {
	return newReader(in, key, true /* uncompressed */)
}

// NewSimpleWriter returns a new non-compressing writer. If key is non-nil, hash values are
// generated and written out for compressed bytes. See package comments for
// details.
func NewSimpleWriter(out io.Writer, key []byte) (*Writer, error) {
	return newWriter(out, key, 1024*1024 /* chunkSize */, true /* uncompressed */, 0)
}
