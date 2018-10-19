// Copyright 2018 Google LLC
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

package secio

import (
	"io"
)

// FullReader adapts an io.Reader to never return partial reads with a nil
// error.
type FullReader struct {
	Reader io.Reader
}

// Read implements io.Reader.Read.
func (r FullReader) Read(dst []byte) (int, error) {
	n, err := io.ReadFull(r.Reader, dst)
	if err == io.ErrUnexpectedEOF {
		return n, io.EOF
	}
	return n, err
}
