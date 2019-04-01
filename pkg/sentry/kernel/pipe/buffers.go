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

package pipe

// Buffer encapsulates a queueable byte buffer that can
// easily be truncated.  It is designed only for use with pipes.
//
// +stateify savable
type Buffer struct {
	bufferEntry
	data []byte
}

// newBuffer initializes a Buffer.
func newBuffer(buf []byte) *Buffer {
	return &Buffer{data: buf}
}

// bytes returns the bytes contained in the buffer.
func (b *Buffer) bytes() []byte {
	return b.data
}

// size returns the number of bytes contained in the buffer.
func (b *Buffer) size() int {
	return len(b.data)
}

// truncate removes the first n bytes from the buffer.
func (b *Buffer) truncate(n int) int {
	if n > len(b.data) {
		panic("Trying to truncate past end of array.")
	}
	b.data = b.data[n:]
	return len(b.data)
}
