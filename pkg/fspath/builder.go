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

package fspath

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/gohacks"
)

// Builder is similar to strings.Builder, but is used to produce pathnames
// given path components in reverse order (from leaf to root). This is useful
// in the common case where a filesystem is represented by a tree of named
// nodes, and the path to a given node must be produced by walking upward from
// that node to a given root.
type Builder struct {
	buf     []byte
	start   int
	needSep bool
}

// Reset resets the Builder to be empty.
func (b *Builder) Reset() {
	b.start = len(b.buf)
	b.needSep = false
}

// Len returns the number of accumulated bytes.
func (b *Builder) Len() int {
	return len(b.buf) - b.start
}

func (b *Builder) needToGrow(n int) bool {
	return b.start < n
}

func (b *Builder) grow(n int) {
	newLen := b.Len() + n
	var newCap int
	if len(b.buf) == 0 {
		newCap = 64 // arbitrary
	} else {
		newCap = 2 * len(b.buf)
	}
	for newCap < newLen {
		newCap *= 2
		if newCap == 0 {
			panic(fmt.Sprintf("required length (%d) causes buffer size to overflow", newLen))
		}
	}
	newBuf := make([]byte, newCap)
	copy(newBuf[newCap-b.Len():], b.buf[b.start:])
	b.start += newCap - len(b.buf)
	b.buf = newBuf
}

// PrependComponent prepends the given path component to b's buffer. A path
// separator is automatically inserted if appropriate.
func (b *Builder) PrependComponent(pc string) {
	if b.needSep {
		b.PrependByte('/')
	}
	b.PrependString(pc)
	b.needSep = true
}

// PrependString prepends the given string to b's buffer.
func (b *Builder) PrependString(str string) {
	if b.needToGrow(len(str)) {
		b.grow(len(str))
	}
	b.start -= len(str)
	copy(b.buf[b.start:], str)
}

// PrependByte prepends the given byte to b's buffer.
func (b *Builder) PrependByte(c byte) {
	if b.needToGrow(1) {
		b.grow(1)
	}
	b.start--
	b.buf[b.start] = c
}

// AppendString appends the given string to b's buffer.
func (b *Builder) AppendString(str string) {
	if b.needToGrow(len(str)) {
		b.grow(len(str))
	}
	oldStart := b.start
	b.start -= len(str)
	copy(b.buf[b.start:], b.buf[oldStart:])
	copy(b.buf[len(b.buf)-len(str):], str)
}

// String returns the accumulated string. No other methods should be called
// after String.
func (b *Builder) String() string {
	return gohacks.StringFromImmutableBytes(b.buf[b.start:])
}
