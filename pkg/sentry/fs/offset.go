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

package fs

import (
	"math"

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// OffsetPageEnd returns the file offset rounded up to the nearest
// page boundary. OffsetPageEnd panics if rounding up causes overflow,
// which shouldn't be possible given that offset is an int64.
func OffsetPageEnd(offset int64) uint64 {
	end, ok := usermem.Addr(offset).RoundUp()
	if !ok {
		panic("impossible overflow")
	}
	return uint64(end)
}

// ReadEndOffset returns an exclusive end offset for a read operation
// so that the read does not overflow an int64 nor size.
//
// Parameters:
// - offset: the starting offset of the read.
// - length: the number of bytes to read.
// - size:   the size of the file.
//
// Postconditions: The returned offset is >= offset.
func ReadEndOffset(offset int64, length int64, size int64) int64 {
	if offset >= size {
		return offset
	}
	end := offset + length
	// Don't overflow.
	if end < offset || end > size {
		end = size
	}
	return end
}

// WriteEndOffset returns an exclusive end offset for a write operation
// so that the write does not overflow an int64.
//
// Parameters:
// - offset: the starting offset of the write.
// - length: the number of bytes to write.
//
// Postconditions: The returned offset is >= offset.
func WriteEndOffset(offset int64, length int64) int64 {
	return ReadEndOffset(offset, length, math.MaxInt64)
}
