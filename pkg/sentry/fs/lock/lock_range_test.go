// Copyright 2018 Google Inc.
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

package lock

import (
	"syscall"
	"testing"
)

func TestComputeRange(t *testing.T) {
	tests := []struct {
		// Description of test.
		name string

		// Requested start of the lock range.
		start int64

		// Requested length of the lock range,
		// can be negative :(
		length int64

		// Pre-computed file offset based on whence.
		// Will be added to start.
		offset int64

		// Expected error.
		err error

		// If error is nil, the expected LockRange.
		LockRange
	}{
		{
			name:      "offset, start, and length all zero",
			LockRange: LockRange{Start: 0, End: LockEOF},
		},
		{
			name:      "zero offset, zero start, positive length",
			start:     0,
			length:    4096,
			offset:    0,
			LockRange: LockRange{Start: 0, End: 4096},
		},
		{
			name:   "zero offset, negative start",
			start:  -4096,
			offset: 0,
			err:    syscall.EINVAL,
		},
		{
			name:      "large offset, negative start, positive length",
			start:     -2048,
			length:    2048,
			offset:    4096,
			LockRange: LockRange{Start: 2048, End: 4096},
		},
		{
			name:      "large offset, negative start, zero length",
			start:     -2048,
			length:    0,
			offset:    4096,
			LockRange: LockRange{Start: 2048, End: LockEOF},
		},
		{
			name:   "zero offset, zero start, negative length",
			start:  0,
			length: -4096,
			offset: 0,
			err:    syscall.EINVAL,
		},
		{
			name:      "large offset, zero start, negative length",
			start:     0,
			length:    -4096,
			offset:    4096,
			LockRange: LockRange{Start: 0, End: 4096},
		},
		{
			name:      "offset, start, and length equal, length is negative",
			start:     1024,
			length:    -1024,
			offset:    1024,
			LockRange: LockRange{Start: 1024, End: 2048},
		},
		{
			name:      "offset, start, and length equal, start is negative",
			start:     -1024,
			length:    1024,
			offset:    1024,
			LockRange: LockRange{Start: 0, End: 1024},
		},
		{
			name:      "offset, start, and length equal, offset is negative",
			start:     1024,
			length:    1024,
			offset:    -1024,
			LockRange: LockRange{Start: 0, End: 1024},
		},
		{
			name:   "offset, start, and length equal, all negative",
			start:  -1024,
			length: -1024,
			offset: -1024,
			err:    syscall.EINVAL,
		},
		{
			name:      "offset, start, and length equal, all positive",
			start:     1024,
			length:    1024,
			offset:    1024,
			LockRange: LockRange{Start: 2048, End: 3072},
		},
	}

	for _, test := range tests {
		rng, err := ComputeRange(test.start, test.length, test.offset)
		if err != test.err {
			t.Errorf("%s: lockRange(%d, %d, %d) got error %v, want %v", test.name, test.start, test.length, test.offset, err, test.err)
			continue
		}
		if err == nil && rng != test.LockRange {
			t.Errorf("%s: lockRange(%d, %d, %d) got LockRange %v, want %v", test.name, test.start, test.length, test.offset, rng, test.LockRange)
		}
	}
}
