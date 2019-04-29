// Copyright 2018 The gVisor Authors.
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
	"math"
)

// LockSet maps a set of Locks into a file.  The key is the file offset.

type lockSetFunctions struct{}

func (lockSetFunctions) MinKey() uint64 {
	return 0
}

func (lockSetFunctions) MaxKey() uint64 {
	return math.MaxUint64
}

func (lockSetFunctions) ClearValue(l *Lock) {
	*l = Lock{}
}

func (lockSetFunctions) Merge(r1 LockRange, val1 Lock, r2 LockRange, val2 Lock) (Lock, bool) {
	// Merge only if the Readers/Writers are identical.
	if len(val1.Readers) != len(val2.Readers) {
		return Lock{}, false
	}
	for k := range val1.Readers {
		if !val2.Readers[k] {
			return Lock{}, false
		}
	}
	if val1.HasWriter != val2.HasWriter {
		return Lock{}, false
	}
	if val1.HasWriter {
		if val1.Writer != val2.Writer {
			return Lock{}, false
		}
	}
	return val1, true
}

func (lockSetFunctions) Split(r LockRange, val Lock, split uint64) (Lock, Lock) {
	// Copy the segment so that split segments don't contain map references
	// to other segments.
	val0 := Lock{Readers: make(map[UniqueID]bool)}
	for k, v := range val.Readers {
		val0.Readers[k] = v
	}
	val0.HasWriter = val.HasWriter
	val0.Writer = val.Writer

	return val, val0
}
