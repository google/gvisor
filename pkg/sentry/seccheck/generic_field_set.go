// Copyright 2021 The gVisor Authors.
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

package seccheck

import (
	"sync/atomic"
)

// NumFieldSetWords is an optional template parameter that must be set to the
// number of fields in the corresponding Info struct divided by 32, rounded up.
const NumFieldSetWords = 1

// Field represents a field in the corresponding Info struct.
type Field uint

// FieldSet is a bitmap representing a set of Fields. The zero value of
// FieldSet is an empty set.
type FieldSet [NumFieldSetWords]uint32

// Contains returns true if f is present in the FieldSet.
func (fs *FieldSet) Contains(f Field) bool {
	word, bit := f/32, f%32
	return fs[word]&(uint32(1)<<bit) != 0
}

// Add adds f to the FieldSet.
func (fs *FieldSet) Add(f Field) {
	word, bit := f/32, f%32
	fs[word] |= uint32(1) << bit
}

// Remove removes f from the FieldSet.
func (fs *FieldSet) Remove(f Field) {
	word, bit := f/32, f%32
	fs[word] &^= uint32(1) << bit
}

func (fs *FieldSet) atomicLoad() (copied FieldSet) {
	// As of this writing, Go will not inline a function containing a loop, so
	// this unrolling allows this function to be inlined in the common case.
	if NumFieldSetWords == 1 {
		copied[0] = atomic.LoadUint32(&fs[0])
	} else {
		for i := range copied {
			copied[i] = atomic.LoadUint32(&fs[i])
		}
	}
	return
}

func (fs *FieldSet) addLocked(f Field) {
	word, bit := f/32, f%32
	atomic.StoreUint32(&fs[word], fs[word]|uint32(1)<<bit)
}
