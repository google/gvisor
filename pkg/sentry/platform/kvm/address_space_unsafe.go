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

package kvm

import (
	"sync/atomic"
	"unsafe"
)

// dirtySet tracks vCPUs for invalidation.
type dirtySet struct {
	vCPUs []unsafe.Pointer
}

// makeDirtySet makes a new dirtySet.
func makeDirtySet(size int) dirtySet {
	return dirtySet{
		vCPUs: make([]unsafe.Pointer, size),
	}
}

// size is the size of the set.
func (ds *dirtySet) size() int {
	return len(ds.vCPUs)
}

// swap sets the given index and returns the previous value.
//
// The index is typically the id for a non-nil vCPU.
func (ds *dirtySet) swap(index int, c *vCPU) *vCPU {
	return (*vCPU)(atomic.SwapPointer(&ds.vCPUs[index], unsafe.Pointer(c)))
}
