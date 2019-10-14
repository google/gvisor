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

package atomicbitops

import (
	"sync/atomic"
)

// IncUnlessNegativeInt32 increments the value stored at the given address and
// returns true; unless the value stored in the pointer is negative, in which
// case it is left unmodified and false is returned.
func IncUnlessNegativeInt32(addr *int32) bool {
	var (
		next int32
		prev int32
	)

	for {
		prev = atomic.LoadInt32(addr)
		if prev < 0 {
			return false
		}
		next = prev + 1;
		if (atomic.CompareAndSwapInt32(addr, prev, next)) {
			return true
		}
	}
}

// DecUnlessPositiveInt32 decrements the value stored at the given address and
// returns true; unless the value stored in the pointer is positive, in which
// case it is left unmodified and false is returned.
func DecUnlessPositiveInt32(addr *int32) bool {
	var (
		next int32
		prev int32
	)

	for {
		prev = atomic.LoadInt32(addr)
		if prev > 0 {
			return false
		}
		next = prev - 1;
		if (atomic.CompareAndSwapInt32(addr, prev, next)) {
			return true
		}
	}
}
