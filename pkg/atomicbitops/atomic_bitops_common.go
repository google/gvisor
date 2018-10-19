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

// +build !amd64

package atomicbitops

import (
	"sync/atomic"
)

// AndUint32 atomically applies bitwise and operation to *addr with val.
func AndUint32(addr *uint32, val uint32) {
	for {
		o := atomic.LoadUint32(addr)
		n := o & val
		if atomic.CompareAndSwapUint32(addr, o, n) {
			break
		}
	}
}

// OrUint32 atomically applies bitwise or operation to *addr with val.
func OrUint32(addr *uint32, val uint32) {
	for {
		o := atomic.LoadUint32(addr)
		n := o | val
		if atomic.CompareAndSwapUint32(addr, o, n) {
			break
		}
	}
}

// XorUint32 atomically applies bitwise xor operation to *addr with val.
func XorUint32(addr *uint32, val uint32) {
	for {
		o := atomic.LoadUint32(addr)
		n := o ^ val
		if atomic.CompareAndSwapUint32(addr, o, n) {
			break
		}
	}
}

// CompareAndSwapUint32 is like sync/atomic.CompareAndSwapUint32, but returns
// the value previously stored at addr.
func CompareAndSwapUint32(addr *uint32, old, new uint32) (prev uint32) {
	for {
		prev = atomic.LoadUint32(addr)
		if prev != old {
			return
		}
		if atomic.CompareAndSwapUint32(addr, old, new) {
			return
		}
	}
}

// AndUint64 atomically applies bitwise and operation to *addr with val.
func AndUint64(addr *uint64, val uint64) {
	for {
		o := atomic.LoadUint64(addr)
		n := o & val
		if atomic.CompareAndSwapUint64(addr, o, n) {
			break
		}
	}
}

// OrUint64 atomically applies bitwise or operation to *addr with val.
func OrUint64(addr *uint64, val uint64) {
	for {
		o := atomic.LoadUint64(addr)
		n := o | val
		if atomic.CompareAndSwapUint64(addr, o, n) {
			break
		}
	}
}

// XorUint64 atomically applies bitwise xor operation to *addr with val.
func XorUint64(addr *uint64, val uint64) {
	for {
		o := atomic.LoadUint64(addr)
		n := o ^ val
		if atomic.CompareAndSwapUint64(addr, o, n) {
			break
		}
	}
}

// CompareAndSwapUint64 is like sync/atomic.CompareAndSwapUint64, but returns
// the value previously stored at addr.
func CompareAndSwapUint64(addr *uint64, old, new uint64) (prev uint64) {
	for {
		prev = atomic.LoadUint64(addr)
		if prev != old {
			return
		}
		if atomic.CompareAndSwapUint64(addr, old, new) {
			return
		}
	}
}

// IncUnlessZeroInt32 increments the value stored at the given address and
// returns true; unless the value stored in the pointer is zero, in which case
// it is left unmodified and false is returned.
func IncUnlessZeroInt32(addr *int32) bool {
	for {
		v := atomic.LoadInt32(addr)
		if v == 0 {
			return false
		}

		if atomic.CompareAndSwapInt32(addr, v, v+1) {
			return true
		}
	}
}

// DecUnlessOneInt32 decrements the value stored at the given address and
// returns true; unless the value stored in the pointer is 1, in which case it
// is left unmodified and false is returned.
func DecUnlessOneInt32(addr *int32) bool {
	for {
		v := atomic.LoadInt32(addr)
		if v == 1 {
			return false
		}

		if atomic.CompareAndSwapInt32(addr, v, v-1) {
			return true
		}
	}
}
