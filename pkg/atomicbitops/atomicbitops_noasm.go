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

//go:build !amd64 && !arm64
// +build !amd64,!arm64

package atomicbitops

import "sync/atomic"

//go:nosplit
func AndUint32(addr *Uint32, val uint32) {
	for {
		o := addr.Load()
		n := o & val
		if atomic.CompareAndSwapUint32(&addr.value, o, n) {
			break
		}
	}
}

//go:nosplit
func OrUint32(addr *Uint32, val uint32) {
	for {
		o := addr.Load()
		n := o | val
		if atomic.CompareAndSwapUint32(&addr.value, o, n) {
			break
		}
	}
}

//go:nosplit
func XorUint32(addr *Uint32, val uint32) {
	for {
		o := addr.Load()
		n := o ^ val
		if atomic.CompareAndSwapUint32(&addr.value, o, n) {
			break
		}
	}
}

//go:nosplit
func CompareAndSwapUint32(addr *Uint32, old, new uint32) (prev uint32) {
	for {
		prev = addr.Load()
		if prev != old {
			return
		}
		if atomic.CompareAndSwapUint32(&addr.value, old, new) {
			return
		}
	}
}

//go:nosplit
func AndUint64(addr *Uint64, val uint64) {
	for {
		o := atomic.LoadUint64(addr.ptr())
		n := o & val
		if atomic.CompareAndSwapUint64(addr.ptr(), o, n) {
			break
		}
	}
}

//go:nosplit
func OrUint64(addr *Uint64, val uint64) {
	for {
		o := atomic.LoadUint64(addr.ptr())
		n := o | val
		if atomic.CompareAndSwapUint64(addr.ptr(), o, n) {
			break
		}
	}
}

//go:nosplit
func XorUint64(addr *Uint64, val uint64) {
	for {
		o := atomic.LoadUint64(addr.ptr())
		n := o ^ val
		if atomic.CompareAndSwapUint64(addr.ptr(), o, n) {
			break
		}
	}
}

//go:nosplit
func CompareAndSwapUint64(addr *Uint64, old, new uint64) (prev uint64) {
	for {
		prev = atomic.LoadUint64(addr.ptr())
		if prev != old {
			return
		}
		if atomic.CompareAndSwapUint64(addr.ptr(), old, new) {
			return
		}
	}
}
