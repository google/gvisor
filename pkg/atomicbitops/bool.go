// Copyright 2022 The gVisor Authors.
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

import "sync/atomic"

// Bool is an atomic Boolean.
//
// It is implemented by a Uint32, with value 0 indicating false, and 1
// indicating true.
//
// +stateify savable
type Bool struct {
	Uint32
}

// FromBool returns an Bool initialized to value val.
//
//go:nosplit
func FromBool(val bool) Bool {
	var u uint32
	if val {
		u = 1
	}
	return Bool{
		Uint32{
			value: u,
		},
	}
}

// Load is analogous to atomic.LoadBool, if such a thing existed.
//
//go:nosplit
func (b *Bool) Load() bool {
	return atomic.LoadUint32(&b.value) == 1
}

// Store is analogous to atomic.StoreBool, if such a thing existed.
//
//go:nosplit
func (b *Bool) Store(val bool) {
	var u uint32
	if val {
		u = 1
	}
	atomic.StoreUint32(&b.value, u)
}

// Swap is analogous to atomic.SwapBool, if such a thing existed.
//
//go:nosplit
func (b *Bool) Swap(val bool) bool {
	var u uint32
	if val {
		u = 1
	}
	return atomic.SwapUint32(&b.value, u) == 1
}
