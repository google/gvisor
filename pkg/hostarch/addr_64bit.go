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

//go:build arm64 || amd64
// +build arm64 amd64

package hostarch

// HugeRoundDown returns the address rounded down to the nearest huge page
// boundary.
func (v Addr) HugeRoundDown() Addr {
	return v & ^Addr(HugePageSize-1)
}

// HugeRoundUp returns the address rounded up to the nearest huge page boundary.
// ok is true iff rounding up did not wrap around.
func (v Addr) HugeRoundUp() (addr Addr, ok bool) {
	addr = Addr(v + HugePageSize - 1).HugeRoundDown()
	ok = addr >= v
	return
}
