// Copyright 2026 The gVisor Authors.
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

//go:build checkescape_binary

package main

const taggedValue = true

// unusedAllocation remains in the Go archive but is removed by the linker.
// The stack check rejects checkescape's conservative fallback if objdump fails.
//
// +mustescape:local,heap
// +checkescape:stack
//
//go:noinline
//go:nosplit
func unusedAllocation() *int {
	return new(int)
}

// Race instrumentation of a stack allocation must not be mistaken for a heap
// allocation. The call keeps the composite literal from being optimized away.
//
// +checkescape:all
//
//go:noinline
//go:nosplit
func stackAllocation(a, b uint64) uint64 {
	values := &[2]uint64{a, b}
	return sum(values)
}

//go:noinline
//go:nosplit
func sum(values *[2]uint64) uint64 {
	return values[0] + values[1]
}
