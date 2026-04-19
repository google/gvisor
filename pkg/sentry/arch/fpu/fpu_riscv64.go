// Copyright 2020 The gVisor Authors.
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

//go:build riscv64
// +build riscv64

package fpu

const (
	// The Magic number for signal context frame header
	RISCV_V_MAGIC = 0x53465457
	END_MAGIC = 0x53465457

	// fpStateSize is the size of union __riscv_mc_fp_state
	fpStateSize = 528
)

// initRiscv64FPState sets up initial state.
//
func initRiscv64FPState(data *State) {
}

func newRiscv64FPStateSlice() []byte {
	return alignedBytes(4096, 16)[:fpStateSize]
}

// NewState returns an initialized floating point state.
//
// The returned state is large enough to store all floating point state
// supported by host, even if the app won't use much of it due to a restricted
// FeatureSet.
func NewState() State {
	f := State(newRiscv64FPStateSlice())
	initRiscv64FPState(&f)
	return f
}

// Fork creates and returns an identical copy of the riscv64 floating point state.
func (s *State) Fork() State {
	n := State(newRiscv64FPStateSlice())
	copy(n, *s)
	return n
}

// BytePointer returns a pointer to the first byte of the state.
//
//go:nosplit
func (s *State) BytePointer() *byte {
	return &(*s)[0]
}
