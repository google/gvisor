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

//go:build arm64
// +build arm64

package fpu

const (
	// fpsimdMagic is the magic number which is used in fpsimd_context.
	fpsimdMagic = 0x46508001

	// fpsimdContextSize is the size of fpsimd_context.
	fpsimdContextSize = 0x210
)

// initAarch64FPState sets up initial state.
//
// Related code in Linux kernel: fpsimd_flush_thread().
// FPCR = FPCR_RM_RN (0x0 << 22).
//
// Currently, aarch64FPState is only a space of 0x210 length for fpstate.
// The fp head is useless in sentry/ptrace/kvm.
func initAarch64FPState(data *State) {
}

func newAarch64FPStateSlice() []byte {
	return alignedBytes(4096, 16)[:fpsimdContextSize]
}

// NewState returns an initialized floating point state.
//
// The returned state is large enough to store all floating point state
// supported by host, even if the app won't use much of it due to a restricted
// FeatureSet.
func NewState() State {
	f := State(newAarch64FPStateSlice())
	initAarch64FPState(&f)
	return f
}

// Fork creates and returns an identical copy of the aarch64 floating point state.
func (s *State) Fork() State {
	n := State(newAarch64FPStateSlice())
	copy(n, *s)
	return n
}

// BytePointer returns a pointer to the first byte of the state.
//
//go:nosplit
func (s *State) BytePointer() *byte {
	return &(*s)[0]
}
