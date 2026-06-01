// Copyright 2024 The gVisor Authors.
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

//go:build loong64
// +build loong64

package fpu

const (
	// loongFPUMagic is the magic number identifying the basic FPU context
	// inside LoongArch sigcontext.sc_extcontext, matching FPU_CTX_MAGIC in
	// arch/loongarch/include/uapi/asm/sigcontext.h.
	loongFPUMagic = 0x46505501

	// loongFPUStateSize is the byte size of the per-task FPU save area we
	// allocate, matching `struct user_fp_state` (fpr[32] + fcc + fcsr)
	// rounded up to 8-byte alignment. LSX/LASX/LBT contexts are NOT saved.
	loongFPUStateSize = 0x110 // 272 bytes
)

// initLoongFPState resets the state to the canonical "clean" values.
// fcsr / fcc default to zero; floating-point registers are don't-care.
func initLoongFPState(data *State) {
}

// newLoongFPStateSlice returns an over-allocated, 16-byte aligned backing
// buffer of which the first loongFPUStateSize bytes are usable. The over
// allocation mirrors fpu_arm64.go and lets us keep alignment without
// special-casing the slice header.
func newLoongFPStateSlice() []byte {
	return alignedBytes(4096, 16)[:loongFPUStateSize]
}

// NewState returns an initialized floating-point state.
func NewState() State {
	f := State(newLoongFPStateSlice())
	initLoongFPState(&f)
	return f
}

// Fork creates and returns an identical copy of the LoongArch FPU state.
func (s *State) Fork() State {
	n := State(newLoongFPStateSlice())
	copy(n, *s)
	return n
}

// BytePointer returns a pointer to the first byte of the state.
//
//go:nosplit
func (s *State) BytePointer() *byte {
	return &(*s)[0]
}
