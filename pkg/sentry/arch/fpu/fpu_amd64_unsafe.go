// Copyright 2023 The gVisor Authors.
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

//go:build amd64 || i386
// +build amd64 i386

package fpu

import (
	"unsafe"
)

// PrepForHostSigframe prepare the SW reserved portion of the fxsave memory
// layout and adds FP_XSTATE_MAGIC2. It has to be called if the state is
// restored by rt_sigreturn.
//
// Look at save_xstate_epilog in the kernel sources for more details.
//
//go:nosplit
func (s State) PrepForHostSigframe() {
	fpsw := (*FPSoftwareFrame)(unsafe.Pointer(&s[FP_SW_FRAME_OFFSET]))
	fpsw.Magic1 = FP_XSTATE_MAGIC1
	fpsw.ExtendedSize = uint32(hostFPSize) + FP_XSTATE_MAGIC2_SIZE
	fpsw.Xfeatures = XFEATURE_MASK_FPSSE | hostXCR0Mask
	fpsw.XstateSize = uint32(hostFPSize)

	if !hostUseXsave {
		return
	}

	*(*uint32)(unsafe.Pointer(&s[hostFPSize])) = FP_XSTATE_MAGIC2
}
