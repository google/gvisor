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

//go:build arm64
// +build arm64

package systrap

import (
	"unsafe"

	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
)

// Signal frames for ARM64 include 8 byte magic header before the floating point
// context.
//
// See: arch/arm64/include/uapi/asm/sigcontext.h
const sigFrameMagicHeaderLen = 8

func (s *subprocess) restoreFPState(msg *sysmsg.Msg, fpuToMsgOffset uint64, c *context, ac *arch.Context64) {
	// c.needRestoreFPState is changed only from the task goroutine, so it can
	// be accessed without locks.
	if !c.needRestoreFPState {
		return
	}
	c.needRestoreFPState = false
	fpState := ac.FloatingPointData().BytePointer()
	src := unsafeSlice(uintptr(unsafe.Pointer(fpState)), c.fpLen)
	dst := unsafeSlice(uintptr(unsafe.Pointer(msg))+uintptr(fpuToMsgOffset)+uintptr(sigFrameMagicHeaderLen), c.fpLen)
	copy(dst, src)
}

func (s *subprocess) saveFPState(msg *sysmsg.Msg, fpuToMsgOffset uint64, c *context, ac *arch.Context64) {
	fpState := ac.FloatingPointData().BytePointer()
	src := unsafeSlice(uintptr(unsafe.Pointer(msg))+uintptr(fpuToMsgOffset)+uintptr(sigFrameMagicHeaderLen), c.fpLen)
	dst := unsafeSlice(uintptr(unsafe.Pointer(fpState)), c.fpLen)
	copy(dst, src)
}
