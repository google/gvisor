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

//go:nosplit
func isFPStateInContextRegion(ctx *sysmsg.ThreadContext) bool {
	// If context decoupling experiment is ON then both the sighandler and
	// syshandler save FPState to the context region since contexts will move
	// threads. Otherwise only syshandler will save FPState to the region.
	return contextDecouplingExp || ctx.State == sysmsg.ContextStateSyscallTrap
}

func (s *subprocess) restoreFPState(msg *sysmsg.Msg, ctx *sysmsg.ThreadContext, fpuToMsgOffset uint64, c *context, ac *arch.Context64) {
	// c.needRestoreFPState is changed only from the task goroutine, so it can
	// be accessed without locks.
	if !c.needRestoreFPState {
		return
	}
	c.needRestoreFPState = false
	ctx.FPStateChanged = 1

	fpState := ac.FloatingPointData().BytePointer()
	src := unsafeSlice(uintptr(unsafe.Pointer(fpState)), c.fpLen)
	var dst []byte
	if isFPStateInContextRegion(ctx) {
		dst = ctx.FPState[:]
	} else {
		dst = unsafeSlice(uintptr(unsafe.Pointer(msg))+uintptr(fpuToMsgOffset), c.fpLen)
	}
	copy(dst, src)
}

func (s *subprocess) saveFPState(msg *sysmsg.Msg, ctx *sysmsg.ThreadContext, fpuToMsgOffset uint64, c *context, ac *arch.Context64) {
	fpState := ac.FloatingPointData().BytePointer()
	dst := unsafeSlice(uintptr(unsafe.Pointer(fpState)), c.fpLen)
	var src []byte
	if isFPStateInContextRegion(ctx) {
		src = ctx.FPState[:]
	} else {
		src = unsafeSlice(uintptr(unsafe.Pointer(msg))+uintptr(fpuToMsgOffset), c.fpLen)
	}
	copy(dst, src)
}
