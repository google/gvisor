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

//go:build go1.12
// +build go1.12

// //go:linkname directives type-checked by checklinkname. Any other
// non-linkname assumptions outside the Go 1 compatibility guarantee should
// have an accompanied vet check or version guard build tag.

package systrap

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
)

//go:linkname beforeFork syscall.runtime_BeforeFork
func beforeFork()

//go:linkname afterFork syscall.runtime_AfterFork
func afterFork()

//go:linkname afterForkInChild syscall.runtime_AfterForkInChild
func afterForkInChild()

// getThreadContextFromID returns a ThreadContext struct that corresponds to the
// given ID.
//
// Precondition: cid must be a valid thread context ID that has a mapping for it
// that exists in s.contexts.
func (s *subprocess) getThreadContextFromID(cid uint64) *sysmsg.ThreadContext {
	tcSlot := s.threadContextRegion + uintptr(cid)*sysmsg.AllocatedSizeofThreadContextStruct
	return (*sysmsg.ThreadContext)(unsafe.Pointer(tcSlot))
}

func mmapContextQueueForSentry(memoryFile *pgalloc.MemoryFile, opts pgalloc.AllocOpts) (memmap.FileRange, *contextQueue) {
	fr, err := memoryFile.Allocate(uint64(stubContextQueueRegionLen), opts)
	if err != nil {
		panic(fmt.Sprintf("failed to allocate a new subprocess context memory region"))
	}
	addr, _, errno := unix.RawSyscall6(
		unix.SYS_MMAP,
		0,
		uintptr(fr.Length()),
		unix.PROT_WRITE|unix.PROT_READ,
		unix.MAP_SHARED|unix.MAP_FILE,
		uintptr(memoryFile.FD()), uintptr(fr.Start))
	if errno != 0 {
		panic(fmt.Sprintf("mmap failed for subprocess context memory region: %v", errno))
	}

	return fr, (*contextQueue)(unsafe.Pointer(addr))
}

//go:nosplit
func isFPStateInContextRegion(ctx *sharedContext) bool {
	// If context decoupling experiment is ON then both the sighandler and
	// syshandler save FPState to the context region since contexts will move
	// threads. Otherwise only syshandler will save FPState to the region.
	return contextDecouplingExp || ctx.state() == sysmsg.ContextStateSyscallTrap
}

func saveFPState(msg *sysmsg.Msg, ctx *sharedContext, fpuToMsgOffset uint64, c *context, ac *arch.Context64) {
	fpState := ac.FloatingPointData().BytePointer()
	dst := unsafeSlice(uintptr(unsafe.Pointer(fpState)), archState.FpLen())
	var src []byte
	if isFPStateInContextRegion(ctx) {
		src = ctx.shared.FPState[:]
	} else {
		src = unsafeSlice(uintptr(unsafe.Pointer(msg))+uintptr(fpuToMsgOffset), archState.FpLen())
	}
	copy(dst, src)
}

// restoreFPStateDecoupledContext writes FPState from c to the thread context
// shared memory region if there is any need to do so.
func restoreFPState(msg *sysmsg.Msg, ctx *sharedContext, fpuToMsgOffset uint64, c *context, ac *arch.Context64) {
	if !c.needRestoreFPState {
		return
	}
	c.needRestoreFPState = false
	ctx.setFPStateChanged()

	fpState := ac.FloatingPointData().BytePointer()
	src := unsafeSlice(uintptr(unsafe.Pointer(fpState)), archState.FpLen())
	var dst []byte
	if isFPStateInContextRegion(ctx) {
		dst = ctx.shared.FPState[:]
	} else {
		dst = unsafeSlice(uintptr(unsafe.Pointer(msg))+uintptr(fpuToMsgOffset), archState.FpLen())
	}
	copy(dst, src)
}
