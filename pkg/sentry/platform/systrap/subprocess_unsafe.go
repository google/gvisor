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

//go:build go1.18
// +build go1.18

// //go:linkname directives type-checked by checklinkname. Any other
// non-linkname assumptions outside the Go 1 compatibility guarantee should
// have an accompanied vet check or version guard build tag.

package systrap

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
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

// cputicks is implemented in assembly.
func cputicks() int64

// spinloop is implemented in assembly.
func spinloop()

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

func saveFPState(ctx *sharedContext, ac *arch.Context64) {
	fpState := ac.FloatingPointData().BytePointer()
	dst := unsafeSlice(uintptr(unsafe.Pointer(fpState)), archState.FpLen())
	src := ctx.shared.FPState[:]
	copy(dst, src)
}

// restoreFPStateDecoupledContext writes FPState from c to the thread context
// shared memory region if there is any need to do so.
func restoreFPState(ctx *sharedContext, c *platformContext, ac *arch.Context64) {
	if !c.needRestoreFPState {
		return
	}
	c.needRestoreFPState = false
	ctx.setFPStateChanged()

	fpState := ac.FloatingPointData().BytePointer()
	src := unsafeSlice(uintptr(unsafe.Pointer(fpState)), archState.FpLen())
	dst := ctx.shared.FPState[:]
	copy(dst, src)
}

// alive returns true if the subprocess is alive.
func (s *subprocess) alive() bool {
	if s.dead.Load() {
		return false
	}

	// Wait4 doesn't support WNOWAIT, but here is no other way to find out
	// whether a process exited or was stopped by ptrace.
	siginfo := linux.SignalInfo{}
	_, _, errno := unix.Syscall6(
		unix.SYS_WAITID,
		unix.P_PID,
		uintptr(s.syscallThread.thread.tid),
		uintptr(unsafe.Pointer(&siginfo)),
		uintptr(unix.WEXITED|unix.WNOHANG|unix.WNOWAIT),
		0, 0)
	if errno == 0 && siginfo.PID() == 0 {
		return true
	}
	if errno == 0 && siginfo.Code != linux.CLD_EXITED && siginfo.Code != linux.CLD_KILLED {
		return true
	}

	// The process is dead, let's collect its zombie.
	wstatus := unix.WaitStatus(0)
	pid, err := unix.Wait4(int(s.syscallThread.thread.tid), &wstatus, unix.WNOHANG, nil)
	log.Warningf("the subprocess %d exited (status: %s, err %s)", pid, wstatus, err)
	s.dead.Store(true)
	return false
}
