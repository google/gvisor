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
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostsyscall"
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
		panic("failed to allocate a new subprocess context memory region")
	}
	addr, errno := hostsyscall.RawSyscall6(
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

// destroyUVM destroys an address space that cannot be pooled because UVM may
// retain its mm. The final reference has been dropped, so no context can use it.
func (s *subprocess) destroyUVM() {
	close(s.requests)
	<-s.requestsDone
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Stop every process sharing the mm before removing their data mappings.
	// Keeping them traced also lets us wait for their deaths outside a PID
	// namespace where the Sentry would otherwise not reap orphaned stubs.
	threads := make([]*thread, 0, len(s.sysmsgThreads)+1)
	for _, p := range s.sysmsgThreads {
		threads = append(threads, p.thread)
	}
	threads = append(threads, s.syscallThread.thread)
	for _, t := range threads {
		if errno := hostsyscall.RawSyscallErrno(unix.SYS_PTRACE, unix.PTRACE_ATTACH, uintptr(t.tid), 0); errno != 0 {
			panic(fmt.Sprintf("cannot attach UVM address space thread %d: %v", t.tid, errno))
		}
		// A newly created sysmsg thread may still have its startup SIGSEGV
		// pending before the attach's SIGSTOP. Any ptrace stop suffices here:
		// these threads will never resume application code.
		if _, err := t.wait(stopped); err != nil {
			panic(fmt.Sprintf("cannot stop UVM address space thread %d: %v", t.tid, err))
		}
		if err := t.init(); err != nil {
			panic(fmt.Sprintf("cannot trace UVM address space thread %d: %v", t.tid, err))
		}
	}
	if err := s.syscallThread.unmaskAllSignalsAttached(); err != nil {
		panic(fmt.Sprintf("cannot unmask UVM syscall thread: %v", err))
	}
	// UVM's MM FD can pin the mm after all tasks exit. Remove its aliases of
	// shared backing before returning those offsets to the memory allocator.
	if _, err := s.syscallThread.thread.syscallIgnoreInterrupt(&s.syscallThread.thread.initRegs, unix.SYS_MUNMAP,
		arch.SyscallArgument{Value: stubROMapEnd},
		arch.SyscallArgument{Value: stubEnd - stubROMapEnd}); err != nil {
		panic(fmt.Sprintf("cannot unmap UVM address space data: %v", err))
	}
	s.dead.Store(true)
	for _, t := range threads {
		t.kill()
	}
	for _, t := range threads {
		for {
			var status unix.WaitStatus
			_, err := unix.Wait4(int(t.tid), &status, unix.WALL, nil)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				panic(fmt.Sprintf("cannot reap UVM address space thread %d: %v", t.tid, err))
			}
			if status.Exited() || status.Signaled() {
				break
			}
			// PTRACE_O_TRACEEXIT stops the process once before its final exit.
			if err := unix.PtraceCont(int(t.tid), 0); err != nil {
				panic(fmt.Sprintf("cannot finish UVM address space thread %d exit: %v", t.tid, err))
			}
		}
	}
	// A traced sysmsg process can first report its exit to us as tracer, then
	// become our waitable child when its original parent (the syscall thread)
	// exits. Reap that second notification when running as the PID-namespace init.
	for _, t := range threads {
		var status unix.WaitStatus
		if _, err := unix.Wait4(int(t.tid), &status, unix.WALL|unix.WNOHANG, nil); err != nil && err != unix.ECHILD {
			panic(fmt.Sprintf("cannot reap orphaned UVM thread %d: %v", t.tid, err))
		}
	}
	if s.syscallThread.seccompNotify != nil {
		if err := s.syscallThread.seccompNotify.Close(); err != nil {
			panic(fmt.Sprintf("cannot close UVM seccomp listener: %v", err))
		}
	}
	for _, p := range s.sysmsgThreads {
		p.unmapStackFromSentry()
		s.memoryFile.DecRef(p.stackRange)
	}
	s.sysmsgThreads = nil
	s.syscallThread.destroySentryMapping()
	if errno := hostsyscall.RawSyscallErrno(unix.SYS_MUNMAP, uintptr(unsafe.Pointer(s.contextQueue)), uintptr(s.contextQueueRange.Length()), 0); errno != 0 {
		panic(fmt.Sprintf("cannot unmap UVM context queue: %v", errno))
	}
	s.contextQueue = nil
	s.memoryFile.DecRef(s.contextQueueRange)
	s.contextQueueRange = memmap.FileRange{}
	if errno := hostsyscall.RawSyscallErrno(unix.SYS_MUNMAP, s.threadContextRegion, uintptr(s.threadContextRange.Length()), 0); errno != 0 {
		panic(fmt.Sprintf("cannot unmap UVM thread contexts: %v", errno))
	}
	s.threadContextRegion = 0
	s.memoryFile.DecRef(s.threadContextRange)
	s.threadContextRange = memmap.FileRange{}
}

func saveFPState(ctx *sharedContext, ac *arch.Context64) {
	fpState := ac.FloatingPointData().BytePointer()
	dst := unsafe.Slice(fpState, archState.FpLen())
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
	src := unsafe.Slice(fpState, archState.FpLen())
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
	log.Warningf("the subprocess %d exited (status: %d, err %s)", pid, wstatus, err)
	s.dead.Store(true)
	return false
}

// wakeAllContexts transitions all active context slots in ContextStateNone to
// ContextStateUnexpectedDeath and wakes their futex.
func (s *subprocess) wakeAllContexts() {
	if s.threadContextRegion == 0 {
		return
	}
	for i := uint64(0); i < maxGuestContexts; i++ {
		tc := s.getThreadContextFromID(i)
		if tc.State.CompareAndSwap(sysmsg.ContextStateNone, sysmsg.ContextStateUnexpectedDeath) {
			futexWakeUint32((*uint32)(unsafe.Pointer(&tc.State)))
		}
	}
}
