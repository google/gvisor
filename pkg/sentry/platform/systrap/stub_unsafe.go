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

package systrap

import (
	"math/rand"
	"reflect"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safecopy"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
)

// initStubProcess is defined in arch-specific assembly.
func initStubProcess()

// addrOfInitStubProcess returns the start address of initStubProcess.
//
// In Go 1.17+, Go references to assembly functions resolve to an ABIInternal
// wrapper function rather than the function itself. We must reference from
// assembly to get the ABI0 (i.e., primary) address.
func addrOfInitStubProcess() uintptr

// stubCall calls the stub at the given address with the given pid.
func stubCall(addr, pid uintptr)

// unsafeSlice returns a slice for the given address and length.
func unsafeSlice(addr uintptr, length int) (slice []byte) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	sh.Data = addr
	sh.Len = length
	sh.Cap = length
	return
}

// prepareSeccompRules compiles stub process seccomp filters and fill
// the sock_fprog structure. So the stub process will only need to call
// seccomp system call to apply these filters.
//
//go:nosplit
func prepareSeccompRules(stubSysmsgStart, stubSysmsgRules, stubSysmsgRulesLen uintptr) {
	instrs := sysmsgThreadRules(stubSysmsgStart)
	progLen := len(instrs) * int(unsafe.Sizeof(bpf.Instruction{}))
	progPtr := stubSysmsgRules + unsafe.Sizeof(linux.SockFprog{})

	if progLen+int(unsafe.Sizeof(linux.SockFprog{})) > int(stubSysmsgRulesLen) {
		panic("not enough space for sysmsg seccomp rules")
	}

	var targetSlice []bpf.Instruction
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&targetSlice))
	sh.Data = progPtr
	sh.Cap = len(instrs)
	sh.Len = sh.Cap

	copy(targetSlice, instrs)

	// stubSysmsgRules and progPtr are addresses from a stub mapping which
	// is mapped once and never moved, so it is safe to use unsafe.Pointer
	// this way for them.
	sockProg := (*linux.SockFprog)(unsafe.Pointer(stubSysmsgRules))
	sockProg.Len = uint16(len(instrs))
	sockProg.Filter = (*linux.BPFInstruction)(unsafe.Pointer(progPtr))

	// Make the seccomp rules stub read-only.
	if _, _, errno := unix.RawSyscall(
		unix.SYS_MPROTECT,
		stubSysmsgRules,
		stubSysmsgRulesLen,
		unix.PROT_READ); errno != 0 {
		panic("mprotect failed: " + errno.Error())
	}
}

// stubInit allocates and  initializes the stub memory region which includes:
//   - the stub code to do initial initialization of a stub process.
//   - the sysmsg signal handler code to notify sentry about new events such as
//     system calls, memory faults, etc.
//   - precompiled seccomp rules to trap application system calls.
//   - reserved space for stub-thread stack regions.
func stubInit() {
	// *--------stubStart-------------------*
	// |--------stubInitProcess-------------|
	// | stub code to init stub processes   |
	// |--------stubSysmsgStart-------------|
	// | sysmsg code                        |
	// |--------stubSysmsgRuleStart---------|
	// | precompiled sysmsg seccomp rules   |
	// |--------guard page------------------|
	// |--------random gap------------------|
	// |                                    |
	// |--------stubSysmsgStack-------------|
	// | Reserved space for per-thread      |
	// | sysmsg stacks.                     |
	// |----------stubContextQueue----------|
	// | Shared ringbuffer queue for stubs  |
	// | to select the next context.        |
	// |--------stubThreadContextRegion-----|
	// | Reserved space for thread contexts |
	// *------------------------------------*

	// Grab the existing stub.
	procStubBegin := addrOfInitStubProcess()
	procStubLen := int(safecopy.FindEndAddress(procStubBegin) - procStubBegin)
	procStubSlice := unsafeSlice(procStubBegin, procStubLen)
	mapLen, _ := hostarch.PageRoundUp(uintptr(procStubLen))

	stubSysmsgStart = mapLen
	stubSysmsgLen := len(sysmsg.SighandlerBlob)
	mapLen, _ = hostarch.PageRoundUp(mapLen + uintptr(stubSysmsgLen))

	stubSysmsgRules = mapLen
	stubSysmsgRulesLen = hostarch.PageSize * 4
	mapLen += stubSysmsgRulesLen

	stubROMapEnd = mapLen
	// Add a guard page.
	mapLen += hostarch.PageSize
	stubSysmsgStack = mapLen

	// Allocate maxGuestThreads plus ONE because each per-thread stack
	// has to be aligned to sysmsg.PerThreadMemSize.
	// Look at sysmsg/sighandler.c:sysmsg_addr() for more details.
	mapLen, _ = hostarch.PageRoundUp(mapLen + sysmsg.PerThreadMemSize*(maxSystemThreads+1))

	// Allocate context queue region
	stubContextQueueRegion = mapLen
	stubContextQueueRegionLen, _ = hostarch.PageRoundUp(unsafe.Sizeof(contextQueue{}))
	mapLen += stubContextQueueRegionLen

	stubSpinningThreadQueueAddr = mapLen
	mapLen += sysmsg.SpinningQueueMemSize

	// Allocate thread context region
	stubContextRegion = mapLen
	stubContextRegionLen = sysmsg.AllocatedSizeofThreadContextStruct * (maxGuestContexts + 1)
	mapLen, _ = hostarch.PageRoundUp(mapLen + stubContextRegionLen)

	// Randomize stubStart address.
	randomOffset := uintptr(rand.Uint64() * hostarch.PageSize)
	maxRandomOffset := maxRandomOffsetOfStubAddress - mapLen
	stubStart = uintptr(0)
	for offset := uintptr(0); offset < maxRandomOffset; offset += hostarch.PageSize {
		stubStart = maxStubUserAddress + (randomOffset+offset)%maxRandomOffset
		// Map the target address for the stub.
		//
		// We don't use FIXED here because we don't want to unmap
		// something that may have been there already. We just walk
		// down the address space until we find a place where the stub
		// can be placed.
		addr, _, _ := unix.RawSyscall6(
			unix.SYS_MMAP,
			stubStart,
			stubROMapEnd,
			unix.PROT_WRITE|unix.PROT_READ,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
			0 /* fd */, 0 /* offset */)
		if addr == stubStart {
			break
		}
		if addr != 0 {
			// Unmap the region we've mapped accidentally.
			unix.RawSyscall(unix.SYS_MUNMAP, addr, stubROMapEnd, 0)
		}
		stubStart = uintptr(0)
	}

	if stubStart == 0 {
		// This will happen only if we exhaust the entire address
		// space, and it will take a long, long time.
		panic("failed to map stub")
	}
	// Randomize stubSysmsgStack address.
	gap := uintptr(rand.Uint64()) * hostarch.PageSize % (maximumUserAddress - stubStart - mapLen)
	stubSysmsgStack += uintptr(gap)
	stubContextQueueRegion += uintptr(gap)
	stubContextRegion += uintptr(gap)

	// Copy the stub to the address.
	targetSlice := unsafeSlice(stubStart, procStubLen)
	copy(targetSlice, procStubSlice)
	stubInitProcess = stubStart

	stubSysmsgStart += stubStart
	stubSysmsgStack += stubStart
	stubROMapEnd += stubStart
	stubContextQueueRegion += stubStart
	stubSpinningThreadQueueAddr += stubStart
	stubContextRegion += stubStart

	// Align stubSysmsgStack to the per-thread stack size.
	// Look at sysmsg/sighandler.c:sysmsg_addr() for more details.
	if offset := stubSysmsgStack % sysmsg.PerThreadMemSize; offset != 0 {
		stubSysmsgStack += sysmsg.PerThreadMemSize - offset
	}
	stubSysmsgRules += stubStart

	targetSlice = unsafeSlice(stubSysmsgStart, stubSysmsgLen)
	copy(targetSlice, sysmsg.SighandlerBlob)

	// Initialize stub globals
	p := (*uint64)(unsafe.Pointer(stubSysmsgStart + uintptr(sysmsg.Sighandler_blob_offset____export_deep_sleep_timeout)))
	*p = deepSleepTimeout
	p = (*uint64)(unsafe.Pointer(stubSysmsgStart + uintptr(sysmsg.Sighandler_blob_offset____export_context_region)))
	*p = uint64(stubContextRegion)
	p = (*uint64)(unsafe.Pointer(stubSysmsgStart + uintptr(sysmsg.Sighandler_blob_offset____export_stub_start)))
	*p = uint64(stubStart)
	archState := (*sysmsg.ArchState)(unsafe.Pointer(stubSysmsgStart + uintptr(sysmsg.Sighandler_blob_offset____export_arch_state)))
	archState.Init()
	p = (*uint64)(unsafe.Pointer(stubSysmsgStart + uintptr(sysmsg.Sighandler_blob_offset____export_context_queue_addr)))
	*p = uint64(stubContextQueueRegion)
	p = (*uint64)(unsafe.Pointer(stubSysmsgStart + uintptr(sysmsg.Sighandler_blob_offset____export_spinning_queue_addr)))
	*p = uint64(stubSpinningThreadQueueAddr)

	prepareSeccompRules(stubSysmsgStart, stubSysmsgRules, stubSysmsgRulesLen)

	// Make the stub executable.
	if _, _, errno := unix.RawSyscall(
		unix.SYS_MPROTECT,
		stubStart,
		stubROMapEnd-stubStart,
		unix.PROT_EXEC|unix.PROT_READ); errno != 0 {
		panic("mprotect failed: " + errno.Error())
	}

	// Set the end.
	stubEnd = stubStart + mapLen + uintptr(gap)
	log.Debugf("stubStart %x stubSysmsgStart %x stubSysmsgStack %x, stubContextQueue %x, stubThreadContextRegion %x, mapLen %x", stubStart, stubSysmsgStart, stubSysmsgStack, stubContextQueueRegion, stubContextRegion, mapLen)
	log.Debugf(archState.String())
}
