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

// +build linux
// +build amd64 arm64

package ptrace

import (
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/hostcpu"
)

// maskPool contains reusable CPU masks for setting affinity. Unfortunately,
// runtime.NumCPU doesn't actually record the number of CPUs on the system, it
// just records the number of CPUs available in the scheduler affinity set at
// startup. This may a) change over time and b) gives a number far lower than
// the maximum indexable CPU. To prevent lots of allocation in the hot path, we
// use a pool to store large masks that we can reuse during bind.
var maskPool = sync.Pool{
	New: func() interface{} {
		const maxCPUs = 1024 // Not a hard limit; see below.
		return make([]uintptr, maxCPUs/64)
	},
}

// unmaskAllSignals unmasks all signals on the current thread.
//
//go:nosplit
func unmaskAllSignals() syscall.Errno {
	var set linux.SignalSet
	_, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, linux.SIG_SETMASK, uintptr(unsafe.Pointer(&set)), 0, linux.SignalSetSize, 0, 0)
	return errno
}

// setCPU sets the CPU affinity.
func (t *thread) setCPU(cpu uint32) error {
	mask := maskPool.Get().([]uintptr)
	n := int(cpu / 64)
	v := uintptr(1 << uintptr(cpu%64))
	if n >= len(mask) {
		// See maskPool note above. We've actually exceeded the number
		// of available cores. Grow the mask and return it.
		mask = make([]uintptr, n+1)
	}
	mask[n] |= v
	if _, _, errno := syscall.RawSyscall(
		unix.SYS_SCHED_SETAFFINITY,
		uintptr(t.tid),
		uintptr(len(mask)*8),
		uintptr(unsafe.Pointer(&mask[0]))); errno != 0 {
		return errno
	}
	mask[n] &^= v
	maskPool.Put(mask)
	return nil
}

// bind attempts to ensure that the thread is on the same CPU as the current
// thread. This provides no guarantees as it is fundamentally a racy operation:
// CPU sets may change and we may be rescheduled in the middle of this
// operation. As a result, no failures are reported.
//
// Precondition: the current runtime thread should be locked.
func (t *thread) bind() {
	currentCPU := hostcpu.GetCPU()

	if oldCPU := atomic.SwapUint32(&t.cpu, currentCPU); oldCPU != currentCPU {
		// Set the affinity on the thread and save the CPU for next
		// round; we don't expect CPUs to bounce around too frequently.
		//
		// (It's worth noting that we could move CPUs between this point
		// and when the tracee finishes executing. But that would be
		// roughly the status quo anyways -- we're just maximizing our
		// chances of colocation, not guaranteeing it.)
		t.setCPU(currentCPU)
	}
}
