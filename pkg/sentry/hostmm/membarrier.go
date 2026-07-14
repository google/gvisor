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

package hostmm

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
)

// HostMemBarrier provides access to the host membarrier(2) operations that the
// calling process has been verified to support. It is obtained from Probe.
type HostMemBarrier struct {
	// global is whether the host supports MEMBARRIER_CMD_GLOBAL.
	global bool

	// privateExpedited is true if we registered for
	// `MEMBARRIER_CMD_PRIVATE_EXPEDITED`.
	privateExpedited bool
}

// HaveGlobalMemoryBarrier returns true if GlobalMemoryBarrier is supported.
func (h HostMemBarrier) HaveGlobalMemoryBarrier() bool {
	return h.global
}

// HaveProcessMemoryBarrier returns true if ProcessMemoryBarrier is supported
// and registration succeeded.
func (h HostMemBarrier) HaveProcessMemoryBarrier() bool {
	return h.privateExpedited
}

// GlobalMemoryBarrier blocks until "all running threads [in the host OS] have
// passed through a state where all memory accesses to user-space addresses
// match program order between entry to and return from [GlobalMemoryBarrier]",
// as for membarrier(2).
//
// Preconditions: HaveGlobalMemoryBarrier() == true.
func (h HostMemBarrier) GlobalMemoryBarrier() error {
	if !h.global {
		panic("hostmm: GlobalMemoryBarrier called, but host does not support it")
	}
	if _, _, e := unix.Syscall(unix.SYS_MEMBARRIER, linux.MEMBARRIER_CMD_GLOBAL, 0 /* flags */, 0 /* unused */); e != 0 {
		return e
	}
	return nil
}

// ProcessMemoryBarrier is equivalent to GlobalMemoryBarrier, but only
// synchronizes with threads sharing a virtual address space (from the host OS'
// perspective) with the calling thread.
//
// Preconditions: HaveProcessMemoryBarrier() == true.
func (h HostMemBarrier) ProcessMemoryBarrier() error {
	if !h.privateExpedited {
		panic("hostmm: ProcessMemoryBarrier called unexpectedly")
	}
	if _, _, e := unix.RawSyscall(unix.SYS_MEMBARRIER, linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0 /* flags */, 0 /* unused */); e != 0 {
		return e
	}
	return nil
}

// Probe asynchronously determines host `membarrier(2)` support and, if
// `probePrivateExpedited` is true and the host supports it, registers for
// MEMBARRIER_CMD_PRIVATE_EXPEDITED.
// Returns a channel on which the resulting HostMemBarrier is sent back.
// This is meant to be used in Platform implementation constructors, which
// mus run before seccomp filters installation.
// Runs in the background to allow further platform initialization to proceed
// while we determine this, which can take tens of milliseconds.
func Probe(probePrivateExpedited bool) <-chan HostMemBarrier {
	ch := make(chan HostMemBarrier, 1)
	go func() {
		ch <- probe(probePrivateExpedited)
		close(ch)
	}()
	return ch
}

func probe(probePrivateExpedited bool) HostMemBarrier {
	var mb HostMemBarrier
	supported, _, e := unix.RawSyscall(unix.SYS_MEMBARRIER, linux.MEMBARRIER_CMD_QUERY, 0 /* flags */, 0 /* unused */)
	if e != 0 {
		if e != unix.ENOSYS {
			log.Warningf("membarrier(MEMBARRIER_CMD_QUERY) failed: %s", e.Error())
		}
		return mb
	}
	if supported&linux.MEMBARRIER_CMD_GLOBAL != 0 {
		mb.global = true
	}
	if !probePrivateExpedited {
		return mb
	}
	// Registering a  process for private-expedited membarrier blocks on an RCU
	// grace period (tens of ms), so only do it if needed.
	if req := uintptr(linux.MEMBARRIER_CMD_PRIVATE_EXPEDITED | linux.MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED); supported&req == req {
		if _, _, e := unix.RawSyscall(unix.SYS_MEMBARRIER, linux.MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0 /* flags */, 0 /* unused */); e != 0 {
			log.Warningf("membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED) failed: %s", e.Error())
		} else {
			mb.privateExpedited = true
		}
	}
	return mb
}
