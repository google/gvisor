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

package kernel

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/hostcpu"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Restartable sequences, as described in https://lwn.net/Articles/650333/.

// RSEQCriticalRegion describes a restartable sequence critical region.
//
// +stateify savable
type RSEQCriticalRegion struct {
	// When a task in this thread group has its CPU preempted (as defined by
	// platform.ErrContextCPUPreempted) or has a signal delivered to an
	// application handler while its instruction pointer is in CriticalSection,
	// set the instruction pointer to Restart and application register r10 (on
	// amd64) to the former instruction pointer.
	CriticalSection usermem.AddrRange
	Restart         usermem.Addr
}

// RSEQAvailable returns true if t supports restartable sequences.
func (t *Task) RSEQAvailable() bool {
	return t.k.useHostCores && t.k.Platform.DetectsCPUPreemption()
}

// RSEQCriticalRegion returns a copy of t's thread group's current restartable
// sequence.
func (t *Task) RSEQCriticalRegion() RSEQCriticalRegion {
	return *t.tg.rscr.Load().(*RSEQCriticalRegion)
}

// SetRSEQCriticalRegion replaces t's thread group's restartable sequence.
//
// Preconditions: t.RSEQAvailable() == true.
func (t *Task) SetRSEQCriticalRegion(rscr RSEQCriticalRegion) error {
	// These checks are somewhat more lenient than in Linux, which (bizarrely)
	// requires rscr.CriticalSection to be non-empty and rscr.Restart to be
	// outside of rscr.CriticalSection, even if rscr.CriticalSection.Start == 0
	// (which disables the critical region).
	if rscr.CriticalSection.Start == 0 {
		rscr.CriticalSection.End = 0
		rscr.Restart = 0
		t.tg.rscr.Store(&rscr)
		return nil
	}
	if rscr.CriticalSection.Start >= rscr.CriticalSection.End {
		return syserror.EINVAL
	}
	if rscr.CriticalSection.Contains(rscr.Restart) {
		return syserror.EINVAL
	}
	// TODO(jamieliu): check that rscr.CriticalSection and rscr.Restart are in
	// the application address range, for consistency with Linux
	t.tg.rscr.Store(&rscr)
	return nil
}

// RSEQCPUAddr returns the address that RSEQ will keep updated with t's CPU
// number.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) RSEQCPUAddr() usermem.Addr {
	return t.rseqCPUAddr
}

// SetRSEQCPUAddr replaces the address that RSEQ will keep updated with t's CPU
// number.
//
// Preconditions: t.RSEQAvailable() == true. The caller must be running on the
// task goroutine. t's AddressSpace must be active.
func (t *Task) SetRSEQCPUAddr(addr usermem.Addr) error {
	t.rseqCPUAddr = addr
	if addr != 0 {
		t.rseqCPU = int32(hostcpu.GetCPU())
		if err := t.rseqCopyOutCPU(); err != nil {
			t.rseqCPUAddr = 0
			t.rseqCPU = -1
			return syserror.EINVAL // yes, EINVAL, not err or EFAULT
		}
	} else {
		t.rseqCPU = -1
	}
	return nil
}

// Preconditions: The caller must be running on the task goroutine. t's
// AddressSpace must be active.
func (t *Task) rseqCopyOutCPU() error {
	buf := t.CopyScratchBuffer(4)
	usermem.ByteOrder.PutUint32(buf, uint32(t.rseqCPU))
	_, err := t.CopyOutBytes(t.rseqCPUAddr, buf)
	return err
}

// Preconditions: The caller must be running on the task goroutine.
func (t *Task) rseqInterrupt() {
	rscr := t.tg.rscr.Load().(*RSEQCriticalRegion)
	if ip := t.Arch().IP(); rscr.CriticalSection.Contains(usermem.Addr(ip)) {
		t.Debugf("Interrupted RSEQ critical section at %#x; restarting at %#x", ip, rscr.Restart)
		t.Arch().SetIP(uintptr(rscr.Restart))
		t.Arch().SetRSEQInterruptedIP(ip)
	}
}
