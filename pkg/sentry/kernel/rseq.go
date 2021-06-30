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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/hostcpu"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Restartable sequences.
//
// We support two different APIs for restartable sequences.
//
//  1. The upstream interface added in v4.18.
//  2. The interface described in https://lwn.net/Articles/650333/.
//
// Throughout this file and other parts of the kernel, the latter is referred
// to as "old rseq". This interface was never merged upstream, but is supported
// for a limited set of applications that use it regardless.

// OldRSeqCriticalRegion describes an old rseq critical region.
//
// +stateify savable
type OldRSeqCriticalRegion struct {
	// When a task in this thread group has its CPU preempted (as defined by
	// platform.ErrContextCPUPreempted) or has a signal delivered to an
	// application handler while its instruction pointer is in CriticalSection,
	// set the instruction pointer to Restart and application register r10 (on
	// amd64) to the former instruction pointer.
	CriticalSection hostarch.AddrRange
	Restart         hostarch.Addr
}

// RSeqAvailable returns true if t supports (old and new) restartable sequences.
func (t *Task) RSeqAvailable() bool {
	return t.k.useHostCores && t.k.Platform.DetectsCPUPreemption()
}

// SetRSeq registers addr as this thread's rseq structure.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) SetRSeq(addr hostarch.Addr, length, signature uint32) error {
	if t.rseqAddr != 0 {
		if t.rseqAddr != addr {
			return linuxerr.EINVAL
		}
		if t.rseqSignature != signature {
			return linuxerr.EINVAL
		}
		return syserror.EBUSY
	}

	// rseq must be aligned and correctly sized.
	if addr&(linux.AlignOfRSeq-1) != 0 {
		return linuxerr.EINVAL
	}
	if length != linux.SizeOfRSeq {
		return linuxerr.EINVAL
	}
	if _, ok := t.MemoryManager().CheckIORange(addr, linux.SizeOfRSeq); !ok {
		return syserror.EFAULT
	}

	t.rseqAddr = addr
	t.rseqSignature = signature

	// Initialize the CPUID.
	//
	// Linux implicitly does this on return from userspace, where failure
	// would cause SIGSEGV.
	if err := t.rseqUpdateCPU(); err != nil {
		t.rseqAddr = 0
		t.rseqSignature = 0

		t.Debugf("Failed to copy CPU to %#x for rseq: %v", t.rseqAddr, err)
		t.forceSignal(linux.SIGSEGV, false /* unconditional */)
		t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
		return syserror.EFAULT
	}

	return nil
}

// ClearRSeq unregisters addr as this thread's rseq structure.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) ClearRSeq(addr hostarch.Addr, length, signature uint32) error {
	if t.rseqAddr == 0 {
		return linuxerr.EINVAL
	}
	if t.rseqAddr != addr {
		return linuxerr.EINVAL
	}
	if length != linux.SizeOfRSeq {
		return linuxerr.EINVAL
	}
	if t.rseqSignature != signature {
		return linuxerr.EPERM
	}

	if err := t.rseqClearCPU(); err != nil {
		return err
	}

	t.rseqAddr = 0
	t.rseqSignature = 0

	if t.oldRSeqCPUAddr == 0 {
		// rseqCPU no longer needed.
		t.rseqCPU = -1
	}

	return nil
}

// OldRSeqCriticalRegion returns a copy of t's thread group's current
// old restartable sequence.
func (t *Task) OldRSeqCriticalRegion() OldRSeqCriticalRegion {
	return *t.tg.oldRSeqCritical.Load().(*OldRSeqCriticalRegion)
}

// SetOldRSeqCriticalRegion replaces t's thread group's old restartable
// sequence.
//
// Preconditions: t.RSeqAvailable() == true.
func (t *Task) SetOldRSeqCriticalRegion(r OldRSeqCriticalRegion) error {
	// These checks are somewhat more lenient than in Linux, which (bizarrely)
	// requires r.CriticalSection to be non-empty and r.Restart to be
	// outside of r.CriticalSection, even if r.CriticalSection.Start == 0
	// (which disables the critical region).
	if r.CriticalSection.Start == 0 {
		r.CriticalSection.End = 0
		r.Restart = 0
		t.tg.oldRSeqCritical.Store(&r)
		return nil
	}
	if r.CriticalSection.Start >= r.CriticalSection.End {
		return linuxerr.EINVAL
	}
	if r.CriticalSection.Contains(r.Restart) {
		return linuxerr.EINVAL
	}
	// TODO(jamieliu): check that r.CriticalSection and r.Restart are in
	// the application address range, for consistency with Linux.
	t.tg.oldRSeqCritical.Store(&r)
	return nil
}

// OldRSeqCPUAddr returns the address that old rseq will keep updated with t's
// CPU number.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) OldRSeqCPUAddr() hostarch.Addr {
	return t.oldRSeqCPUAddr
}

// SetOldRSeqCPUAddr replaces the address that old rseq will keep updated with
// t's CPU number.
//
// Preconditions:
// * t.RSeqAvailable() == true.
// * The caller must be running on the task goroutine.
// * t's AddressSpace must be active.
func (t *Task) SetOldRSeqCPUAddr(addr hostarch.Addr) error {
	t.oldRSeqCPUAddr = addr

	// Check that addr is writable.
	//
	// N.B. rseqUpdateCPU may fail on a bad t.rseqAddr as well. That's
	// unfortunate, but unlikely in a correct program.
	if err := t.rseqUpdateCPU(); err != nil {
		t.oldRSeqCPUAddr = 0
		return linuxerr.EINVAL // yes, EINVAL, not err or EFAULT
	}
	return nil
}

// Preconditions:
// * The caller must be running on the task goroutine.
// * t's AddressSpace must be active.
func (t *Task) rseqUpdateCPU() error {
	if t.rseqAddr == 0 && t.oldRSeqCPUAddr == 0 {
		t.rseqCPU = -1
		return nil
	}

	t.rseqCPU = int32(hostcpu.GetCPU())

	// Update both CPUs, even if one fails.
	rerr := t.rseqCopyOutCPU()
	oerr := t.oldRSeqCopyOutCPU()

	if rerr != nil {
		return rerr
	}
	return oerr
}

// Preconditions:
// * The caller must be running on the task goroutine.
// * t's AddressSpace must be active.
func (t *Task) oldRSeqCopyOutCPU() error {
	if t.oldRSeqCPUAddr == 0 {
		return nil
	}

	buf := t.CopyScratchBuffer(4)
	hostarch.ByteOrder.PutUint32(buf, uint32(t.rseqCPU))
	_, err := t.CopyOutBytes(t.oldRSeqCPUAddr, buf)
	return err
}

// Preconditions:
// * The caller must be running on the task goroutine.
// * t's AddressSpace must be active.
func (t *Task) rseqCopyOutCPU() error {
	if t.rseqAddr == 0 {
		return nil
	}

	buf := t.CopyScratchBuffer(8)
	// CPUIDStart and CPUID are the first two fields in linux.RSeq.
	hostarch.ByteOrder.PutUint32(buf, uint32(t.rseqCPU))     // CPUIDStart
	hostarch.ByteOrder.PutUint32(buf[4:], uint32(t.rseqCPU)) // CPUID
	// N.B. This write is not atomic, but since this occurs on the task
	// goroutine then as long as userspace uses a single-instruction read
	// it can't see an invalid value.
	_, err := t.CopyOutBytes(t.rseqAddr, buf)
	return err
}

// Preconditions:
// * The caller must be running on the task goroutine.
// * t's AddressSpace must be active.
func (t *Task) rseqClearCPU() error {
	buf := t.CopyScratchBuffer(8)
	// CPUIDStart and CPUID are the first two fields in linux.RSeq.
	hostarch.ByteOrder.PutUint32(buf, 0)                                   // CPUIDStart
	hostarch.ByteOrder.PutUint32(buf[4:], linux.RSEQ_CPU_ID_UNINITIALIZED) // CPUID
	// N.B. This write is not atomic, but since this occurs on the task
	// goroutine then as long as userspace uses a single-instruction read
	// it can't see an invalid value.
	_, err := t.CopyOutBytes(t.rseqAddr, buf)
	return err
}

// rseqAddrInterrupt checks if IP is in a critical section, and aborts if so.
//
// This is a bit complex since both the RSeq and RSeqCriticalSection structs
// are stored in userspace. So we must:
//
// 1. Copy in the address of RSeqCriticalSection from RSeq.
// 2. Copy in RSeqCriticalSection itself.
// 3. Validate critical section struct version, address range, abort address.
// 4. Validate the abort signature (4 bytes preceding abort IP match expected
//    signature).
// 5. Clear address of RSeqCriticalSection from RSeq.
// 6. Finally, conditionally abort.
//
// See kernel/rseq.c:rseq_ip_fixup for reference.
//
// Preconditions:
// * The caller must be running on the task goroutine.
// * t's AddressSpace must be active.
func (t *Task) rseqAddrInterrupt() {
	if t.rseqAddr == 0 {
		return
	}

	critAddrAddr, ok := t.rseqAddr.AddLength(linux.OffsetOfRSeqCriticalSection)
	if !ok {
		// SetRSeq should validate this.
		panic(fmt.Sprintf("t.rseqAddr (%#x) not large enough", t.rseqAddr))
	}

	if t.Arch().Width() != 8 {
		// We only handle 64-bit for now.
		t.Debugf("Only 64-bit rseq supported.")
		t.forceSignal(linux.SIGSEGV, false /* unconditional */)
		t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
		return
	}

	buf := t.CopyScratchBuffer(8)
	if _, err := t.CopyInBytes(critAddrAddr, buf); err != nil {
		t.Debugf("Failed to copy critical section address from %#x for rseq: %v", critAddrAddr, err)
		t.forceSignal(linux.SIGSEGV, false /* unconditional */)
		t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
		return
	}

	critAddr := hostarch.Addr(hostarch.ByteOrder.Uint64(buf))
	if critAddr == 0 {
		return
	}

	var cs linux.RSeqCriticalSection
	if _, err := cs.CopyIn(t, critAddr); err != nil {
		t.Debugf("Failed to copy critical section from %#x for rseq: %v", critAddr, err)
		t.forceSignal(linux.SIGSEGV, false /* unconditional */)
		t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
		return
	}

	if cs.Version != 0 {
		t.Debugf("Unknown version in %+v", cs)
		t.forceSignal(linux.SIGSEGV, false /* unconditional */)
		t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
		return
	}

	start := hostarch.Addr(cs.Start)
	critRange, ok := start.ToRange(cs.PostCommitOffset)
	if !ok {
		t.Debugf("Invalid start and offset in %+v", cs)
		t.forceSignal(linux.SIGSEGV, false /* unconditional */)
		t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
		return
	}

	abort := hostarch.Addr(cs.Abort)
	if critRange.Contains(abort) {
		t.Debugf("Abort in critical section in %+v", cs)
		t.forceSignal(linux.SIGSEGV, false /* unconditional */)
		t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
		return
	}

	// Verify signature.
	sigAddr := abort - linux.SizeOfRSeqSignature

	buf = t.CopyScratchBuffer(linux.SizeOfRSeqSignature)
	if _, err := t.CopyInBytes(sigAddr, buf); err != nil {
		t.Debugf("Failed to copy critical section signature from %#x for rseq: %v", sigAddr, err)
		t.forceSignal(linux.SIGSEGV, false /* unconditional */)
		t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
		return
	}

	sig := hostarch.ByteOrder.Uint32(buf)
	if sig != t.rseqSignature {
		t.Debugf("Mismatched rseq signature %d != %d", sig, t.rseqSignature)
		t.forceSignal(linux.SIGSEGV, false /* unconditional */)
		t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
		return
	}

	// Clear the critical section address.
	//
	// NOTE(b/143949567): We don't support any rseq flags, so we always
	// restart if we are in the critical section, and thus *always* clear
	// critAddrAddr.
	if _, err := t.MemoryManager().ZeroOut(t, critAddrAddr, int64(t.Arch().Width()), usermem.IOOpts{
		AddressSpaceActive: true,
	}); err != nil {
		t.Debugf("Failed to clear critical section address from %#x for rseq: %v", critAddrAddr, err)
		t.forceSignal(linux.SIGSEGV, false /* unconditional */)
		t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
		return
	}

	// Finally we can actually decide whether or not to restart.
	if !critRange.Contains(hostarch.Addr(t.Arch().IP())) {
		return
	}

	t.Arch().SetIP(uintptr(cs.Abort))
}

// Preconditions: The caller must be running on the task goroutine.
func (t *Task) oldRSeqInterrupt() {
	r := t.tg.oldRSeqCritical.Load().(*OldRSeqCriticalRegion)
	if ip := t.Arch().IP(); r.CriticalSection.Contains(hostarch.Addr(ip)) {
		t.Debugf("Interrupted rseq critical section at %#x; restarting at %#x", ip, r.Restart)
		t.Arch().SetIP(uintptr(r.Restart))
		t.Arch().SetOldRSeqInterruptedIP(ip)
	}
}

// Preconditions: The caller must be running on the task goroutine.
func (t *Task) rseqInterrupt() {
	t.rseqAddrInterrupt()
	t.oldRSeqInterrupt()
}
