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

package linux

// Flags passed to rseq(2).
//
// Defined in include/uapi/linux/rseq.h.
const (
	// RSEQ_FLAG_UNREGISTER unregisters the current thread.
	RSEQ_FLAG_UNREGISTER = 1 << 0
)

// Critical section flags used in RSeqCriticalSection.Flags and RSeq.Flags.
//
// Defined in include/uapi/linux/rseq.h.
const (
	// RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT inhibits restart on preemption.
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT = 1 << 0

	// RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL inhibits restart on signal
	// delivery.
	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL = 1 << 1

	// RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE inhibits restart on CPU
	// migration.
	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE = 1 << 2
)

// RSeqCriticalSection describes a restartable sequences critical section. It
// is equivalent to struct rseq_cs, defined in include/uapi/linux/rseq.h.
//
// In userspace, this structure is always aligned to 32 bytes.
//
// +marshal
type RSeqCriticalSection struct {
	// Version is the version of this structure. Version 0 is defined here.
	Version uint32

	// Flags are the critical section flags, defined above.
	Flags uint32

	// Start is the start address of the critical section.
	Start uint64

	// PostCommitOffset is the offset from Start of the first instruction
	// outside of the critical section.
	PostCommitOffset uint64

	// Abort is the abort address. It must be outside the critical section,
	// and the 4 bytes prior must match the abort signature.
	Abort uint64
}

const (
	// SizeOfRSeqCriticalSection is the size of RSeqCriticalSection.
	SizeOfRSeqCriticalSection = 32

	// SizeOfRSeqSignature is the size of the signature immediately
	// preceding RSeqCriticalSection.Abort.
	SizeOfRSeqSignature = 4
)

// Special values for RSeq.CPUID, defined in include/uapi/linux/rseq.h.
const (
	// RSEQ_CPU_ID_UNINITIALIZED indicates that this thread has not
	// performed rseq initialization.
	RSEQ_CPU_ID_UNINITIALIZED = ^uint32(0) // -1

	// RSEQ_CPU_ID_REGISTRATION_FAILED indicates that rseq initialization
	// failed.
	RSEQ_CPU_ID_REGISTRATION_FAILED = ^uint32(1) // -2
)

// RSeq is the thread-local restartable sequences config/status. It
// is equivalent to struct rseq, defined in include/uapi/linux/rseq.h.
//
// In userspace, this structure is always aligned to 32 bytes.
type RSeq struct {
	// CPUIDStart contains the current CPU ID if rseq is initialized.
	//
	// This field should only be read by the thread which registered this
	// structure, and must be read atomically.
	CPUIDStart uint32

	// CPUID contains the current CPU ID or one of the CPU ID special
	// values defined above.
	//
	// This field should only be read by the thread which registered this
	// structure, and must be read atomically.
	CPUID uint32

	// RSeqCriticalSection is a pointer to the current RSeqCriticalSection
	// block, or NULL. It is reset to NULL by the kernel on restart or
	// non-restarting preempt/signal.
	//
	// This field should only be written by the thread which registered
	// this structure, and must be written atomically.
	RSeqCriticalSection uint64

	// Flags are the critical section flags that apply to all critical
	// sections on this thread, defined above.
	Flags uint32
}

const (
	// SizeOfRSeq is the size of RSeq.
	//
	// Note that RSeq is naively 24 bytes. However, it has 32-byte
	// alignment, which in C increases sizeof to 32. That is the size that
	// the Linux kernel uses.
	SizeOfRSeq = 32

	// AlignOfRSeq is the standard alignment of RSeq.
	AlignOfRSeq = 32

	// OffsetOfRSeqCriticalSection is the offset of RSeqCriticalSection in RSeq.
	OffsetOfRSeqCriticalSection = 8
)
