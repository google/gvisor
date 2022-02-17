// Copyright 2021 The gVisor Authors.
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

//go:build amd64 || i386
// +build amd64 i386

package fpu

import (
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sync"
)

// initX86FPState (defined in asm files) sets up initial state.
func initX86FPState(data *byte, useXsave bool)

func newX86FPStateSlice() State {
	size, align := cpuid.HostFeatureSet().ExtendedStateSize()
	capacity := size
	// Always use at least 4096 bytes.
	//
	// For the KVM platform, this state is a fixed 4096 bytes, so make sure
	// that the underlying array is at _least_ that size otherwise we will
	// corrupt random memory. This is not a pleasant thing to debug.
	if capacity < 4096 {
		capacity = 4096
	}
	return alignedBytes(capacity, align)[:size]
}

// NewState returns an initialized floating point state.
//
// The returned state is large enough to store all floating point state
// supported by host, even if the app won't use much of it due to a restricted
// FeatureSet. Since they may still be able to see state not advertised by
// CPUID we must ensure it does not contain any sentry state.
func NewState() State {
	f := newX86FPStateSlice()
	initX86FPState(&f[0], cpuid.HostFeatureSet().UseXsave())
	return f
}

// Fork creates and returns an identical copy of the x86 floating point state.
func (s *State) Fork() State {
	n := newX86FPStateSlice()
	copy(n, *s)
	return n
}

// Reset resets s to its initial state.
func (s *State) Reset() {
	f := *s
	for i := range f {
		f[i] = 0
	}
	initX86FPState(&f[0], cpuid.HostFeatureSet().UseXsave())
}

// ptraceFPRegsSize is the size in bytes of Linux's user_i387_struct, the type
// manipulated by PTRACE_GETFPREGS and PTRACE_SETFPREGS on x86. Equivalently,
// ptraceFPRegsSize is the size in bytes of the x86 FXSAVE area.
const ptraceFPRegsSize = 512

// PtraceGetFPRegs implements Context.PtraceGetFPRegs.
func (s *State) PtraceGetFPRegs(dst io.Writer, maxlen int) (int, error) {
	if maxlen < ptraceFPRegsSize {
		return 0, linuxerr.EFAULT
	}

	return dst.Write((*s)[:ptraceFPRegsSize])
}

// PtraceSetFPRegs implements Context.PtraceSetFPRegs.
func (s *State) PtraceSetFPRegs(src io.Reader, maxlen int) (int, error) {
	if maxlen < ptraceFPRegsSize {
		return 0, linuxerr.EFAULT
	}

	var f [ptraceFPRegsSize]byte
	n, err := io.ReadFull(src, f[:])
	if err != nil {
		return 0, err
	}
	// Force reserved bits in MXCSR to 0. This is consistent with Linux.
	sanitizeMXCSR(State(f[:]))
	// N.B. this only copies the beginning of the FP state, which
	// corresponds to the FXSAVE area.
	copy(*s, f[:])
	return n, nil
}

const (
	// mxcsrOffset is the offset in bytes of the MXCSR field from the start of
	// the FXSAVE area. (Intel SDM Vol. 1, Table 10-2 "Format of an FXSAVE
	// Area")
	mxcsrOffset = 24

	// mxcsrMaskOffset is the offset in bytes of the MXCSR_MASK field from the
	// start of the FXSAVE area.
	mxcsrMaskOffset = 28
)

const (
	// minXstateBytes is the minimum size in bytes of an x86 XSAVE area, equal
	// to the size of the XSAVE legacy area (512 bytes) plus the size of the
	// XSAVE header (64 bytes). Equivalently, minXstateBytes is GDB's
	// X86_XSTATE_SSE_SIZE.
	minXstateBytes = 512 + 64

	// userXstateXCR0Offset is the offset in bytes of the USER_XSTATE_XCR0_WORD
	// field in Linux's struct user_xstateregs, which is the type manipulated
	// by ptrace(PTRACE_GET/SETREGSET, NT_X86_XSTATE). Equivalently,
	// userXstateXCR0Offset is GDB's I386_LINUX_XSAVE_XCR0_OFFSET.
	userXstateXCR0Offset = 464

	// xstateBVOffset is the offset in bytes of the XSTATE_BV field in an x86
	// XSAVE area.
	xstateBVOffset = 512

	// xsaveHeaderZeroedOffset and xsaveHeaderZeroedBytes indicate parts of the
	// XSAVE header that we coerce to zero: "Bytes 15:8 of the XSAVE header is
	// a state-component bitmap called XCOMP_BV. ... Bytes 63:16 of the XSAVE
	// header are reserved." - Intel SDM Vol. 1, Section 13.4.2 "XSAVE Header".
	// Linux ignores XCOMP_BV, but it's able to recover from XRSTOR #GP
	// exceptions resulting from invalid values; we aren't. Linux also never
	// uses the compacted format when doing XSAVE and doesn't even define the
	// compaction extensions to XSAVE as a CPU feature, so for simplicity we
	// assume no one is using them.
	xsaveHeaderZeroedOffset = 512 + 8
	xsaveHeaderZeroedBytes  = 64 - 8
)

// PtraceGetXstateRegs implements ptrace(PTRACE_GETREGS, NT_X86_XSTATE) by
// writing the floating point registers from this state to dst and returning the
// number of bytes written, which must be less than or equal to maxlen.
func (s *State) PtraceGetXstateRegs(dst io.Writer, maxlen int, featureSet cpuid.FeatureSet) (int, error) {
	// N.B. s.x86FPState may contain more state than the application
	// expects. We only copy the subset that would be in their XSAVE area.
	ess, _ := featureSet.ExtendedStateSize()
	f := make([]byte, ess)
	copy(f, *s)
	// "The XSAVE feature set does not use bytes 511:416; bytes 463:416 are
	// reserved." - Intel SDM Vol 1., Section 13.4.1 "Legacy Region of an XSAVE
	// Area". Linux uses the first 8 bytes of this area to store the OS XSTATE
	// mask. GDB relies on this: see
	// gdb/x86-linux-nat.c:x86_linux_read_description().
	hostarch.ByteOrder.PutUint64(f[userXstateXCR0Offset:], featureSet.ValidXCR0Mask())
	if len(f) > maxlen {
		f = f[:maxlen]
	}
	return dst.Write(f)
}

// PtraceSetXstateRegs implements ptrace(PTRACE_SETREGS, NT_X86_XSTATE) by
// reading floating point registers from src and returning the number of bytes
// read, which must be less than or equal to maxlen.
func (s *State) PtraceSetXstateRegs(src io.Reader, maxlen int, featureSet cpuid.FeatureSet) (int, error) {
	// Allow users to pass an xstate register set smaller than ours (they can
	// mask bits out of XSTATE_BV), as long as it's at least minXstateBytes.
	// Also allow users to pass a register set larger than ours; anything after
	// their ExtendedStateSize will be ignored. (I think Linux technically
	// permits setting a register set smaller than minXstateBytes, but it has
	// the same silent truncation behavior in kernel/ptrace.c:ptrace_regset().)
	if maxlen < minXstateBytes {
		return 0, unix.EFAULT
	}
	ess, _ := featureSet.ExtendedStateSize()
	if maxlen > int(ess) {
		maxlen = int(ess)
	}
	f := make([]byte, maxlen)
	if _, err := io.ReadFull(src, f); err != nil {
		return 0, err
	}
	n := copy(*s, f)
	s.SanitizeUser(featureSet)
	return n, nil
}

// SanitizeUser mutates s to ensure that restoring it is safe.
func (s *State) SanitizeUser(featureSet cpuid.FeatureSet) {
	f := *s

	// Force reserved bits in MXCSR to 0. This is consistent with Linux.
	sanitizeMXCSR(f)

	if len(f) >= minXstateBytes {
		// Users can't enable *more* XCR0 bits than what we, and the CPU, support.
		xstateBV := hostarch.ByteOrder.Uint64(f[xstateBVOffset:])
		xstateBV &= featureSet.ValidXCR0Mask()
		hostarch.ByteOrder.PutUint64(f[xstateBVOffset:], xstateBV)
		// Force XCOMP_BV and reserved bytes in the XSAVE header to 0.
		reserved := f[xsaveHeaderZeroedOffset : xsaveHeaderZeroedOffset+xsaveHeaderZeroedBytes]
		for i := range reserved {
			reserved[i] = 0
		}
	}
}

var (
	mxcsrMask     uint32
	initMXCSRMask sync.Once
)

// sanitizeMXCSR coerces reserved bits in the MXCSR field of f to 0. ("FXRSTOR
// generates a general-protection fault (#GP) in response to an attempt to set
// any of the reserved bits of the MXCSR register." - Intel SDM Vol. 1, Section
// 10.5.1.2 "SSE State")
func sanitizeMXCSR(f State) {
	mxcsr := hostarch.ByteOrder.Uint32(f[mxcsrOffset:])
	initMXCSRMask.Do(func() {
		temp := State(alignedBytes(uint(ptraceFPRegsSize), 16))
		initX86FPState(&temp[0], false /* useXsave */)
		mxcsrMask = hostarch.ByteOrder.Uint32(temp[mxcsrMaskOffset:])
		if mxcsrMask == 0 {
			// "If the value of the MXCSR_MASK field is 00000000H, then the
			// MXCSR_MASK value is the default value of 0000FFBFH." - Intel SDM
			// Vol. 1, Section 11.6.6 "Guidelines for Writing to the MXCSR
			// Register"
			mxcsrMask = 0xffbf
		}
	})
	mxcsr &= mxcsrMask
	hostarch.ByteOrder.PutUint32(f[mxcsrOffset:], mxcsr)
}

// SetMXCSR sets the MXCSR control/status register in the state.
func (s *State) SetMXCSR(mxcsr uint32) {
	hostarch.ByteOrder.PutUint32((*s)[mxcsrOffset:], mxcsr)
}

// BytePointer returns a pointer to the first byte of the state.
//
//go:nosplit
func (s *State) BytePointer() *byte {
	return &(*s)[0]
}

// XSTATE_BV does not exist if FXSAVE is used, but FXSAVE implicitly saves x87
// and SSE state, so this is the equivalent XSTATE_BV value.
const fxsaveBV uint64 = cpuid.XSAVEFeatureX87 | cpuid.XSAVEFeatureSSE

// AfterLoad converts the loaded state to the format that compatible with the
// current processor.
func (s *State) AfterLoad() {
	old := *s

	// Recreate the slice. This is done to ensure that it is aligned
	// appropriately in memory, and large enough to accommodate any new
	// state that may be saved by the new CPU. Even if extraneous new state
	// is saved, the state we care about is guaranteed to be a subset of
	// new state. Later optimizations can use less space when using a
	// smaller state component bitmap. Intel SDM Volume 1 Chapter 13 has
	// more info.
	*s = NewState()

	// x86FPState always contains all the FP state supported by the host.
	// We may have come from a newer machine that supports additional state
	// which we cannot restore.
	//
	// The x86 FP state areas are backwards compatible, so we can simply
	// truncate the additional floating point state.
	//
	// Applications should not depend on the truncated state because it
	// should relate only to features that were not exposed in the app
	// FeatureSet. However, because we do not *prevent* them from using
	// this state, we must verify here that there is no in-use state
	// (according to XSTATE_BV) which we do not support.
	if len(*s) < len(old) {
		// What do we support?
		supportedBV := fxsaveBV
		if fs := cpuid.HostFeatureSet(); fs.UseXsave() {
			supportedBV = fs.ValidXCR0Mask()
		}

		// What was in use?
		savedBV := fxsaveBV
		if len(old) >= xstateBVOffset+8 {
			savedBV = hostarch.ByteOrder.Uint64(old[xstateBVOffset:])
		}

		// Supported features must be a superset of saved features.
		if savedBV&^supportedBV != 0 {
			panic(ErrLoadingState{supportedFeatures: supportedBV, savedFeatures: savedBV})
		}
	}

	// Copy to the new, aligned location.
	copy(*s, old)
}
