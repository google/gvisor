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

//go:build amd64
// +build amd64

package kvm

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
)

func rdfsbase() uint64
func rdgsbase() uint64

// loadSegments copies the current segments.
//
// This may be called from within the signal context and throws on error.
//
//go:nosplit
func (c *vCPU) loadSegments(tid uint64) {
	if errno := hostsyscall.RawSyscallErrno(unix.SYS_SIGALTSTACK, 0, uintptr(unsafe.Pointer(&c.signalStack)), 0); errno != 0 {
		throw("sigaltstack")
	}
	if hasFSGSBASE {
		c.CPU.Registers().Fs_base = rdfsbase()
		c.CPU.Registers().Gs_base = rdgsbase()
	} else {
		if errno := hostsyscall.RawSyscallErrno(
			unix.SYS_ARCH_PRCTL,
			linux.ARCH_GET_FS,
			uintptr(unsafe.Pointer(&c.CPU.Registers().Fs_base)),
			0); errno != 0 {
			throw("getting FS segment")
		}
		if errno := hostsyscall.RawSyscallErrno(
			unix.SYS_ARCH_PRCTL,
			linux.ARCH_GET_GS,
			uintptr(unsafe.Pointer(&c.CPU.Registers().Gs_base)),
			0); errno != 0 {
			throw("getting GS segment")
		}
	}
	c.tid.Store(tid)
}

// setCPUID sets the CPUID to be used by the guest.
func (c *vCPU) setCPUID() error {
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_CPUID2,
		uintptr(unsafe.Pointer(&cpuidSupported))); errno != 0 {
		return fmt.Errorf("error setting CPUID: %v", errno)
	}
	return nil
}

func (c *vCPU) setPAT() error {
	// See Intel SDM Vol. 3, Sec. 13.12.2 "IA32_PAT MSR", or AMD64 APM Vol. 2,
	// Sec. 7.8.1 "PAT Register".
	const (
		_MSR_IA32_PAT = 0x277

		_PAT_UC = 0x00
		_PAT_WC = 0x01
		_PAT_WB = 0x06
	)
	registers := modelControlRegisters{
		nmsrs: 1,
	}
	registers.entries[0].index = _MSR_IA32_PAT
	if hostarch.NumMemoryTypes != 3 {
		panic("additional memory types must be configured in PAT")
	}
	registers.entries[0].data = (_PAT_WB << (hostarch.MemoryTypeWriteBack * 8)) |
		(_PAT_WC << (hostarch.MemoryTypeWriteCombine * 8)) |
		(_PAT_UC << (hostarch.MemoryTypeUncached * 8))
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_MSRS,
		uintptr(unsafe.Pointer(&registers))); errno != 0 {
		return fmt.Errorf("error setting PAT: %v", errno)
	}
	return nil
}

// getTSCFreq gets the TSC frequency.
//
// If mustSucceed is true, then this function panics on error.
func (c *vCPU) getTSCFreq() (uintptr, error) {
	rawFreq, errno := hostsyscall.RawSyscall(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_GET_TSC_KHZ,
		0 /* ignored */)
	if errno != 0 {
		return 0, errno
	}
	return rawFreq, nil
}

// setTSCFreq sets the TSC frequency.
func (c *vCPU) setTSCFreq(freq uintptr) error {
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_TSC_KHZ,
		freq /* khz */); errno != 0 {
		return fmt.Errorf("error setting TSC frequency: %v", errno)
	}
	return nil
}

// setTSCOffset sets the TSC offset.
func (c *vCPU) setTSCOffset(offset uint64) error {
	da := struct {
		flags uint32
		group uint32
		attr  uint64
		addr  unsafe.Pointer
	}{
		group: _KVM_VCPU_TSC_CTRL,
		attr:  _KVM_VCPU_TSC_OFFSET,
		addr:  unsafe.Pointer(&offset),
	}
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_DEVICE_ATTR,
		uintptr(unsafe.Pointer(&da))); errno != 0 {
		return fmt.Errorf("error setting tsc offset: %v", errno)
	}
	return nil
}

// setTSC sets the TSC value.
func (c *vCPU) setTSC(value uint64) error {
	const _MSR_IA32_TSC = 0x00000010
	registers := modelControlRegisters{
		nmsrs: 1,
	}
	registers.entries[0].index = _MSR_IA32_TSC
	registers.entries[0].data = value
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_MSRS,
		uintptr(unsafe.Pointer(&registers))); errno != 0 {
		return fmt.Errorf("error setting tsc: %v", errno)
	}
	return nil
}

func (c *vCPU) enableCPUIDFaulting() error {
	const (
		_MSR_MISC_FEATURES_ENABLE              = 0x140
		_MSR_MISC_FEATURES_ENABLES_CPUID_FAULT = 1 << 0
	)
	registers := modelControlRegisters{
		nmsrs: 1,
	}
	registers.entries[0].index = _MSR_MISC_FEATURES_ENABLE
	registers.entries[0].data = _MSR_MISC_FEATURES_ENABLES_CPUID_FAULT
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_MSRS,
		uintptr(unsafe.Pointer(&registers))); errno != 0 {
		return fmt.Errorf("error enabling CPUID faulting: %v", errno)
	}
	return nil
}

// setUserRegisters sets user registers in the vCPU.
//
//go:nosplit
func (c *vCPU) setUserRegisters(uregs *userRegs) unix.Errno {
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_REGS,
		uintptr(unsafe.Pointer(uregs))); errno != 0 {
		return errno
	}
	return 0
}

// getUserRegisters reloads user registers in the vCPU.
//
// This is safe to call from a nosplit context.
//
//go:nosplit
func (c *vCPU) getUserRegisters(uregs *userRegs) unix.Errno {
	if errno := hostsyscall.RawSyscallErrno( // escapes: no.
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_GET_REGS,
		uintptr(unsafe.Pointer(uregs))); errno != 0 {
		return errno
	}
	return 0
}

// setSystemRegisters sets system registers.
func (c *vCPU) setSystemRegisters(sregs *systemRegs) error {
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_SREGS,
		uintptr(unsafe.Pointer(sregs))); errno != 0 {
		return fmt.Errorf("error setting system registers: %v", errno)
	}
	return nil
}

// getSystemRegisters sets system registers.
//
//go:nosplit
func (c *vCPU) getSystemRegisters(sregs *systemRegs) unix.Errno {
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_GET_SREGS,
		uintptr(unsafe.Pointer(sregs))); errno != 0 {
		return errno
	}
	return 0
}

//go:nosplit
func seccompMmapSyscall(context unsafe.Pointer) (uintptr, uintptr, unix.Errno) {
	ctx := bluepillArchContext(context)

	// MAP_DENYWRITE is deprecated and ignored by kernel. We use it only for seccomp filters.
	addr, e := hostsyscall.RawSyscall6(uintptr(ctx.Rax), uintptr(ctx.Rdi), uintptr(ctx.Rsi),
		uintptr(ctx.Rdx), uintptr(ctx.R10)|unix.MAP_DENYWRITE, uintptr(ctx.R8), uintptr(ctx.R9))
	if e != 0 {
		ctx.Rax = uint64(-e)
	} else {
		ctx.Rax = uint64(addr)
	}

	return addr, uintptr(ctx.Rsi), unix.Errno(e)
}

func (m *machine) shadowVDSOVirt() uintptr {
	if len(m.shadowVDSO) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&m.shadowVDSO[0]))
}

// initShadowVDSO creates a binary-patched shadow copy of the host [vdso]
// when tscOffset != 0. In GR0 (guest ring 0), hardware RDTSC/RDTSCP returns
// Host_TSC + tscOffset, while the host [vvar] page contains raw Host_TSC
// base cycles. By patching RDTSC/RDTSCP in the shadow VDSO to subtract
// tscOffset, GR0 VDSO calls (such as Go runtime time.Now() / nanotime1)
// compute the exact unadjusted host time without any VM-exits.
func (m *machine) initShadowVDSO() error {
	if m.tscOffset == 0 {
		return nil
	}
	var vdsoRegion virtualRegion
	found := false
	if err := applyVirtualRegions(func(vr virtualRegion) bool {
		if vr.filename == "[vdso]" {
			vdsoRegion = vr
			found = true
			return true
		}
		return false
	}); err != nil {
		return fmt.Errorf("error scanning /proc/self/maps for [vdso]: %v", err)
	}
	if !found || vdsoRegion.length == 0 {
		return fmt.Errorf("[vdso] region not found in /proc/self/maps")
	}
	if excludeVirtualRegion(vdsoRegion) {
		return nil
	}

	addr, errno := hostsyscall.RawSyscall6(
		unix.SYS_MMAP,
		0,
		vdsoRegion.length,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
		^uintptr(0),
		0)
	if errno != 0 {
		return fmt.Errorf("failed to allocate shadow VDSO memory: %v", errno)
	}
	shadowSlice := sliceFromAddr(addr, vdsoRegion.length)
	origSlice := sliceFromAddr(vdsoRegion.virtual, vdsoRegion.length)
	copy(shadowSlice, origSlice)

	if err := patchVDSOTSCOffset(shadowSlice, m.tscOffset); err != nil {
		hostsyscall.RawSyscallErrno(unix.SYS_MUNMAP, addr, vdsoRegion.length, 0)
		return fmt.Errorf("failed to patch shadow VDSO: %v", err)
	}

	m.shadowVDSO = shadowSlice
	m.vdsoVirt = vdsoRegion.virtual
	return nil
}

func (m *machine) protectShadowVDSO() {
	if len(m.shadowVDSO) == 0 {
		return
	}
	shadowVirt := m.shadowVDSOVirt()
	length := uintptr(len(m.shadowVDSO))
	for length != 0 {
		physical, plength, ok := translateToPhysical(shadowVirt)
		if !ok || plength == 0 {
			panic(fmt.Sprintf("impossible translation: shadowVirt %x length %x", shadowVirt, length))
		}
		if plength > length {
			plength = length
		}
		m.kernel.PageTables.Map(
			hostarch.Addr(shadowVirt),
			plength,
			pagetables.MapOpts{AccessType: hostarch.Read},
			physical)
		m.mapPhysical(physical, plength)
		length -= plength
		shadowVirt += plength
	}
}

func (m *machine) destroyShadowVDSO() {
	if len(m.shadowVDSO) == 0 {
		return
	}
	addr := uintptr(unsafe.Pointer(&m.shadowVDSO[0]))
	length := uintptr(len(m.shadowVDSO))
	m.shadowVDSO = nil
	if errno := hostsyscall.RawSyscallErrno(unix.SYS_MUNMAP, addr, length, 0); errno != 0 {
		panic(fmt.Sprintf("error unmapping shadow VDSO: %v", errno))
	}
}

func patchVDSOTSCOffset(vdsoBytes []byte, tscOffset uint64) error {
	f, err := elf.NewFile(bytes.NewReader(vdsoBytes))
	if err != nil {
		return fmt.Errorf("failed to parse [vdso] ELF: %v", err)
	}
	defer f.Close()

	textSec := f.Section(".text")
	if textSec == nil {
		return fmt.Errorf("[vdso] ELF missing .text section")
	}
	if textSec.Offset+textSec.Size > uint64(len(vdsoBytes)) {
		return fmt.Errorf("[vdso] .text section out of bounds")
	}

	const (
		rdtscpStubLen      = 15
		lfenceRdtscStubLen = 17
		totalStubsLen      = rdtscpStubLen + lfenceRdtscStubLen
	)

	stubOffset := -1
	if altSec := f.Section(".altinstr_replacement"); altSec != nil {
		if altSec.Size >= totalStubsLen && altSec.Offset+altSec.Size <= uint64(len(vdsoBytes)) {
			stubOffset = int(altSec.Offset)
		}
	}
	if stubOffset == -1 {
		for _, p := range f.Progs {
			if p.Type != elf.PT_LOAD || (p.Flags&elf.PF_X) == 0 {
				continue
			}
			segEnd := int(p.Off + p.Memsz)
			if segEnd > len(vdsoBytes) {
				segEnd = len(vdsoBytes)
			}
			textEnd := int(textSec.Offset + textSec.Size)
			if segEnd-totalStubsLen >= textEnd {
				allZero := true
				cand := segEnd - totalStubsLen
				for j := cand; j < segEnd; j++ {
					if vdsoBytes[j] != 0 {
						allZero = false
						break
					}
				}
				if allZero {
					stubOffset = cand
					break
				}
			}
		}
	}
	if stubOffset == -1 {
		return fmt.Errorf("no space found in [vdso] for %d-byte TSC adjustment stubs", totalStubsLen)
	}

	rdtscpStubOff := stubOffset
	lfenceRdtscStubOff := stubOffset + rdtscpStubLen

	lo := uint32(tscOffset)
	hi := uint32(tscOffset >> 32)

	// rdtscp stub (15 bytes):
	//   0f 01 f9                rdtscp
	//   2d <lo: 4 bytes LE>     subl $lo, %eax
	//   81 da <hi: 4 bytes LE>  sbbl $hi, %edx
	//   c3                      ret
	copy(vdsoBytes[rdtscpStubOff:], []byte{0x0f, 0x01, 0xf9, 0x2d})
	binary.LittleEndian.PutUint32(vdsoBytes[rdtscpStubOff+4:rdtscpStubOff+8], lo)
	vdsoBytes[rdtscpStubOff+8] = 0x81
	vdsoBytes[rdtscpStubOff+9] = 0xda
	binary.LittleEndian.PutUint32(vdsoBytes[rdtscpStubOff+10:rdtscpStubOff+14], hi)
	vdsoBytes[rdtscpStubOff+14] = 0xc3

	// lfence; rdtsc stub (17 bytes):
	//   0f ae e8                lfence
	//   0f 31                   rdtsc
	//   2d <lo: 4 bytes LE>     subl $lo, %eax
	//   81 da <hi: 4 bytes LE>  sbbl $hi, %edx
	//   c3                      ret
	copy(vdsoBytes[lfenceRdtscStubOff:], []byte{0x0f, 0xae, 0xe8, 0x0f, 0x31, 0x2d})
	binary.LittleEndian.PutUint32(vdsoBytes[lfenceRdtscStubOff+6:lfenceRdtscStubOff+10], lo)
	vdsoBytes[lfenceRdtscStubOff+10] = 0x81
	vdsoBytes[lfenceRdtscStubOff+11] = 0xda
	binary.LittleEndian.PutUint32(vdsoBytes[lfenceRdtscStubOff+12:lfenceRdtscStubOff+16], hi)
	vdsoBytes[lfenceRdtscStubOff+16] = 0xc3

	textStart := int(textSec.Offset)
	textEnd := int(textSec.Offset + textSec.Size)
	patchedCount := 0
	for i := textStart; i <= textEnd-5; i++ {
		targetStubOff := -1
		if vdsoBytes[i] == 0x0f && vdsoBytes[i+1] == 0x01 && vdsoBytes[i+2] == 0xf9 {
			if (vdsoBytes[i+3] == 0x66 && vdsoBytes[i+4] == 0x90) ||
				(vdsoBytes[i+3] == 0x90 && vdsoBytes[i+4] == 0x90) {
				targetStubOff = rdtscpStubOff
			}
		} else if vdsoBytes[i] == 0x0f && vdsoBytes[i+1] == 0xae && vdsoBytes[i+2] == 0xe8 &&
			vdsoBytes[i+3] == 0x0f && vdsoBytes[i+4] == 0x31 {
			targetStubOff = lfenceRdtscStubOff
		} else if vdsoBytes[i] == 0x0f && vdsoBytes[i+1] == 0x31 {
			if (vdsoBytes[i+2] == 0x0f && vdsoBytes[i+3] == 0x1f && vdsoBytes[i+4] == 0x00) ||
				(vdsoBytes[i+2] == 0x66 && vdsoBytes[i+3] == 0x66 && vdsoBytes[i+4] == 0x90) ||
				(vdsoBytes[i+2] == 0x90 && vdsoBytes[i+3] == 0x90 && vdsoBytes[i+4] == 0x90) {
				targetStubOff = lfenceRdtscStubOff
			}
		}
		if targetStubOff != -1 {
			rel32 := int32(targetStubOff - (i + 5))
			vdsoBytes[i] = 0xe8 // CALL rel32
			binary.LittleEndian.PutUint32(vdsoBytes[i+1:i+5], uint32(rel32))
			i += 4
			patchedCount++
		}
	}
	if patchedCount == 0 {
		return fmt.Errorf("no rdtsc/rdtscp instructions found in [vdso] .text")
	}
	log.Debugf("Patched %d rdtsc/rdtscp sites in shadow VDSO (tscOffset=%#x)", patchedCount, tscOffset)
	return nil
}
