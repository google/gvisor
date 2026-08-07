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

//go:build arm64
// +build arm64

package systrap

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostsyscall"
)

// getTLS gets the thread local storage register.
func (t *thread) getTLS(tls *uint64) error {
	iovec := unix.Iovec{
		Base: (*byte)(unsafe.Pointer(tls)),
		Len:  uint64(unsafe.Sizeof(*tls)),
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_PTRACE,
		unix.PTRACE_GETREGSET,
		uintptr(t.tid),
		linux.NT_ARM_TLS,
		uintptr(unsafe.Pointer(&iovec)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// setTLS sets the thread local storage register.
func (t *thread) setTLS(tls *uint64) error {
	iovec := unix.Iovec{
		Base: (*byte)(unsafe.Pointer(tls)),
		Len:  uint64(unsafe.Sizeof(*tls)),
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_PTRACE,
		unix.PTRACE_SETREGSET,
		uintptr(t.tid),
		linux.NT_ARM_TLS,
		uintptr(unsafe.Pointer(&iovec)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// userPACAddressKeys mirrors the kernel's struct user_pac_address_keys
// (NT_ARM_PACA_KEYS): the APIA/APIB/APDA/APDB keys, each {lo, hi}. // PAC-KEY-CR-A
type userPACAddressKeys struct {
	apiaLo, apiaHi uint64
	apibLo, apibHi uint64
	apdaLo, apdaHi uint64
	apdbLo, apdbHi uint64
}

// userPACGenericKeys mirrors struct user_pac_generic_keys (NT_ARM_PACG_KEYS): APGA {lo, hi}.
type userPACGenericKeys struct {
	apgaLo, apgaHi uint64
}

func (t *thread) setPACAddressKeys(k *userPACAddressKeys) error {
	iovec := unix.Iovec{Base: (*byte)(unsafe.Pointer(k)), Len: uint64(unsafe.Sizeof(*k))}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_PTRACE, unix.PTRACE_SETREGSET, uintptr(t.tid),
		linux.NT_ARM_PACA_KEYS, uintptr(unsafe.Pointer(&iovec)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (t *thread) setPACGenericKeys(k *userPACGenericKeys) error {
	iovec := unix.Iovec{Base: (*byte)(unsafe.Pointer(k)), Len: uint64(unsafe.Sizeof(*k))}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_PTRACE, unix.PTRACE_SETREGSET, uintptr(t.tid),
		linux.NT_ARM_PACG_KEYS, uintptr(unsafe.Pointer(&iovec)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// installPACKeys installs a 10-word key set (8 address + 2 generic) on this guest thread
// via ptrace, so the sandbox's PAC keys are consistent across C/R.
func (t *thread) installPACKeys(keys [10]uint64) error {
	a := userPACAddressKeys{keys[0], keys[1], keys[2], keys[3], keys[4], keys[5], keys[6], keys[7]}
	if err := t.setPACAddressKeys(&a); err != nil {
		return err
	}
	g := userPACGenericKeys{keys[8], keys[9]}
	return t.setPACGenericKeys(&g)
}
