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
	"fmt"
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

// getPACKeys reads the pointer authentication state that keys has room for
// from t.
func (t *thread) getPACKeys(keys *pacKeys) error {
	if keys.Address != nil {
		if err := t.pacKeysRegset(unix.PTRACE_GETREGSET, linux.NT_ARM_PACA_KEYS, unsafe.Pointer(keys.Address), unsafe.Sizeof(*keys.Address)); err != nil {
			return fmt.Errorf("PTRACE_GETREGSET(NT_ARM_PACA_KEYS): %w", err)
		}
	}
	if keys.Generic != nil {
		if err := t.pacKeysRegset(unix.PTRACE_GETREGSET, linux.NT_ARM_PACG_KEYS, unsafe.Pointer(keys.Generic), unsafe.Sizeof(*keys.Generic)); err != nil {
			return fmt.Errorf("PTRACE_GETREGSET(NT_ARM_PACG_KEYS): %w", err)
		}
	}
	if keys.Enabled != nil {
		if err := t.pacKeysRegset(unix.PTRACE_GETREGSET, linux.NT_ARM_PAC_ENABLED_KEYS, unsafe.Pointer(keys.Enabled), unsafe.Sizeof(*keys.Enabled)); err != nil {
			return fmt.Errorf("PTRACE_GETREGSET(NT_ARM_PAC_ENABLED_KEYS): %w", err)
		}
	}
	return nil
}

// setPACKeys writes the pointer authentication state in keys to t.
func (t *thread) setPACKeys(keys *pacKeys) error {
	if keys.Address != nil {
		if err := t.pacKeysRegset(unix.PTRACE_SETREGSET, linux.NT_ARM_PACA_KEYS, unsafe.Pointer(keys.Address), unsafe.Sizeof(*keys.Address)); err != nil {
			return fmt.Errorf("PTRACE_SETREGSET(NT_ARM_PACA_KEYS): %w", err)
		}
	}
	if keys.Generic != nil {
		if err := t.pacKeysRegset(unix.PTRACE_SETREGSET, linux.NT_ARM_PACG_KEYS, unsafe.Pointer(keys.Generic), unsafe.Sizeof(*keys.Generic)); err != nil {
			return fmt.Errorf("PTRACE_SETREGSET(NT_ARM_PACG_KEYS): %w", err)
		}
	}
	if keys.Enabled != nil {
		if err := t.pacKeysRegset(unix.PTRACE_SETREGSET, linux.NT_ARM_PAC_ENABLED_KEYS, unsafe.Pointer(keys.Enabled), unsafe.Sizeof(*keys.Enabled)); err != nil {
			return fmt.Errorf("PTRACE_SETREGSET(NT_ARM_PAC_ENABLED_KEYS): %w", err)
		}
	}
	return nil
}

func (t *thread) pacKeysRegset(op, note uintptr, data unsafe.Pointer, size uintptr) error {
	iovec := unix.Iovec{
		Base: (*byte)(data),
		Len:  uint64(size),
	}
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_PTRACE,
		op,
		uintptr(t.tid),
		note,
		uintptr(unsafe.Pointer(&iovec)),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
