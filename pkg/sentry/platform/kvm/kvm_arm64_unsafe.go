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

//go:build arm64
// +build arm64

package kvm

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostos"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/log"
)

var (
	runDataSize  int
	hasGuestPCID bool
)

func updateSystemValues(fd int) error {
	// Extract the mmap size.
	sz, errno := hostsyscall.RawSyscall(unix.SYS_IOCTL, uintptr(fd), KVM_GET_VCPU_MMAP_SIZE, 0)
	if errno != 0 {
		return fmt.Errorf("getting VCPU mmap size: %v", errno)
	}
	// Save the data.
	runDataSize = int(sz)
	hasGuestPCID = true

	// Success.
	return nil
}

// vvarMemslotUnusable checks if mapping vvar into a memslot is liable to being
// blocked by the host. This can happen due to kernel commits 2a8dfab and
// 0c67288.
func vvarMemslotUnusable(kvmFd int) bool {
	version, err := hostos.KernelVersion()
	// Problematic kernel version range:
	if err == nil && (version.LessThan(6, 17) || version.AtLeast(7, 1)) {
		return false
	}

	vvar, err := findRegionStartingWith("[vvar")
	if err != nil {
		// Very unexpected...
		log.Warningf("%v", err)
		// Let's just try our luck
		// or: we didn't find vvar once, we can't find it a second time.
		return false
	}
	if vvar.length == 0 {
		return false
	}

	vmFd, errno := hostsyscall.RawSyscall(unix.SYS_IOCTL, uintptr(kvmFd), KVM_CREATE_VM, 0)
	if errno != 0 {
		// We will re-fail on the actual VM creation.
		return false
	}
	defer hostsyscall.RawSyscall(unix.SYS_CLOSE, vmFd, 0, 0)

	userRegion := userMemoryRegion{
		slot:          0,
		flags:         _KVM_MEM_READONLY,
		guestPhysAddr: 0,
		memorySize:    uint64(vvar.length),
		userspaceAddr: uint64(uintptr(vvar.virtual)),
	}
	_, errno = hostsyscall.RawSyscall(unix.SYS_IOCTL, vmFd, KVM_SET_USER_MEMORY_REGION, uintptr(unsafe.Pointer(&userRegion)))
	return errno != 0
}
