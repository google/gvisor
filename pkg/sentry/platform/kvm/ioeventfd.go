// Copyright 2025 The gVisor Authors.
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

package kvm

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/eventfd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

// IoeventfdEnable causes the given eventfd to use MMIO when Eventfd.Write() is
// called in k's guest mode.
//
// Postconditions: Eventfd.Write() cannot be called while in the guest mode of
// any VM other than k, i.e. no other KVM platform instance may be in use.
func (k *KVM) IoeventfdEnable(ev *eventfd.Eventfd) error {
	return k.machine.ioeventfdEnable(ev)
}

func (m *machine) ioeventfdEnable(ev *eventfd.Eventfd) error {
	if addr := ev.MMIOAddr(); addr != 0 {
		return fmt.Errorf("eventfd already has MMIO address %#x", addr)
	}
	addr, err := getIoeventfdMMIOAddr()
	if err != nil {
		return err
	}
	physical, _, ok := translateToPhysical(addr)
	if !ok {
		putIoeventfdMMIOAddr(addr)
		return fmt.Errorf("failed to obtain physical address for ioeventfd MMIO address %#x", addr)
	}
	ioeventfd := kvmIoeventfd{
		Addr: uint64(physical),
		Len:  8,
		FD:   int32(ev.FD()),
	}
	if errno := kvmIoeventfdIoctl(m.fd, &ioeventfd); errno != 0 {
		putIoeventfdMMIOAddr(addr)
		return errno
	}
	ev.EnableMMIO(addr, ioeventfdMMIOController{m})
	return nil
}

// IoeventfdDisable undoes the effect of a previous call to IoeventfdEnable.
func (k *KVM) IoeventfdDisable(ev *eventfd.Eventfd) {
	k.machine.ioeventfdDisable(ev)
}

func (m *machine) ioeventfdDisable(ev *eventfd.Eventfd) {
	addr := ev.MMIOAddr()
	if addr == 0 {
		return
	}
	physical, _, ok := translateToPhysical(addr)
	if !ok {
		log.Warningf("Can't deassign ioeventfd MMIO address %#x: no physical address?", addr)
	} else {
		ioeventfd := kvmIoeventfd{
			Addr:  uint64(physical),
			Len:   8,
			FD:    int32(ev.FD()),
			Flags: _KVM_IOEVENTFD_FLAG_DEASSIGN,
		}
		if errno := kvmIoeventfdIoctl(m.fd, &ioeventfd); errno != 0 {
			log.Warningf("Failed to deassign ioeventfd for FD %d, addr %#x, physical %#x: %v", ev.FD(), addr, physical, errno)
		}
	}
	ev.DisableMMIO()
}

// ioeventfdMMIOController implements eventfd.MMIOController.
// ioeventfdMMIOController consists of a single pointer field, allowing it to
// be inlined into eventfd.MMIOController interface values, avoiding additional
// allocations.
type ioeventfdMMIOController struct {
	m *machine
}

// Enabled implements eventfd.MMIOController.Enabled.
func (c ioeventfdMMIOController) Enabled() bool {
	return inKernelMode()
}

// Close implements eventfd.MMIOController.Close.
func (c ioeventfdMMIOController) Close(ev eventfd.Eventfd) {
	// ioeventfdDisable() => ev.DisableMMIO() will be useless since ev is a
	// value and not a pointer, but ev shouldn't be used again after Close
	// anwyay.
	c.m.ioeventfdDisable(&ev)
}

// ioeventfdMMIO allocates 8-byte regions from a mapping that is excluded from
// the guest physical address space (so that guest accesses to it trigger MMIO
// exits), allowing those addresses to be used for ioeventfds.
var ioeventfdMMIO struct {
	initOnce sync.Once
	mapping  uintptr
	mu       sync.Mutex
	inuse    bitmap.Bitmap
}

// kvmIoeventfd is struct kvm_ioeventfd.
type kvmIoeventfd struct {
	DataMatch uint64
	Addr      uint64
	Len       uint32
	FD        int32
	Flags     uint32
	Pad       [36]byte
}

const maxIoeventfds = 1024 // arbitrary

func initIoeventfdMMIO() {
	ioeventfdMMIO.initOnce.Do(func() {
		// Make a shared anonymous mapping, rather than a private anonymous
		// one, to prevent it from being merged with other VMAs.
		mapLen := uintptr(maxIoeventfds) * 8
		mapping, _, errno := unix.Syscall6(
			unix.SYS_MMAP,
			0,
			mapLen,
			unix.PROT_NONE,
			unix.MAP_SHARED|unix.MAP_ANONYMOUS,
			^uintptr(0),
			0)
		if errno != 0 {
			log.Warningf("Failed to create ioeventfdMMIOAllocator mapping: %v", errno)
			return
		}
		ioeventfdMMIO.mapping = mapping
		ioeventfdMMIO.inuse = bitmap.New(maxIoeventfds)
	})
}

// getIoeventfdMMIOAddr returns an MMIO address that may be used by a
// kvm_ioeventfd.
func getIoeventfdMMIOAddr() (uintptr, error) {
	ioeventfdMMIO.mu.Lock()
	defer ioeventfdMMIO.mu.Unlock()
	i, err := ioeventfdMMIO.inuse.FirstZero(0)
	if err != nil {
		return 0, fmt.Errorf("no ioeventfd MMIO addresses available (%d in use)", ioeventfdMMIO.inuse.GetNumOnes())
	}
	ioeventfdMMIO.inuse.Add(i)
	return ioeventfdMMIO.mapping + uintptr(i)*8, nil
}

// putIoeventfdMMIOAddr marks an MMIO address previously returned by
// getIoeventfdMMIOAddr() as no longer in use.
func putIoeventfdMMIOAddr(addr uintptr) {
	i := (addr - ioeventfdMMIO.mapping) / 8
	ioeventfdMMIO.mu.Lock()
	defer ioeventfdMMIO.mu.Unlock()
	ioeventfdMMIO.inuse.Remove(uint32(i))
}
