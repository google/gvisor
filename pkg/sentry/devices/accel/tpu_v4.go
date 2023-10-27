// Copyright 2023 The gVisor Authors.
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

// Package accel implements proxying for hardware accelerators.
package accel

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/gasket"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// tpuV4FD implements vfs.FileDescriptionImpl for /dev/accel[0-9]+.
//
// accelFD is not savable; we do not implement save/restore of accelerator
// state.
type tpuV4FD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	hostFD     int32
	device     *tpuV4Device
	queue      waiter.Queue
	memmapFile accelFDMemmapFile
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *tpuV4FD) Release(context.Context) {
	fd.device.mu.Lock()
	defer fd.device.mu.Unlock()
	fd.device.openWriteFDs--
	if fd.device.openWriteFDs == 0 {
		log.Infof("openWriteFDs is zero, unpinning all sentry memory mappings")
		s := &fd.device.devAddrSet
		seg := s.FirstSegment()
		for seg.Ok() {
			r, v := seg.Range(), seg.Value()
			gpti := gasket.GasketPageTableIoctl{
				PageTableIndex: v.pageTableIndex,
				DeviceAddress:  r.Start,
				Size:           r.End - r.Start,
				HostAddress:    0,
			}
			_, err := ioctlInvokePtrArg(fd.hostFD, gasket.GASKET_IOCTL_UNMAP_BUFFER, &gpti)
			if err != nil {
				log.Warningf("could not unmap range [%#x, %#x) (index %d) on device: %v", r.Start, r.End, v.pageTableIndex, err)
			}
			mm.Unpin([]mm.PinnedRange{v.pinnedRange})
			gap := s.Remove(seg)
			seg = gap.NextSegment()
		}
		fd.device.owner = nil
	}
	fdnotifier.RemoveFD(fd.hostFD)
	unix.Close(int(fd.hostFD))
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *tpuV4FD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		fd.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *tpuV4FD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *tpuV4FD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(fd.hostFD, mask)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *tpuV4FD) Epollable() bool {
	return true
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *tpuV4FD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()
	argPtr := args[2].Pointer()
	argSize := linux.IOC_SIZE(cmd)

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		panic("Ioctl should be called from a task context")
	}
	if err := fd.checkPermission(t); err != nil {
		return 0, err
	}

	log.Infof("Accel ioctl %s called on fd %d with arg %v of size %d.", gasket.Ioctl(cmd), fd.hostFD, argPtr, argSize)
	switch gasket.Ioctl(cmd) {
	// Not yet implemented gasket ioctls.
	case gasket.GASKET_IOCTL_SET_EVENTFD, gasket.GASKET_IOCTL_CLEAR_EVENTFD,
		gasket.GASKET_IOCTL_NUMBER_PAGE_TABLES, gasket.GASKET_IOCTL_PAGE_TABLE_SIZE,
		gasket.GASKET_IOCTL_SIMPLE_PAGE_TABLE_SIZE, gasket.GASKET_IOCTL_PARTITION_PAGE_TABLE,
		gasket.GASKET_IOCTL_MAP_DMA_BUF:
		return 0, linuxerr.ENOSYS
	case gasket.GASKET_IOCTL_RESET:
		return ioctlInvoke[uint64](fd.hostFD, gasket.GASKET_IOCTL_RESET, args[2].Uint64())
	case gasket.GASKET_IOCTL_MAP_BUFFER:
		return gasketMapBufferIoctl(ctx, t, fd.hostFD, fd, argPtr)
	case gasket.GASKET_IOCTL_UNMAP_BUFFER:
		return gasketUnmapBufferIoctl(ctx, t, fd.hostFD, fd, argPtr)
	case gasket.GASKET_IOCTL_CLEAR_INTERRUPT_COUNTS:
		return ioctlInvoke(fd.hostFD, gasket.GASKET_IOCTL_CLEAR_INTERRUPT_COUNTS, 0)
	case gasket.GASKET_IOCTL_REGISTER_INTERRUPT:
		return gasketInterruptMappingIoctl(ctx, t, fd.hostFD, argPtr, fd.device.lite)
	case gasket.GASKET_IOCTL_UNREGISTER_INTERRUPT:
		return ioctlInvoke[uint64](fd.hostFD, gasket.GASKET_IOCTL_UNREGISTER_INTERRUPT, args[2].Uint64())
	default:
		return 0, linuxerr.EINVAL
	}
}

// checkPermission checks that the thread that owns this device is the only
// one that can issue commands to the TPU. Other threads with access to
// /dev/accel will not be able to issue commands to the device.
func (fd *tpuV4FD) checkPermission(t *kernel.Task) error {
	fd.device.mu.Lock()
	defer fd.device.mu.Unlock()
	owner := fd.device.owner
	if t.ThreadGroup() != owner {
		return linuxerr.EPERM
	}
	return nil
}

type pinnedAccelMem struct {
	pinnedRange    mm.PinnedRange
	pageTableIndex uint64
}

// DevAddrSet tracks device address ranges that have been mapped.
type devAddrSetFuncs struct{}

func (devAddrSetFuncs) MinKey() uint64 {
	return 0
}

func (devAddrSetFuncs) MaxKey() uint64 {
	return ^uint64(0)
}

func (devAddrSetFuncs) ClearValue(val *pinnedAccelMem) {
	*val = pinnedAccelMem{}
}

func (devAddrSetFuncs) Merge(r1 DevAddrRange, v1 pinnedAccelMem, r2 DevAddrRange, v2 pinnedAccelMem) (pinnedAccelMem, bool) {
	// Do we have the same backing file?
	if v1.pinnedRange.File != v2.pinnedRange.File {
		return pinnedAccelMem{}, false
	}

	// Do we have contiguous offsets in the backing file?
	if v1.pinnedRange.Offset+uint64(v1.pinnedRange.Source.Length()) != v2.pinnedRange.Offset {
		return pinnedAccelMem{}, false
	}

	// Are the virtual addresses contiguous?
	//
	// This check isn't strictly needed because 'mm.PinnedRange.Source'
	// is only used to track the size of the pinned region (this is
	// because the virtual address range can be unmapped or remapped
	// elsewhere). Regardless we require this for simplicity.
	if v1.pinnedRange.Source.End != v2.pinnedRange.Source.Start {
		return pinnedAccelMem{}, false
	}

	// Extend v1 to account for the adjacent PinnedRange.
	v1.pinnedRange.Source.End = v2.pinnedRange.Source.End
	return v1, true
}

func (devAddrSetFuncs) Split(r DevAddrRange, val pinnedAccelMem, split uint64) (pinnedAccelMem, pinnedAccelMem) {
	n := split - r.Start

	left := val
	left.pinnedRange.Source.End = left.pinnedRange.Source.Start + hostarch.Addr(n)

	right := val
	right.pinnedRange.Source.Start += hostarch.Addr(n)
	right.pinnedRange.Offset += n

	return left, right
}
