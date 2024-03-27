// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tpuproxy

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// deviceFD implements vfs.FileDescriptionImpl for /dev/vfio/vfio.
type vfioFd struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	hostFd     int32
	device     *vfioDevice
	queue      waiter.Queue
	memmapFile vfioFDMemmapFile
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *vfioFd) Release(context.Context) {
	fdnotifier.RemoveFD(fd.hostFd)
	fd.queue.Notify(waiter.EventHUp)
	unix.Close(int(fd.hostFd))
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *vfioFd) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(fd.hostFd); err != nil {
		fd.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *vfioFd) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(fd.hostFd); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *vfioFd) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(fd.hostFd, mask)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *vfioFd) Epollable() bool {
	return true
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *vfioFd) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		panic("Ioctl should be called from a task context")
	}
	switch cmd {
	case linux.VFIO_CHECK_EXTENSION:
		return fd.checkExtension(extension(args[2].Int()))
	case linux.VFIO_SET_IOMMU:
		return fd.setIOMMU(extension(args[2].Int()))
	case linux.VFIO_IOMMU_MAP_DMA:
		return fd.iommuMapDma(ctx, t, args[2].Pointer())
	}
	return 0, linuxerr.ENOSYS
}

// checkExtension returns a positive integer when the given VFIO extension
// is supported, otherwise, it returns 0.
func (fd *vfioFd) checkExtension(ext extension) (uintptr, error) {
	switch ext {
	case linux.VFIO_TYPE1_IOMMU, linux.VFIO_SPAPR_TCE_IOMMU, linux.VFIO_TYPE1v2_IOMMU:
		ret, err := IOCTLInvoke[uint32, int32](fd.hostFd, linux.VFIO_CHECK_EXTENSION, int32(ext))
		if err != nil {
			log.Warningf("check VFIO extension %s: %v", ext, err)
			return 0, err
		}
		return ret, nil
	}
	return 0, linuxerr.EINVAL
}

// Set the iommu to the given type.  The type must be supported by an iommu
// driver as verified by calling VFIO_CHECK_EXTENSION using the same type.
func (fd *vfioFd) setIOMMU(ext extension) (uintptr, error) {
	switch ext {
	case linux.VFIO_TYPE1_IOMMU, linux.VFIO_SPAPR_TCE_IOMMU, linux.VFIO_TYPE1v2_IOMMU:
		ret, err := IOCTLInvoke[uint32, int32](fd.hostFd, linux.VFIO_SET_IOMMU, int32(ext))
		if err != nil {
			log.Warningf("set the IOMMU group to %s: %v", ext, err)
			return 0, err
		}
		return ret, nil
	}
	return 0, linuxerr.EINVAL
}

func (fd *vfioFd) iommuMapDma(ctx context.Context, t *kernel.Task, arg hostarch.Addr) (uintptr, error) {
	var dmaMap linux.VFIOIommuType1DmaMap
	if _, err := dmaMap.CopyIn(t, arg); err != nil {
		return 0, err
	}
	tmm := t.MemoryManager()
	ar, ok := tmm.CheckIORange(hostarch.Addr(dmaMap.Vaddr), int64(dmaMap.Size))
	if !ok {
		return 0, linuxerr.EFAULT
	}
	if !ar.IsPageAligned() || (dmaMap.Size/hostarch.PageSize) == 0 {
		return 0, linuxerr.EINVAL
	}
	// See comments at pkg/sentry/devices/accel/gasket.go, line 57-60.
	devAddr := dmaMap.IOVa
	devAddr &^= (hostarch.PageSize - 1)

	devar := DevAddrRange{
		devAddr,
		devAddr + dmaMap.Size,
	}
	if !devar.WellFormed() {
		return 0, linuxerr.EINVAL
	}
	// Reserve a range in the address space.
	m, _, errno := unix.RawSyscall6(unix.SYS_MMAP, 0 /* addr */, uintptr(ar.Length()), unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uintptr(0), 0)
	if errno != 0 {
		return 0, errno
	}
	cu := cleanup.Make(func() {
		unix.RawSyscall(unix.SYS_MUNMAP, m, uintptr(ar.Length()), 0)
	})
	defer cu.Clean()
	// Mirror application mappings into the reserved range.
	prs, err := t.MemoryManager().Pin(ctx, ar, hostarch.ReadWrite, false)
	cu.Add(func() {
		mm.Unpin(prs)
	})
	if err != nil {
		return 0, err
	}
	sentryAddr := uintptr(m)
	for _, pr := range prs {
		ims, err := pr.File.MapInternal(memmap.FileRange{Start: pr.Offset, End: pr.Offset + uint64(pr.Source.Length())}, hostarch.ReadWrite)
		if err != nil {
			return 0, err
		}
		for !ims.IsEmpty() {
			im := ims.Head()
			if _, _, errno := unix.RawSyscall6(unix.SYS_MREMAP, im.Addr(), 0, uintptr(im.Len()), linux.MREMAP_MAYMOVE|linux.MREMAP_FIXED, sentryAddr, 0); errno != 0 {
				return 0, errno
			}
			sentryAddr += uintptr(im.Len())
			ims = ims.Tail()
		}
	}
	// Replace Vaddr with the host's virtual address.
	dmaMap.Vaddr = uint64(m)
	n, err := IOCTLInvokePtrArg[uint32](fd.hostFd, linux.VFIO_IOMMU_MAP_DMA, &dmaMap)
	if err != nil {
		return n, err
	}
	cu.Release()
	// Unmap the reserved range, which is no longer required.
	unix.RawSyscall(unix.SYS_MUNMAP, m, uintptr(ar.Length()), 0)

	fd.device.mu.Lock()
	defer fd.device.mu.Unlock()
	for _, pr := range prs {
		rlen := uint64(pr.Source.Length())
		fd.device.devAddrSet.InsertRange(DevAddrRange{
			devAddr,
			devAddr + rlen,
		}, pr)
		devAddr += rlen
	}
	return n, nil
}

// VFIO extension.
type extension int32

// String implements fmt.Stringer for VFIO extension string representation.
func (e extension) String() string {
	switch e {
	case linux.VFIO_TYPE1_IOMMU:
		return "VFIO_TYPE1_IOMMU"
	case linux.VFIO_SPAPR_TCE_IOMMU:
		return "VFIO_SPAPR_TCE_IOMMU"
	case linux.VFIO_TYPE1v2_IOMMU:
		return "VFIO_TYPE1v2_IOMMU"
	}
	return ""
}
