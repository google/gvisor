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

// Package tpuproxy implements proxying for TPU devices.
package tpuproxy

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/eventfd"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// A value of -1 can be used to either de-assign interrupts if already
	// assigned or skip un-assigned interrupts.
	disableInterrupt = -1
)

var (
	// vfioDeviceInfoFlags contains all available flags for
	// IOCTL command VFIO_DEVICE_GET_INFO.
	vfioDeviceInfoFlags uint32 = linux.VFIO_DEVICE_FLAGS_RESET | linux.VFIO_DEVICE_FLAGS_PCI |
		linux.VFIO_DEVICE_FLAGS_PLATFORM | linux.VFIO_DEVICE_FLAGS_AMBA |
		linux.VFIO_DEVICE_FLAGS_CCW | linux.VFIO_DEVICE_FLAGS_AP | linux.VFIO_DEVICE_FLAGS_FSL_MC |
		linux.VFIO_DEVICE_FLAGS_CAPS | linux.VFIO_DEVICE_FLAGS_CDX
	// vfioIrqSetFlags includes all available flags for IOCTL comamnd VFIO_DEVICE_SET_IRQS
	vfioIrqSetFlags uint32 = linux.VFIO_IRQ_SET_DATA_TYPE_MASK | linux.VFIO_IRQ_SET_ACTION_TYPE_MASK
)

// tpuFD implements vfs.FileDescriptionImpl for /dev/vfio/[0-9]+
//
// tpuFD is not savable until TPU save/restore is needed.
type tpuFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	hostFD     int32
	device     *tpuDevice
	queue      waiter.Queue
	memmapFile tpuFDMemmapFile
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *tpuFD) Release(context.Context) {
	fdnotifier.RemoveFD(fd.hostFD)
	fd.queue.Notify(waiter.EventHUp)
	unix.Close(int(fd.hostFD))
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *tpuFD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		fd.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *tpuFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *tpuFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(fd.hostFD, mask)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *tpuFD) Epollable() bool {
	return true
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *tpuFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		panic("Ioctl should be called from a task context")
	}
	switch cmd {
	case linux.VFIO_GROUP_SET_CONTAINER:
		return fd.setContainer(ctx, t, args[2].Pointer())
	case linux.VFIO_GROUP_GET_DEVICE_FD:
		ret, cleanup, err := fd.getPciDeviceFd(t, args[2].Pointer())
		defer cleanup()
		return ret, err
	}
	return 0, linuxerr.ENOSYS
}

func (fd *tpuFD) setContainer(ctx context.Context, t *kernel.Task, arg hostarch.Addr) (uintptr, error) {
	var vfioContainerFD int32
	if _, err := primitive.CopyInt32In(t, arg, &vfioContainerFD); err != nil {
		return 0, err
	}
	vfioContainerFile, _ := t.FDTable().Get(vfioContainerFD)
	if vfioContainerFile == nil {
		return 0, linuxerr.EBADF
	}
	defer vfioContainerFile.DecRef(ctx)
	vfioContainer, ok := vfioContainerFile.Impl().(*vfioFD)
	if !ok {
		return 0, linuxerr.EINVAL
	}
	return IOCTLInvokePtrArg[uint32](fd.hostFD, linux.VFIO_GROUP_SET_CONTAINER, &vfioContainer.hostFD)
}

// It will be the caller's responsibility to call the returned cleanup function.
func (fd *tpuFD) getPciDeviceFd(t *kernel.Task, arg hostarch.Addr) (uintptr, func(), error) {
	pciAddress, err := t.CopyInString(arg, hostarch.PageSize)
	if err != nil {
		return 0, func() {}, err
	}
	// Build a NUL-terminated slice of bytes containing the PCI address.
	pciAddressBytes, err := unix.ByteSliceFromString(pciAddress)
	if err != nil {
		return 0, func() {}, err
	}
	// Pass the address of the PCI address' first byte which can be
	// recognized by the IOCTL syscall.
	hostFD, err := IOCTLInvokePtrArg[uint32](fd.hostFD, linux.VFIO_GROUP_GET_DEVICE_FD, &pciAddressBytes[0])
	if err != nil {
		return 0, func() {}, err
	}
	pciDevFD := &pciDeviceFD{
		hostFD: int32(hostFD),
	}
	cleanup := func() {
		unix.Close(int(hostFD))
	}
	// See drivers/vfio/group.c:vfio_device_open_file(), the PCI device
	// is accessed for both reads and writes.
	vd := t.Kernel().VFS().NewAnonVirtualDentry("[vfio-device]")
	if err := pciDevFD.vfsfd.Init(pciDevFD, linux.O_RDWR, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return 0, cleanup, err
	}
	if err := fdnotifier.AddFD(int32(hostFD), &fd.queue); err != nil {
		return 0, cleanup, err
	}
	newFD, err := t.NewFDFrom(0, &pciDevFD.vfsfd, kernel.FDFlags{})
	if err != nil {
		return 0, cleanup, err
	}
	// Initialize a mapping that is backed by a host FD.
	pciDevFD.memmapFile.fd = pciDevFD
	return uintptr(newFD), func() {}, nil
}

// pciDeviceFD implements vfs.FileDescriptionImpl for TPU's PCI device.
type pciDeviceFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	hostFD     int32
	queue      waiter.Queue
	memmapFile pciDeviceFdMemmapFile
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *pciDeviceFD) Release(context.Context) {
	fdnotifier.RemoveFD(fd.hostFD)
	fd.queue.Notify(waiter.EventHUp)
	unix.Close(int(fd.hostFD))
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *pciDeviceFD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		fd.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *pciDeviceFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *pciDeviceFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(fd.hostFD, mask)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *pciDeviceFD) Epollable() bool {
	return true
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *pciDeviceFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		panic("Ioctl should be called from a task context")
	}
	switch cmd {
	// TODO(b/299303493): consider making VFIO's GET_INFO commands more generic.
	case linux.VFIO_DEVICE_GET_INFO:
		return fd.vfioDeviceInfo(ctx, t, args[2].Pointer())
	case linux.VFIO_DEVICE_GET_REGION_INFO:
		return fd.vfioRegionInfo(ctx, t, args[2].Pointer())
	case linux.VFIO_DEVICE_GET_IRQ_INFO:
		return fd.vfioIrqInfo(ctx, t, args[2].Pointer())
	case linux.VFIO_DEVICE_SET_IRQS:
		return fd.vfioSetIrqs(ctx, t, args[2].Pointer())
	case linux.VFIO_DEVICE_RESET:
		// VFIO_DEVICE_RESET is just a simple IOCTL command that carries no data.
		return IOCTLInvoke[uint32, uintptr](fd.hostFD, linux.VFIO_DEVICE_RESET, 0)
	}
	return 0, linuxerr.ENOSYS
}

// Retrieve the host TPU device's region information, which could be used by
// vfio driver to setup mappings.
func (fd *pciDeviceFD) vfioRegionInfo(ctx context.Context, t *kernel.Task, arg hostarch.Addr) (uintptr, error) {
	var regionInfo linux.VFIORegionInfo
	if _, err := regionInfo.CopyIn(t, arg); err != nil {
		return 0, err
	}
	if regionInfo.Argsz == 0 {
		return 0, linuxerr.EINVAL
	}
	ret, err := IOCTLInvokePtrArg[uint32](fd.hostFD, linux.VFIO_DEVICE_GET_REGION_INFO, &regionInfo)
	if err != nil {
		return 0, err
	}
	if _, err := regionInfo.CopyOut(t, arg); err != nil {
		return 0, err
	}
	return ret, nil
}

// Retrieve the host TPU device's information.
func (fd *pciDeviceFD) vfioDeviceInfo(ctx context.Context, t *kernel.Task, arg hostarch.Addr) (uintptr, error) {
	var deviceInfo linux.VFIODeviceInfo
	if _, err := deviceInfo.CopyIn(t, arg); err != nil {
		return 0, err
	}
	// Callers must set VFIODeviceInfo.Argsz.
	if deviceInfo.Argsz == 0 {
		return 0, linuxerr.EINVAL
	}
	if deviceInfo.Flags&^vfioDeviceInfoFlags != 0 {
		return 0, linuxerr.EINVAL
	}
	ret, err := IOCTLInvokePtrArg[uint32](fd.hostFD, linux.VFIO_DEVICE_GET_INFO, &deviceInfo)
	if err != nil {
		return 0, err
	}
	// gVisor is not supposed to change any device information that is
	// returned from the host since gVisor doesn't own the device.
	// Passing the device info back to the caller will be just fine.
	if _, err := deviceInfo.CopyOut(t, arg); err != nil {
		return 0, err
	}
	return ret, nil
}

// Retrieve the device's interrupt information.
func (fd *pciDeviceFD) vfioIrqInfo(ctx context.Context, t *kernel.Task, arg hostarch.Addr) (uintptr, error) {
	var irqInfo linux.VFIOIrqInfo
	if _, err := irqInfo.CopyIn(t, arg); err != nil {
		return 0, err
	}
	// Callers must set the payload's size.
	if irqInfo.Argsz == 0 {
		return 0, linuxerr.EINVAL
	}
	ret, err := IOCTLInvokePtrArg[uint32](fd.hostFD, linux.VFIO_DEVICE_GET_IRQ_INFO, &irqInfo)
	if err != nil {
		return 0, err
	}
	if _, err := irqInfo.CopyOut(t, arg); err != nil {
		return 0, err
	}
	return ret, nil
}

func (fd *pciDeviceFD) vfioSetIrqs(ctx context.Context, t *kernel.Task, arg hostarch.Addr) (uintptr, error) {
	var irqSet linux.VFIOIrqSet
	if _, err := irqSet.CopyIn(t, arg); err != nil {
		return 0, err
	}
	// Callers must set the payload's size.
	if irqSet.Argsz == 0 {
		return 0, linuxerr.EINVAL
	}
	// Invalidate unknown flags.
	if irqSet.Flags&^vfioIrqSetFlags != 0 {
		return 0, linuxerr.EINVAL
	}
	// See drivers/vfio/vfio_main.c:vfio_set_irqs_validate_and_prepare,
	// VFIO uses the data type at the request's flags to determine
	// the memory layout of data field.
	//
	// The struct vfio_irq_set includes a flexible array member, it
	// allocates an array for a continuous trunk of memory to back
	// a vfio_irq_set object. In order to mirror that behavior, gVisor
	// would allocate a slice to store the underlying bytes
	// and pass that through to its host.
	switch irqSet.Flags & linux.VFIO_IRQ_SET_DATA_TYPE_MASK {
	// VFIO_IRQ_SET_DATA_NONE indicates there is no data field for
	// the IOCTL command.
	// It works with VFIO_IRQ_SET_ACTION_MASK, VFIO_IRQ_SET_ACTION_UNMASK,
	// or VFIO_IRQ_SET_ACTION_TRIGGER to mask an interrupt, unmask an
	// interrupt,  and trigger an interrupt unconditionally.
	case linux.VFIO_IRQ_SET_DATA_NONE:
		// When there is no data, passing through the given payload
		// works just fine.
		return IOCTLInvokePtrArg[uint32](fd.hostFD, linux.VFIO_DEVICE_SET_IRQS, &irqSet)
	// VFIO_IRQ_SET_DATA_BOOL indicates that the data field is an array of uint8.
	// The action will be performed if the corresponding boolean is true.
	case linux.VFIO_IRQ_SET_DATA_BOOL:
		payloadSize := uint32(irqSet.Size()) + irqSet.Count
		payload := make([]uint8, payloadSize)
		if _, err := primitive.CopyUint8SliceIn(t, arg, payload); err != nil {
			return 0, err
		}
		return IOCTLInvokePtrArg[uint32](fd.hostFD, linux.VFIO_DEVICE_SET_IRQS, &payload[0])
	// VFIO_IRQ_SET_DATA_EVENTFD indicates that the data field is an array
	// of int32 (or event file descriptors). These descriptors will be
	// signalled when an action in the flags happens.
	case linux.VFIO_IRQ_SET_DATA_EVENTFD:
		payloadSize := uint32(irqSet.Size())/4 + irqSet.Count
		payload := make([]int32, payloadSize)
		if _, err := primitive.CopyInt32SliceIn(t, arg, payload); err != nil {
			return 0, err
		}
		// Transform the input FDs to host FDs.
		for i := 0; i < int(irqSet.Count); i++ {
			index := len(payload) - 1 - i
			fd := payload[index]
			// Skip non-event FD.
			if fd == disableInterrupt {
				continue
			}
			eventFileGeneric, _ := t.FDTable().Get(fd)
			if eventFileGeneric == nil {
				return 0, linuxerr.EBADF
			}
			defer eventFileGeneric.DecRef(ctx)
			eventFile, ok := eventFileGeneric.Impl().(*eventfd.EventFileDescription)
			if !ok {
				return 0, linuxerr.EINVAL
			}
			eventfd, err := eventFile.HostFD()
			if err != nil {
				return 0, err
			}
			payload[index] = int32(eventfd)
		}
		return IOCTLInvokePtrArg[uint32](fd.hostFD, linux.VFIO_DEVICE_SET_IRQS, &payload[0])
	}
	// No data type is specified or multiple data types are specified.
	return 0, linuxerr.EINVAL
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *pciDeviceFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	buf := make([]byte, dst.NumBytes())
	_, err := unix.Pread(int(fd.hostFD), buf, offset)
	if err != nil {
		return 0, err
	}
	n, err := dst.CopyOut(ctx, buf)
	return int64(n), err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *pciDeviceFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	buf := make([]byte, src.NumBytes())
	_, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}
	n, err := unix.Pwrite(int(fd.hostFD), buf, offset)
	return int64(n), err
}

// DevAddrSet tracks device address ranges that have been mapped.
type devAddrSetFuncs struct{}

func (devAddrSetFuncs) MinKey() uint64 {
	return 0
}

func (devAddrSetFuncs) MaxKey() uint64 {
	return ^uint64(0)
}

func (devAddrSetFuncs) ClearValue(val *mm.PinnedRange) {
	*val = mm.PinnedRange{}
}

func (devAddrSetFuncs) Merge(r1 DevAddrRange, v1 mm.PinnedRange, r2 DevAddrRange, v2 mm.PinnedRange) (mm.PinnedRange, bool) {
	// Do we have the same backing file?
	if v1.File != v2.File {
		return mm.PinnedRange{}, false
	}

	// Do we have contiguous offsets in the backing file?
	if v1.Offset+uint64(v1.Source.Length()) != v2.Offset {
		return mm.PinnedRange{}, false
	}

	// Are the virtual addresses contiguous?
	//
	// This check isn't strictly needed because 'mm.PinnedRange.Source'
	// is only used to track the size of the pinned region (this is
	// because the virtual address range can be unmapped or remapped
	// elsewhere). Regardless we require this for simplicity.
	if v1.Source.End != v2.Source.Start {
		return mm.PinnedRange{}, false
	}

	// Extend v1 to account for the adjacent PinnedRange.
	v1.Source.End = v2.Source.End
	return v1, true
}

func (devAddrSetFuncs) Split(r DevAddrRange, val mm.PinnedRange, split uint64) (mm.PinnedRange, mm.PinnedRange) {
	n := split - r.Start

	left := val
	left.Source.End = left.Source.Start + hostarch.Addr(n)

	right := val
	right.Source.Start += hostarch.Addr(n)
	right.Offset += n

	return left, right
}
