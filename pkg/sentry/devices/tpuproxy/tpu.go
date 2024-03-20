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
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	// vfioDeviceInfoFlags contains all available flags for
	// IOCTL command VFIO_DEVICE_GET_INFO.
	vfioDeviceInfoFlags uint32 = linux.VFIO_DEVICE_FLAGS_RESET | linux.VFIO_DEVICE_FLAGS_PCI |
		linux.VFIO_DEVICE_FLAGS_PLATFORM | linux.VFIO_DEVICE_FLAGS_AMBA |
		linux.VFIO_DEVICE_FLAGS_CCW | linux.VFIO_DEVICE_FLAGS_AP | linux.VFIO_DEVICE_FLAGS_FSL_MC |
		linux.VFIO_DEVICE_FLAGS_CAPS | linux.VFIO_DEVICE_FLAGS_CDX
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
	var vfioContainerFd int32
	if _, err := primitive.CopyInt32In(t, arg, &vfioContainerFd); err != nil {
		return 0, err
	}
	vfioContainerFile, _ := t.FDTable().Get(vfioContainerFd)
	if vfioContainerFile == nil {
		return 0, linuxerr.EBADF
	}
	defer vfioContainerFile.DecRef(ctx)
	vfioContainer, ok := vfioContainerFile.Impl().(*vfioFd)
	if !ok {
		return 0, linuxerr.EINVAL
	}
	return IOCTLInvokePtrArg[uint32](fd.hostFD, linux.VFIO_GROUP_SET_CONTAINER, &vfioContainer.hostFd)
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
	memmapFile tpuFDMemmapFile
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
	case linux.VFIO_DEVICE_GET_INFO:
		return fd.vfioDeviceInfo(ctx, t, args[2].Pointer())
	}
	return 0, linuxerr.ENOSYS
}

func (fd *pciDeviceFD) vfioDeviceInfo(ctx context.Context, t *kernel.Task, arg hostarch.Addr) (uintptr, error) {
	var deviceInfo linux.VFIODeviceInfo
	if _, err := deviceInfo.CopyIn(t, arg); err != nil {
		return 0, err
	}
	// Callers must set VFIODevice.Argsz.
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
