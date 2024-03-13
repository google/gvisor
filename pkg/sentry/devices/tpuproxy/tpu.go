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
	return ioctlInvokePtrArg(fd.hostFD, linux.VFIO_GROUP_SET_CONTAINER, &vfioContainer.hostFd)
}
