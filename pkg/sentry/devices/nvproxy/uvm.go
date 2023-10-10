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

package nvproxy

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// uvmDevice implements vfs.Device for /dev/nvidia-uvm.
//
// +stateify savable
type uvmDevice struct {
	nvp *nvproxy
}

// Open implements vfs.Device.Open.
func (dev *uvmDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	hostFD, err := unix.Openat(-1, "/dev/nvidia-uvm", int((opts.Flags&unix.O_ACCMODE)|unix.O_NOFOLLOW), 0)
	if err != nil {
		ctx.Warningf("nvproxy: failed to open host /dev/nvidia-uvm: %v", err)
		return nil, err
	}
	fd := &uvmFD{
		nvp:    dev.nvp,
		hostFD: int32(hostFD),
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	if err := fdnotifier.AddFD(int32(hostFD), &fd.queue); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	fd.memmapFile.fd = fd
	return &fd.vfsfd, nil
}

// uvmFD implements vfs.FileDescriptionImpl for /dev/nvidia-uvm.
//
// uvmFD is not savable; we do not implement save/restore of host GPU state.
type uvmFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	nvp        *nvproxy
	hostFD     int32
	memmapFile uvmFDMemmapFile

	queue waiter.Queue
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *uvmFD) Release(context.Context) {
	fdnotifier.RemoveFD(fd.hostFD)
	fd.queue.Notify(waiter.EventHUp)
	unix.Close(int(fd.hostFD))
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *uvmFD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		fd.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *uvmFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *uvmFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(fd.hostFD, mask)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *uvmFD) Epollable() bool {
	return true
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *uvmFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()
	argPtr := args[2].Pointer()

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		panic("Ioctl should be called from a task context")
	}

	if log.IsLogging(log.Debug) {
		ctx.Debugf("nvproxy: frontend ioctl %#08x", cmd)
	}

	ui := uvmIoctlState{
		fd:              fd,
		ctx:             ctx,
		t:               t,
		cmd:             cmd,
		ioctlParamsAddr: argPtr,
	}
	handler := fd.nvp.abi.uvmIoctl[cmd]
	if handler == nil {
		ctx.Warningf("nvproxy: unknown uvm ioctl %d", cmd)
		return 0, linuxerr.EINVAL
	}
	return handler(&ui)
}

// uvmIoctlState holds the state of a call to uvmFD.Ioctl().
type uvmIoctlState struct {
	fd              *uvmFD
	ctx             context.Context
	t               *kernel.Task
	cmd             uint32
	ioctlParamsAddr hostarch.Addr
}

func uvmIoctlNoParams(ui *uvmIoctlState) (uintptr, error) {
	return uvmIoctlInvoke[byte](ui, nil)
}

func uvmIoctlSimple[Params any, PParams marshalPtr[Params]](ui *uvmIoctlState) (uintptr, error) {
	var ioctlParams Params
	if _, err := (PParams)(&ioctlParams).CopyIn(ui.t, ui.ioctlParamsAddr); err != nil {
		return 0, err
	}
	n, err := uvmIoctlInvoke(ui, &ioctlParams)
	if err != nil {
		return n, err
	}
	if _, err := (PParams)(&ioctlParams).CopyOut(ui.t, ui.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func uvmInitialize(ui *uvmIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.UVM_INITIALIZE_PARAMS
	if _, err := ioctlParams.CopyIn(ui.t, ui.ioctlParamsAddr); err != nil {
		return 0, err
	}
	sentryIoctlParams := ioctlParams
	// This is necessary to share the host UVM FD between sentry and
	// application processes.
	sentryIoctlParams.Flags = ioctlParams.Flags | nvgpu.UVM_INIT_FLAGS_MULTI_PROCESS_SHARING_MODE
	n, err := uvmIoctlInvoke(ui, &sentryIoctlParams)
	if err != nil {
		return n, err
	}
	outIoctlParams := sentryIoctlParams
	// Only expose the MULTI_PROCESS_SHARING_MODE flag if it was present in
	// ioctlParams.
	outIoctlParams.Flags &^= ^ioctlParams.Flags & nvgpu.UVM_INIT_FLAGS_MULTI_PROCESS_SHARING_MODE
	if _, err := outIoctlParams.CopyOut(ui.t, ui.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func uvmMMInitialize(ui *uvmIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.UVM_MM_INITIALIZE_PARAMS
	if _, err := ioctlParams.CopyIn(ui.t, ui.ioctlParamsAddr); err != nil {
		return 0, err
	}

	failWithStatus := func(status uint32) error {
		outIoctlParams := ioctlParams
		outIoctlParams.Status = status
		_, err := outIoctlParams.CopyOut(ui.t, ui.ioctlParamsAddr)
		return err
	}

	uvmFileGeneric, _ := ui.t.FDTable().Get(ioctlParams.UvmFD)
	if uvmFileGeneric == nil {
		return 0, failWithStatus(nvgpu.NV_ERR_INVALID_ARGUMENT)
	}
	defer uvmFileGeneric.DecRef(ui.ctx)
	uvmFile, ok := uvmFileGeneric.Impl().(*uvmFD)
	if !ok {
		return 0, failWithStatus(nvgpu.NV_ERR_INVALID_ARGUMENT)
	}

	sentryIoctlParams := ioctlParams
	sentryIoctlParams.UvmFD = uvmFile.hostFD
	n, err := uvmIoctlInvoke(ui, &sentryIoctlParams)
	if err != nil {
		return n, err
	}

	outIoctlParams := sentryIoctlParams
	outIoctlParams.UvmFD = ioctlParams.UvmFD
	if _, err := outIoctlParams.CopyOut(ui.t, ui.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

type hasRMCtrlFDPtr[T any] interface {
	*T
	marshal.Marshallable
	nvgpu.HasRMCtrlFD
}

func uvmIoctlHasRMCtrlFD[Params any, PParams hasRMCtrlFDPtr[Params]](ui *uvmIoctlState) (uintptr, error) {
	var ioctlParams Params
	if _, err := (PParams)(&ioctlParams).CopyIn(ui.t, ui.ioctlParamsAddr); err != nil {
		return 0, err
	}

	rmCtrlFD := (PParams)(&ioctlParams).GetRMCtrlFD()
	if rmCtrlFD < 0 {
		n, err := uvmIoctlInvoke(ui, &ioctlParams)
		if err != nil {
			return n, err
		}
		if _, err := (PParams)(&ioctlParams).CopyOut(ui.t, ui.ioctlParamsAddr); err != nil {
			return n, err
		}
		return n, nil
	}

	ctlFileGeneric, _ := ui.t.FDTable().Get(rmCtrlFD)
	if ctlFileGeneric == nil {
		return 0, linuxerr.EINVAL
	}
	defer ctlFileGeneric.DecRef(ui.ctx)
	ctlFile, ok := ctlFileGeneric.Impl().(*frontendFD)
	if !ok {
		return 0, linuxerr.EINVAL
	}

	sentryIoctlParams := ioctlParams
	(PParams)(&sentryIoctlParams).SetRMCtrlFD(ctlFile.hostFD)
	n, err := uvmIoctlInvoke(ui, &sentryIoctlParams)
	if err != nil {
		return n, err
	}

	outIoctlParams := sentryIoctlParams
	(PParams)(&outIoctlParams).SetRMCtrlFD(rmCtrlFD)
	if _, err := (PParams)(&outIoctlParams).CopyOut(ui.t, ui.ioctlParamsAddr); err != nil {
		return n, err
	}

	return n, nil
}
