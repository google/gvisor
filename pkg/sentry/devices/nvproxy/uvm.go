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
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
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
	fd := &uvmFD{
		dev: dev,
	}
	var err error
	fd.hostFD, fd.containerName, err = openHostDevFile(ctx, "nvidia-uvm", dev.nvp.useDevGofer, opts.Flags)
	if err != nil {
		return nil, err
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		unix.Close(int(fd.hostFD))
		return nil, err
	}
	if err := fdnotifier.AddFD(fd.hostFD, &fd.queue); err != nil {
		unix.Close(int(fd.hostFD))
		return nil, err
	}
	fd.memmapFile.SetFD(int(fd.hostFD))
	fd.memmapFile.RequireAddrEqualsFileOffset()
	return &fd.vfsfd, nil
}

// uvmFD implements vfs.FileDescriptionImpl for /dev/nvidia-uvm.
//
// +stateify savable
type uvmFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
	memmap.MappableNoTrackMappings

	dev           *uvmDevice
	containerName string
	hostFD        int32
	memmapFile    uvmFDMemmapFile

	queue waiter.Queue

	// mu protects fields below.
	mu sync.RWMutex
	// multiProcessSharing is true if the FD was initialized with
	// UVM_INIT_FLAGS_MULTI_PROCESS_SHARING_MODE.
	multiProcessSharing bool
	ownerMM             *mm.MemoryManager
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *uvmFD) Release(context.Context) {
	fdnotifier.RemoveFD(fd.hostFD)
	fd.queue.Notify(waiter.EventHUp)
	fd.memmapFile.MappableRelease()
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

	if ctx.IsLogging(log.Debug) {
		ctx.Debugf("nvproxy: uvm ioctl %d = %#x", cmd, cmd)
	}

	ui := uvmIoctlState{
		fd:              fd,
		ctx:             ctx,
		t:               t,
		cmd:             cmd,
		ioctlParamsAddr: argPtr,
	}

	if cmd != nvgpu.UVM_INITIALIZE {
		ui.fd.mu.RLock()
		if !ui.fd.multiProcessSharing && ui.fd.ownerMM != taskMM(ui.t) {
			ui.fd.mu.RUnlock()
			ctx.Warningf("nvproxy: uvm ioctl %d = %#x called from wrong process", cmd, cmd)
			return 0, linuxerr.EINVAL
		}
		ui.fd.mu.RUnlock()
	}

	result, err := fd.dev.nvp.abi.uvmIoctl[cmd].handle(&ui)
	if err != nil {
		if handleErr, ok := err.(*errHandler); ok {
			ctx.Warningf("nvproxy: %v for uvm ioctl %d = %#x", handleErr, cmd, cmd)
			return 0, linuxerr.EINVAL
		}
	}
	return result, err
}

// IsNvidiaDeviceFD implements NvidiaDeviceFD.IsNvidiaDeviceFD.
func (fd *uvmFD) IsNvidiaDeviceFD() {}

// uvmIoctlState holds the state of a call to uvmFD.Ioctl().
type uvmIoctlState struct {
	fd              *uvmFD
	ctx             context.Context
	t               *kernel.Task
	cmd             uint32
	ioctlParamsAddr hostarch.Addr
}

func uvmIoctlNoParams(ui *uvmIoctlState) (uintptr, error) {
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(ui.fd.hostFD), uintptr(ui.cmd), 0 /* params */)
	if errno != 0 {
		return n, errno
	}
	return n, nil
}

func uvmIoctlSimple[Params any, PtrParams hasStatusPtr[Params]](ui *uvmIoctlState) (uintptr, error) {
	var ioctlParamsValue Params
	ioctlParams := PtrParams(&ioctlParamsValue)
	if _, err := ioctlParams.CopyIn(ui.t, ui.ioctlParamsAddr); err != nil {
		return 0, err
	}
	n, err := uvmIoctlInvoke(ui, ioctlParams)
	if err != nil {
		return n, err
	}
	if _, err := ioctlParams.CopyOut(ui.t, ui.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func uvmInitialize(ui *uvmIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.UVM_INITIALIZE_PARAMS
	if _, err := ioctlParams.CopyIn(ui.t, ui.ioctlParamsAddr); err != nil {
		return 0, err
	}
	origFlags := ioctlParams.Flags
	// This is necessary to share the host UVM FD between sentry and
	// application processes.
	ioctlParams.Flags = ioctlParams.Flags | nvgpu.UVM_INIT_FLAGS_MULTI_PROCESS_SHARING_MODE
	n, err := uvmIoctlInvoke(ui, &ioctlParams)
	// Only expose the MULTI_PROCESS_SHARING_MODE flag if it was already present.
	ioctlParams.Flags &^= ^origFlags & nvgpu.UVM_INIT_FLAGS_MULTI_PROCESS_SHARING_MODE
	if err != nil {
		return n, err
	}

	if ioctlParams.GetStatus() == nvgpu.NV_OK {
		ui.fd.mu.Lock()
		ui.fd.ownerMM = taskMM(ui.t)
		ui.fd.multiProcessSharing = (origFlags & nvgpu.UVM_INIT_FLAGS_MULTI_PROCESS_SHARING_MODE) != 0
		ui.fd.mu.Unlock()
	}

	if _, err := ioctlParams.CopyOut(ui.t, ui.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func uvmMMInitialize(ui *uvmIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.UVM_MM_INITIALIZE_PARAMS
	if _, err := ioctlParams.CopyIn(ui.t, ui.ioctlParamsAddr); err != nil {
		return 0, err
	}

	uvmFileGeneric, _ := ui.t.FDTable().Get(ioctlParams.UvmFD)
	if uvmFileGeneric == nil {
		return 0, uvmFailWithStatus(ui, &ioctlParams, nvgpu.NV_ERR_INVALID_ARGUMENT)
	}
	defer uvmFileGeneric.DecRef(ui.ctx)
	uvmFile, ok := uvmFileGeneric.Impl().(*uvmFD)
	if !ok {
		return 0, uvmFailWithStatus(ui, &ioctlParams, nvgpu.NV_ERR_INVALID_ARGUMENT)
	}

	origFD := ioctlParams.UvmFD
	ioctlParams.UvmFD = uvmFile.hostFD
	n, err := uvmIoctlInvoke(ui, &ioctlParams)
	ioctlParams.UvmFD = origFD
	if err != nil {
		return n, err
	}
	if _, err := ioctlParams.CopyOut(ui.t, ui.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func uvmIoctlHasFrontendFD[Params any, PtrParams hasFrontendFDAndStatusPtr[Params]](ui *uvmIoctlState) (uintptr, error) {
	var ioctlParamsValue Params
	ioctlParams := PtrParams(&ioctlParamsValue)
	if _, err := ioctlParams.CopyIn(ui.t, ui.ioctlParamsAddr); err != nil {
		return 0, err
	}

	origFD := ioctlParams.GetFrontendFD()
	if origFD < 0 {
		n, err := uvmIoctlInvoke(ui, ioctlParams)
		if err != nil {
			return n, err
		}
		if _, err := ioctlParams.CopyOut(ui.t, ui.ioctlParamsAddr); err != nil {
			return n, err
		}
		return n, nil
	}

	ctlFileGeneric, _ := ui.t.FDTable().Get(origFD)
	if ctlFileGeneric == nil {
		return 0, linuxerr.EINVAL
	}
	defer ctlFileGeneric.DecRef(ui.ctx)
	ctlFile, ok := ctlFileGeneric.Impl().(*frontendFD)
	if !ok {
		return 0, linuxerr.EINVAL
	}

	ioctlParams.SetFrontendFD(ctlFile.hostFD)
	n, err := uvmIoctlInvoke(ui, ioctlParams)
	ioctlParams.SetFrontendFD(origFD)
	if err != nil {
		return n, err
	}
	if _, err := ioctlParams.CopyOut(ui.t, ui.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func uvmFailWithStatus[Params any, PtrParams hasStatusPtr[Params]](ui *uvmIoctlState, ioctlParams PtrParams, status uint32) error {
	return failWithStatus(ui.ctx, ui.t, ui.ioctlParamsAddr, ioctlParams, status)
}

// taskMM gets the kernel task's MemoryManager. No additional reference is taken on
// mm here. This is safe because MemoryManager.destroy is required to leave the
// MemoryManager in a state where it's still usable as a DynamicBytesSource.
func taskMM(task *kernel.Task) *mm.MemoryManager {
	var tmm *mm.MemoryManager
	task.WithMuLocked(func(t *kernel.Task) {
		if mm := t.MemoryManager(); mm != nil {
			tmm = mm
		}
	})
	return tmm
}
