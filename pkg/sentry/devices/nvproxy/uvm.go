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
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
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
	if err := fdnotifier.AddFD(fd.hostFD, &fd.queue); err != nil {
		unix.Close(int(fd.hostFD))
		return nil, err
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		SpecialFile:       true,
	}); err != nil {
		fdnotifier.RemoveFD(fd.hostFD)
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
	// Application-bound UVM cannot be restored against a different host mm.
	applicationMMInitialized atomicbitops.Bool

	queue waiter.Queue
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
	if runtime.GOARCH == "arm64" {
		if initializer, ok := ui.t.MemoryManager().AddressSpace().(platform.UVMAddressSpace); ok {
			// Coherent Grace GPUs require ATS. Bind UVM to the application's
			// host mm, rather than disabling mm tracking or binding the Sentry.
			// Mark the attempt before invoking the application: its returned
			// status is untrusted and must not decide checkpoint eligibility.
			ui.fd.applicationMMInitialized.Store(true)
			status, err := initializer.UVMInitialize(ui.fd.hostFD, ioctlParams.Flags)
			if err != nil {
				return 0, err
			}
			ioctlParams.RMStatus = status
			_, err = ioctlParams.CopyOut(ui.t, ui.ioctlParamsAddr)
			return 0, err
		}
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

func uvmPopulatePageable(ui *uvmIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.UVM_POPULATE_PAGEABLE_PARAMS
	if _, err := ioctlParams.CopyIn(ui.t, ui.ioctlParamsAddr); err != nil {
		return 0, err
	}
	initializer, ok := ui.t.MemoryManager().AddressSpace().(platform.UVMAddressSpace)
	if runtime.GOARCH != "arm64" || !ok {
		return 0, linuxerr.EOPNOTSUPP
	}
	// Nonzero flags are reserved for NVIDIA's built-in tests or internal use.
	if ioctlParams.Flags != 0 {
		return 0, uvmFailWithStatus(ui, &ioctlParams, nvgpu.NV_ERR_INVALID_ARGUMENT)
	}
	ar, valid := hostarch.Addr(ioctlParams.Base).ToRange(ioctlParams.Length)
	if !valid || ar.Length() == 0 || !ar.IsPageAligned() {
		return 0, uvmFailWithStatus(ui, &ioctlParams, nvgpu.NV_ERR_INVALID_ADDRESS)
	}
	// UVM can only populate VMAs already installed in the host mm. Resolve
	// gVisor's lazy mappings and software COW first, inheriting each VMA's
	// permissions just as the NVIDIA driver does on native Linux.
	mm := ui.t.MemoryManager()
	for addr := ar.Start; addr < ar.End; addr += hostarch.PageSize {
		err := mm.HandleUserFault(ui.ctx, addr, hostarch.Write, 0)
		if linuxerr.Equals(linuxerr.EPERM, err) || linuxerr.Equals(linuxerr.EACCES, err) || linuxerr.Equals(linuxerr.EFAULT, err) {
			err = mm.HandleUserFault(ui.ctx, addr, hostarch.Read, 0)
		}
		if err != nil {
			if linuxerr.Equals(linuxerr.EPERM, err) || linuxerr.Equals(linuxerr.EACCES, err) || linuxerr.Equals(linuxerr.EFAULT, err) {
				return 0, uvmFailWithStatus(ui, &ioctlParams, nvgpu.NV_ERR_INVALID_ADDRESS)
			}
			return 0, err
		}
	}
	status, err := initializer.UVMPopulatePageable(ui.fd.hostFD, ioctlParams.Base, ioctlParams.Length, ioctlParams.Flags)
	if err != nil {
		return 0, err
	}
	ioctlParams.RMStatus = status
	_, err = ioctlParams.CopyOut(ui.t, ui.ioctlParamsAddr)
	return 0, err
}

func uvmSetPreferredLocationV550(ui *uvmIoctlState) (uintptr, error) {
	as, ok := ui.t.MemoryManager().AddressSpace().(platform.UVMAddressSpace)
	if runtime.GOARCH != "arm64" || !ok {
		return uvmIoctlSimple[nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS_V550](ui)
	}
	var params nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS_V550
	if _, err := params.CopyIn(ui.t, ui.ioctlParamsAddr); err != nil {
		return 0, err
	}
	// NVIDIA requires the calling mm to match UVM's saved mm when applying
	// preferred-location policy to ATS memory, including pinned allocations.
	status, err := as.UVMSetPreferredLocation(ui.fd.hostFD, params.RequestedBase, params.Length, params.PreferredLocation, params.PreferredCPUNumaNode)
	if err != nil {
		return 0, err
	}
	params.RMStatus = status
	_, err = params.CopyOut(ui.t, ui.ioctlParamsAddr)
	return 0, err
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
