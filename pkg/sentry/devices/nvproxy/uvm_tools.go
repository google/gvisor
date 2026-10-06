// Copyright 2026 The gVisor Authors.
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
	"math"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// uvmToolsDevice implements vfs.Device for /dev/nvidia-uvm-tools.
//
// +stateify savable
type uvmToolsDevice struct {
	nvp *nvproxy
}

// Open implements vfs.Device.Open.
func (dev *uvmToolsDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &uvmToolsFD{
		dev: dev,
	}
	var err error
	fd.hostFD, fd.containerName, err = openHostDevFile(ctx, "nvidia-uvm-tools", dev.nvp.useDevGofer, opts.Flags)
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
	return &fd.vfsfd, nil
}

// uvmToolsFD implements vfs.FileDescriptionImpl for /dev/nvidia-uvm-tools.
//
// +stateify savable
type uvmToolsFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	dev           *uvmToolsDevice
	containerName string
	hostFD        int32

	queue waiter.Queue

	// mirrors are the application buffers passed to the host event tracker.
	// The host driver keeps them pinned until hostFD is closed.
	mirrorsMu sync.Mutex  `state:"nosave"`
	mirrors   []appMirror `state:"nosave"`
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *uvmToolsFD) Release(ctx context.Context) {
	fdnotifier.RemoveFD(fd.hostFD)
	fd.queue.Notify(waiter.EventHUp)
	// Closing hostFD makes the host driver unpin its view of the mirrors.
	unix.Close(int(fd.hostFD))
	fd.mirrorsMu.Lock()
	defer fd.mirrorsMu.Unlock()
	for i := range fd.mirrors {
		fd.mirrors[i].release(ctx)
	}
	fd.mirrors = nil
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *uvmToolsFD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		fd.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *uvmToolsFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *uvmToolsFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(fd.hostFD, mask)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *uvmToolsFD) Epollable() bool {
	return true
}

// IsNvidiaDeviceFD implements NvidiaDeviceFD.IsNvidiaDeviceFD.
func (fd *uvmToolsFD) IsNvidiaDeviceFD() {}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *uvmToolsFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	return uvmIoctl(ctx, fd.dev.nvp, fd.hostFD, fd, args)
}

// uvmToolsInitEventTracker handles UVM_TOOLS_INIT_EVENT_TRACKER(_V2). The host
// driver pins the queue and control buffers from the caller's address space
// (kernel-open/nvidia-uvm/uvm_tools.c:create_event_tracker() =>
// map_user_pages()) and writes events into them asynchronously, so they must
// be mirrored into the sentry's address space and kept pinned until the
// tracker is destroyed.
//
// Events identify host processes, threads and CPUs, not the sandbox's.
func uvmToolsInitEventTracker(ui *uvmIoctlState) (uintptr, error) {
	if ui.toolsFD == nil {
		// /dev/nvidia-uvm rejects this ioctl without reading its parameters.
		var zeroParams nvgpu.UVM_TOOLS_INIT_EVENT_TRACKER_PARAMS
		return uvmIoctlInvoke(ui, &zeroParams)
	}
	var ioctlParams nvgpu.UVM_TOOLS_INIT_EVENT_TRACKER_PARAMS
	if _, err := ioctlParams.CopyIn(ui.t, ui.ioctlParamsAddr); err != nil {
		return 0, err
	}

	uvmFileGeneric, _ := ui.t.FDTable().Get(int32(ioctlParams.UvmFD))
	if uvmFileGeneric == nil {
		return 0, uvmFailWithStatus(ui, &ioctlParams, nvgpu.NV_ERR_INSUFFICIENT_PERMISSIONS)
	}
	defer uvmFileGeneric.DecRef(ui.ctx)
	uvmFile, ok := uvmFileGeneric.Impl().(*uvmFD)
	if !ok {
		return 0, uvmFailWithStatus(ui, &ioctlParams, nvgpu.NV_ERR_INSUFFICIENT_PERMISSIONS)
	}

	var mirrors []appMirror
	releaseMirrors := cleanup.Make(func() {
		for i := range mirrors {
			mirrors[i].release(ui.ctx)
		}
	})
	defer releaseMirrors.Clean()
	// Compare uvm_tools.c:map_user_pages().
	mirror := func(addr *uint64, size uint64) uint32 {
		start := hostarch.Addr(*addr)
		length, ok := hostarch.PageRoundUp(size)
		if !ok || start == 0 || !start.IsPageAligned() {
			return nvgpu.NV_ERR_INVALID_ADDRESS
		}
		ar, ok := start.ToRange(length)
		if !ok {
			return nvgpu.NV_ERR_INVALID_ADDRESS
		}
		am, m, err := mirrorAppRange(ui.ctx, ui.t, ar, hostarch.ReadWrite)
		if err != nil {
			// check_vmas() rejects unmapped and UVM-backed memory; otherwise,
			// pin_user_pages() fails with EFAULT on inaccessible memory.
			inaccessible := linuxerr.Equals(linuxerr.EFAULT, err) || linuxerr.Equals(linuxerr.EPERM, err)
			if inaccessible && ui.t.MemoryManager().VirtualMemorySizeRange(ar) == uint64(ar.Length()) {
				return nvgpu.NV_ERR_INVALID_ADDRESS
			}
			return nvgpu.NV_ERR_INVALID_ARGUMENT
		}
		mirrors = append(mirrors, am)
		*addr = uint64(m)
		return nvgpu.NV_OK
	}

	// Compare uvm_tools.c:create_event_tracker().
	hostParams := ioctlParams
	controlSize := uint64(nvgpu.UVM_TOTAL_COUNTERS * 8)
	if count := ioctlParams.QueueBufferSize; count != 0 {
		if count > math.MaxUint32 || count < 2 || count&(count-1) != 0 {
			return 0, uvmFailWithStatus(ui, &ioctlParams, nvgpu.NV_ERR_INVALID_ARGUMENT)
		}
		entrySize := uint64((*nvgpu.UvmEventEntry)(nil).SizeBytes())
		if ui.cmd == nvgpu.UVM_TOOLS_INIT_EVENT_TRACKER_V2 {
			entrySize = uint64((*nvgpu.UvmEventEntry_V2)(nil).SizeBytes())
		}
		if status := mirror(&hostParams.QueueBuffer, count*entrySize); status != nvgpu.NV_OK {
			return 0, uvmFailWithStatus(ui, &ioctlParams, status)
		}
		controlSize = uint64((*nvgpu.UvmToolsEventControlData)(nil).SizeBytes())
	} else {
		hostParams.QueueBuffer = 0
	}
	if status := mirror(&hostParams.ControlBuffer, controlSize); status != nvgpu.NV_OK {
		return 0, uvmFailWithStatus(ui, &ioctlParams, status)
	}
	hostParams.UvmFD = uint32(uvmFile.hostFD)

	n, err := uvmIoctlInvoke(ui, &hostParams)
	if err != nil {
		return n, err
	}
	if hostParams.RMStatus == nvgpu.NV_OK {
		ui.toolsFD.mirrorsMu.Lock()
		ui.toolsFD.mirrors = append(ui.toolsFD.mirrors, mirrors...)
		ui.toolsFD.mirrorsMu.Unlock()
		releaseMirrors.Release()
	}
	ioctlParams.RMStatus = hostParams.RMStatus
	if _, err := ioctlParams.CopyOut(ui.t, ui.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}
