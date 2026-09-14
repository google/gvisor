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
	"reflect"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
)

func uvmIoctlInvoke[Params any, PtrParams hasStatusPtr[Params]](ui *uvmIoctlState, ioctlParams PtrParams) (uintptr, error) {
	// UVM names GPUs by UUID. After a restore that remapped devices the
	// application still holds the UUIDs of the GPUs it had before the
	// checkpoint, so resolve them to the host's on the way in and report the
	// host's as the application's on the way out. uvmIoctlInvoke() is the
	// single choke point every UVM ioctl passes through, so no handler can be
	// missed.
	nvp := ui.fd.dev.nvp
	scope := scopeFor(ui.t)
	var (
		uuidOffs []int
		buf      []byte
	)
	if len(nvp.hostToGuestUUID) != 0 && scope.Restored {
		typ := reflect.TypeOf(ioctlParams).Elem()
		uuidOffs = uuidOffsetsFor(typ)
		if len(uuidOffs) != 0 {
			buf = unsafe.Slice((*byte)(unsafe.Pointer(ioctlParams)), int(typ.Size()))
			if in := translateUUIDsInBuf(buf, uuidOffs, nvp.guestToHostUUID); len(in) != 0 && log.IsLogging(log.Debug) {
				for _, pair := range in {
					ui.ctx.Debugf("nvproxy: uvm %s: translated UUID %s (guest) to %s (host) [%v]", uvmIoctlName(ui.cmd), pair[0], pair[1], scope)
				}
			}
		}
	}

	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(ui.fd.hostFD), uintptr(ui.cmd), uintptr(unsafe.Pointer(ioctlParams)))

	if buf != nil {
		// Both restores the inbound UUIDs the application passed and
		// translates any the driver returned, since the two maps are inverses.
		translateUUIDsInBuf(buf, uuidOffs, nvp.hostToGuestUUID)
	}
	if errno != 0 {
		return n, errno
	}
	logUVMIoctl(ui, ioctlParams, scope)
	if status := ioctlParams.GetStatus(); status != nvgpu.NV_OK {
		logUVMIoctlStatus(ui, status)
	}
	return n, nil
}

// logUVMIoctl writes the Debug line for the UVM ioctls by which an application
// builds its view of which GPUs exist and which may reach which memory. Those
// are the ones a stale UUID breaks, and the UUIDs shown are the guest's, since
// this runs after the outbound translation.
func logUVMIoctl[Params any, PtrParams hasStatusPtr[Params]](ui *uvmIoctlState, ioctlParams PtrParams, scope translationScope) {
	if !log.IsLogging(log.Debug) {
		return
	}
	if _, ok := uvmIoctlLogsUUIDs[ui.cmd]; !ok {
		return
	}
	typ := reflect.TypeOf(ioctlParams).Elem()
	offs := uuidOffsetsFor(typ)
	if len(offs) == 0 {
		return
	}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(ioctlParams)), int(typ.Size()))
	status := ioctlParams.GetStatus()
	switch p := any(ioctlParams).(type) {
	case *nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS:
		ui.ctx.Debugf("nvproxy: uvm %s: gpuAttributesCount=%d hClient=%#x hMemory=%#x base=%#x length=%#x uuids=%s rmStatus=%#x (%s) [%v]",
			uvmIoctlName(ui.cmd), p.GPUAttributesCount, p.HClient, p.HMemory, p.Base, p.Length, describeUUIDsInBuf(buf, offs), status, statusName(status), scope)
	case *nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550:
		ui.ctx.Debugf("nvproxy: uvm %s: gpuAttributesCount=%d hClient=%#x hMemory=%#x base=%#x length=%#x uuids=%s rmStatus=%#x (%s) [%v]",
			uvmIoctlName(ui.cmd), p.GPUAttributesCount, p.HClient, p.HMemory, p.Base, p.Length, describeUUIDsInBuf(buf, offs), status, statusName(status), scope)
	default:
		ui.ctx.Debugf("nvproxy: uvm %s: uuids=%s rmStatus=%#x (%s) [%v]",
			uvmIoctlName(ui.cmd), describeUUIDsInBuf(buf, offs), status, statusName(status), scope)
	}
}

// BufferReadAt implements memmap.File.BufferReadAt.
func (mf *uvmFDMemmapFile) BufferReadAt(off uint64, dst []byte) (uint64, error) {
	// kernel-open/nvidia-uvm/uvm.c:uvm_fops.{read,read_iter,splice_read} ==
	// NULL, so UVM data can only be read via ioctl.
	if len(dst) == 0 {
		return 0, nil
	}
	defer runtime.KeepAlive(dst)
	params := nvgpu.UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS{
		Buffer:   uint64(uintptr(unsafe.Pointer(&dst[0]))),
		Size:     uint64(len(dst)),
		TargetVA: off,
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(mf.FD()), nvgpu.UVM_TOOLS_READ_PROCESS_MEMORY, uintptr(unsafe.Pointer(&params)))
	if errno != 0 {
		return 0, errno
	}
	if status := params.GetStatus(); status != nvgpu.NV_OK {
		log.Warningf("nvproxy: UVM_TOOLS_READ_PROCESS_MEMORY(targetVa=%#x, len=%d) returned status %d", off, len(dst), status)
		return params.BytesRead, linuxerr.EINVAL
	}
	if params.BytesRead != uint64(len(dst)) {
		log.Warningf("nvproxy: UVM_TOOLS_READ_PROCESS_MEMORY(targetVa=%#x, len=%d) returned %d bytes", off, len(dst), params.BytesRead)
		return params.BytesRead, linuxerr.EINVAL
	}
	return params.BytesRead, nil
}

// BufferWriteAt implements memmap.File.BufferWriteAt.
func (mf *uvmFDMemmapFile) BufferWriteAt(off uint64, src []byte) (uint64, error) {
	// kernel-open/nvidia-uvm/uvm.c:uvm_fops.{write,write_iter,splice_write} ==
	// NULL, so UVM data can only be written via ioctl.
	if len(src) == 0 {
		return 0, nil
	}
	defer runtime.KeepAlive(src)
	params := nvgpu.UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS{
		Buffer:   uint64(uintptr(unsafe.Pointer(&src[0]))),
		Size:     uint64(len(src)),
		TargetVA: off,
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(mf.FD()), nvgpu.UVM_TOOLS_WRITE_PROCESS_MEMORY, uintptr(unsafe.Pointer(&params)))
	if errno != 0 {
		return 0, errno
	}
	if status := params.GetStatus(); status != nvgpu.NV_OK {
		log.Warningf("nvproxy: UVM_TOOLS_WRITE_PROCESS_MEMORY(targetVa=%#x, len=%d) returned status %d", off, len(src), status)
		return params.BytesWritten, linuxerr.EINVAL
	}
	if params.BytesWritten != uint64(len(src)) {
		log.Warningf("nvproxy: UVM_TOOLS_WRITE_PROCESS_MEMORY(targetVa=%#x, len=%d) returned %d bytes", off, len(src), params.BytesWritten)
		return params.BytesWritten, linuxerr.EINVAL
	}
	return params.BytesWritten, nil
}
