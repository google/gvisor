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
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
)

func uvmIoctlInvoke[Params any](ui *uvmIoctlState, ioctlParams *Params) (uintptr, error) {
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(ui.fd.hostFD), uintptr(ui.cmd), uintptr(unsafe.Pointer(ioctlParams)))
	if errno != 0 {
		return n, errno
	}
	return n, nil
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
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(mf.fd.hostFD), nvgpu.UVM_TOOLS_READ_PROCESS_MEMORY, uintptr(unsafe.Pointer(&params)))
	if errno != 0 {
		return 0, errno
	}
	if params.RMStatus != nvgpu.NV_OK {
		log.Warningf("nvproxy: UVM_TOOLS_READ_PROCESS_MEMORY(targetVa=%#x, len=%d) returned status %d", off, len(dst), params.RMStatus)
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
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(mf.fd.hostFD), nvgpu.UVM_TOOLS_WRITE_PROCESS_MEMORY, uintptr(unsafe.Pointer(&params)))
	if errno != 0 {
		return 0, errno
	}
	if params.RMStatus != nvgpu.NV_OK {
		log.Warningf("nvproxy: UVM_TOOLS_WRITE_PROCESS_MEMORY(targetVa=%#x, len=%d) returned status %d", off, len(src), params.RMStatus)
		return params.BytesWritten, linuxerr.EINVAL
	}
	if params.BytesWritten != uint64(len(src)) {
		log.Warningf("nvproxy: UVM_TOOLS_WRITE_PROCESS_MEMORY(targetVa=%#x, len=%d) returned %d bytes", off, len(src), params.BytesWritten)
		return params.BytesWritten, linuxerr.EINVAL
	}
	return params.BytesWritten, nil
}
