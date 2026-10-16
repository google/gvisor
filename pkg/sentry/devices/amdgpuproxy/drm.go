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

package amdgpuproxy

import (
	"gvisor.dev/gvisor/pkg/abi/amdgpu"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// maxDRMBuffer bounds the nested buffers of DRM queries.
const maxDRMBuffer = 4096

func (fd *deviceFD) drmIoctl(t *kernel.Task, cmd uint32, addr hostarch.Addr) error {
	switch cmd {
	case amdgpu.DRM_IOCTL_VERSION:
		return fd.drmVersion(t, addr)
	case amdgpu.DRM_IOCTL_AMDGPU_INFO:
		return fd.drmInfo(t, addr)
	default:
		return linuxerr.ENOTTY
	}
}

func (fd *deviceFD) drmVersion(t *kernel.Task, addr hostarch.Addr) error {
	var v amdgpu.DRMVersion
	if _, err := v.CopyIn(t, addr); err != nil {
		return err
	}
	fields := []struct{ ptr, length *uint64 }{{&v.Name, &v.NameLen}, {&v.Date, &v.DateLen}, {&v.Desc, &v.DescLen}}
	var ptrs [3]uint64
	var bufs [3][]byte
	for i, f := range fields {
		if *f.length > maxDRMBuffer {
			return linuxerr.EINVAL
		}
		// drm_copy_field only reports a field's length to a NULL buffer.
		if ptrs[i] = *f.ptr; ptrs[i] != 0 {
			bufs[i] = make([]byte, *f.length)
		}
		*f.ptr = hostBufferPointer(bufs[i])
	}
	err := fd.call(amdgpu.DRM_IOCTL_VERSION, &v, bufs[0], bufs[1], bufs[2])
	for i, f := range fields {
		*f.ptr = ptrs[i]
		if err == nil && len(bufs[i]) != 0 {
			if _, err = t.CopyOutBytes(hostarch.Addr(ptrs[i]), bufs[i][:min(uint64(len(bufs[i])), *f.length)]); err != nil {
				return err
			}
		}
	}
	return copyOut(t, amdgpu.DRM_IOCTL_VERSION, addr, &v, err)
}

func (fd *deviceFD) drmInfo(t *kernel.Task, addr hostarch.Addr) error {
	var v amdgpu.DRMAMDGPUInfo
	if _, err := v.CopyIn(t, addr); err != nil {
		return err
	}
	if v.ReturnSize > maxDRMBuffer {
		return linuxerr.EINVAL
	}
	// amdgpu_info_ioctl writes min(return_size, sizeof(result)) bytes without
	// reporting how many, so start from the application's buffer contents.
	out := make([]byte, v.ReturnSize)
	ptr := hostarch.Addr(v.ReturnPointer)
	if _, err := t.CopyInBytes(ptr, out); err != nil {
		return err
	}
	v.ReturnPointer = hostBufferPointer(out)
	if err := fd.call(amdgpu.DRM_IOCTL_AMDGPU_INFO, &v, out); err != nil {
		return err
	}
	_, err := t.CopyOutBytes(ptr, out)
	return err
}
