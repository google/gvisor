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

// Package nvproxy implements proxying for the Nvidia GPU Linux kernel driver:
// https://github.com/NVIDIA/open-gpu-kernel-modules.
//
// Supported Nvidia GPUs: T4, L4, A100, A10G and H100.
package nvproxy

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Register registers all devices implemented by this package in vfsObj.
func Register(vfsObj *vfs.VirtualFilesystem, uvmDevMajor uint32) error {
	// The kernel driver's interface is unstable, so only allow versions of the
	// driver that are known to be supported.
	versionStr, err := hostDriverVersion()
	if err != nil {
		return fmt.Errorf("failed to get Nvidia driver version: %w", err)
	}
	log.Debugf("NVIDIA driver version: %s", versionStr)
	version, err := DriverVersionFrom(versionStr)
	if err != nil {
		return fmt.Errorf("failed to parse Nvidia driver version %s: %w", versionStr, err)
	}
	abiCons, ok := abis[version]
	if !ok {
		return fmt.Errorf("unsupported Nvidia driver version: %s", versionStr)
	}
	nvp := &nvproxy{
		objsLive: make(map[nvgpu.Handle]*object),
		abi:      abiCons.cons(),
	}
	for minor := uint32(0); minor <= nvgpu.NV_CONTROL_DEVICE_MINOR; minor++ {
		if err := vfsObj.RegisterDevice(vfs.CharDevice, nvgpu.NV_MAJOR_DEVICE_NUMBER, minor, &frontendDevice{
			nvp:   nvp,
			minor: minor,
		}, &vfs.RegisterDeviceOptions{
			GroupName: "nvidia-frontend",
		}); err != nil {
			return err
		}
	}
	if err := vfsObj.RegisterDevice(vfs.CharDevice, uvmDevMajor, nvgpu.NVIDIA_UVM_PRIMARY_MINOR_NUMBER, &uvmDevice{
		nvp: nvp,
	}, &vfs.RegisterDeviceOptions{
		GroupName: "nvidia-uvm",
	}); err != nil {
		return err
	}
	return nil
}

// +stateify savable
type nvproxy struct {
	objsMu   objsMutex `state:"nosave"`
	objsLive map[nvgpu.Handle]*object
	abi      *driverABI
}

// object tracks an object allocated through the driver.
//
// +stateify savable
type object struct {
	impl objectImpl
}

func (o *object) init(impl objectImpl) {
	o.impl = impl
}

// Release is called after the represented object is freed.
func (o *object) Release(ctx context.Context) {
	o.impl.Release(ctx)
}

type objectImpl interface {
	Release(ctx context.Context)
}

// osDescMem is an objectImpl tracking an OS descriptor.
//
// +stateify savable
type osDescMem struct {
	object
	pinnedRanges []mm.PinnedRange
}

// Release implements objectImpl.Release.
func (o *osDescMem) Release(ctx context.Context) {
	ctx.Infof("nvproxy: unpinning pages for released OS descriptor")
	mm.Unpin(o.pinnedRanges)
}

type marshalPtr[T any] interface {
	*T
	marshal.Marshallable
}

func addrFromP64(p nvgpu.P64) hostarch.Addr {
	return hostarch.Addr(uintptr(uint64(p)))
}
