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
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Register registers all devices implemented by this package in vfsObj.
func Register(vfsObj *vfs.VirtualFilesystem, versionStr string, uvmDevMajor uint32) error {
	// The kernel driver's interface is unstable, so only allow versions of the
	// driver that are known to be supported.
	log.Infof("NVIDIA driver version: %s", versionStr)
	version, err := DriverVersionFrom(versionStr)
	if err != nil {
		return fmt.Errorf("failed to parse Nvidia driver version %s: %w", versionStr, err)
	}
	abiCons, ok := abis[version]
	if !ok {
		return fmt.Errorf("unsupported Nvidia driver version: %s", versionStr)
	}
	nvp := &nvproxy{
		abi:         abiCons.cons(),
		version:     version,
		frontendFDs: make(map[*frontendFD]struct{}),
		clients:     make(map[nvgpu.Handle]*rootClient),
		objsFreeSet: make(map[*object]struct{}),
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
	abi     *driverABI `state:"nosave"`
	version DriverVersion

	fdsMu       fdsMutex `state:"nosave"`
	frontendFDs map[*frontendFD]struct{}

	// See object.go.
	// Users should call nvproxy.objsLock/Unlock() rather than locking objsMu
	// directly.
	objsMu objsMutex `state:"nosave"`
	// These fields are protected by objsMu.
	clients      map[nvgpu.Handle]*rootClient
	objsCleanup  []func()             `state:"nosave"`
	objsFreeList objectFreeList       `state:"nosave"`
	objsFreeSet  map[*object]struct{} `state:"nosave"`
}

type marshalPtr[T any] interface {
	*T
	marshal.Marshallable
}

func addrFromP64(p nvgpu.P64) hostarch.Addr {
	return hostarch.Addr(uintptr(uint64(p)))
}

type hasFrontendFDPtr[T any] interface {
	marshalPtr[T]
	nvgpu.HasFrontendFD
}

type hasCtrlInfoListPtr[T any] interface {
	marshalPtr[T]
	nvgpu.HasCtrlInfoList
}

// NvidiaDeviceFD is an interface that should be implemented by all
// vfs.FileDescriptionImpl of Nvidia devices.
type NvidiaDeviceFD interface {
	IsNvidiaDeviceFD()
}
