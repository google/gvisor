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
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// UseApplicationMMUVM selects the UVM mode for the GPUs exposed to a container.
// Call it during device setup, before any application UVM FDs are opened. The
// driver queries use temporary host FDs, independent of application RM clients.
func UseApplicationMMUVM(ctx context.Context, devClient *devutil.GoferClient, minors []uint32, caps nvconf.DriverCaps) (bool, error) {
	if runtime.GOARCH != "arm64" || len(minors) == 0 || caps&compUtil == 0 {
		return false, nil
	}
	if devClient == nil {
		return false, fmt.Errorf("nvproxy: device gofer is unavailable for UVM mode selection")
	}
	ctlFD, err := devClient.OpenAt(ctx, "nvidiactl", unix.O_RDONLY)
	if err != nil {
		return false, fmt.Errorf("nvproxy: open nvidiactl for UVM mode selection: %w", err)
	}
	// Closing the fresh control FD frees the temporary RM client and children.
	defer unix.Close(ctlFD)
	for _, minor := range minors {
		fd, err := devClient.OpenAt(ctx, fmt.Sprintf("nvidia%d", minor), unix.O_RDONLY)
		if err != nil {
			return false, fmt.Errorf("nvproxy: open GPU %d for UVM mode selection: %w", minor, err)
		}
		// The driver requires these FDs to stay open during device allocation.
		defer unix.Close(fd)
	}
	arches, err := nvconf.GPUArchitectures(ctlFD, minors)
	if err != nil {
		return false, fmt.Errorf("nvproxy: query GPU architectures for UVM mode selection: %w", err)
	}
	for _, arch := range arches {
		if gpuRequiresApplicationMMUVM(arch) {
			return true, nil
		}
	}
	return false, nil
}

func gpuRequiresApplicationMMUVM(arch nvconf.GPUArchInfo) bool {
	// Known integrated CPU-GPU compute platforms, starting with GH/GB systems,
	// use the application's host page tables. Otherwise initialization will not
	// work due to the GPU requiring ATS.
	switch arch.Architecture {
	// Internal identifier: GH200
	case nvgpu.NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GH100:
		return arch.Implementation == nvgpu.NV2080_CTRL_MC_ARCH_INFO_IMPLEMENTATION_GH100_SOC

	// Internal identifier: GB200, GB300
	case nvgpu.NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GB100:
		return arch.Implementation == nvgpu.NV2080_CTRL_MC_ARCH_INFO_IMPLEMENTATION_GB100 || arch.Implementation == nvgpu.NV2080_CTRL_MC_ARCH_INFO_IMPLEMENTATION_GB110

	// Internal identifier: VR200
	case nvgpu.NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GR100:
		return arch.Implementation == nvgpu.NV2080_CTRL_MC_ARCH_INFO_IMPLEMENTATION_GR100

	default:
		return false
	}
}

// SetContainerUVMMode records a mode selected during device setup. Each UVM FD
// keeps the mode of its opening container even if passed to another container.
func SetContainerUVMMode(vfsObj *vfs.VirtualFilesystem, containerName string, applicationMM bool) {
	nvp := nvproxyFromVFS(vfsObj)
	if nvp == nil {
		panic("nvproxy: setting UVM mode before device registration")
	}
	nvp.fdsMu.Lock()
	defer nvp.fdsMu.Unlock()
	nvp.containerUVMModes[containerName] = applicationMM
}
