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
	"slices"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// ProcfsInfo contains information about procfs files maintained by nvproxy.
type ProcfsInfo struct {
	// StaticFiles maps paths relative to /proc/driver/nvidia/ to the contents of
	// files at those paths.
	StaticFiles map[string]string
}

// ProcfsInfoFromVFS returns procfs information for nvproxy devices registered
// in vfsObj. If ProcfsInfoFromVFS returns nil, nvproxy.Register(vfsObj) has
// not been called.
func ProcfsInfoFromVFS(vfsObj *vfs.VirtualFilesystem) *ProcfsInfo {
	nvp := nvproxyFromVFS(vfsObj)
	if nvp == nil {
		return nil
	}
	procfsInfo := &ProcfsInfo{
		StaticFiles: map[string]string{
			"params": nvp.procDriverNvidiaParams,
		},
	}
	if nvp.devInfo.HaveFabricIMEXManagement {
		procfsInfo.StaticFiles["capabilities/fabric-imex-mgmt"] = procfsCapability(nvp.devInfo.FabricIMEXManagementDevMinor, 0o400)
	}
	if nvp.devInfo.HaveMNCCManagement {
		procfsInfo.StaticFiles["capabilities/mncc-mgmt"] = procfsCapability(nvp.devInfo.MNCCManagementDevMinor, 0o400)
	}
	return procfsInfo
}

// procfsCapability returns the contents of a file in
// /proc/driver/nvidia/capabilities/ representing the capability with the given
// device minor number in /dev/nvidia-caps/. mode is the mode passed to
// kernel-open/nvidia/os-interface.c:os_nv_cap_create_file_entry() =>
// kernel-open/nvidia/nv-caps.c:nv_cap_create_file_entry() and stored in
// nv_cap_t::permissions, which does not include file type and is not updated
// by file mode changes in /dev/nvidia-caps/.
func procfsCapability(devMinor, mode uint32) string {
	// Force DeviceFileModify to 0 regardless of the host value. This is
	// consistent with our treatment of ModifyDeviceFiles in
	// /proc/driver/nvidia/params.
	return fmt.Sprintf("DeviceFileMinor: %d\nDeviceFileMode: %d\nDeviceFileModify: 0\n", devMinor, mode)
}

// GPUProcDirNames returns the PCI-addressed procfs directory names of the GPUs
// available through devClient.
func GPUProcDirNames(ctx context.Context, vfsObj *vfs.VirtualFilesystem, devClient *devutil.GoferClient) ([]string, error) {
	nvp := nvproxyFromVFS(vfsObj)
	if nvp == nil || devClient == nil || nvp.capsEnabled&compUtil == 0 {
		return nil, nil
	}
	minors, err := RegularDeviceMinorsFromGofer(ctx, devClient)
	if err != nil {
		return nil, err
	}
	if len(minors) == 0 {
		return nil, nil
	}
	ctlFD, err := devClient.OpenAt(ctx, "nvidiactl", unix.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("opening nvidiactl for procfs: %w", err)
	}
	defer unix.Close(ctlFD)
	var cards [nvgpu.NV_MAX_DEVICES]nvgpu.IoctlCardInfo
	if err := queryCardInfo(uintptr(ctlFD), &cards); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(minors))
	for _, minor := range minors {
		found := false
		for _, card := range cards {
			if card.Valid == 0 || card.MinorNumber != minor {
				continue
			}
			pci := card.PCIInfo
			domainWidth := 4
			if pci.Domain > 0xffff {
				domainWidth = 8
			}
			names = append(names, fmt.Sprintf("%0*x:%02x:%02x.%x", domainWidth, pci.Domain, pci.Bus, pci.Slot, pci.Function))
			found = true
			break
		}
		if !found {
			return nil, fmt.Errorf("NV_ESC_CARD_INFO returned no info for assigned minor %d", minor)
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}
