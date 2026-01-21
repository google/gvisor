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
