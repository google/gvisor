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
	"encoding/binary"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
)

// exportedObject identifies an RM object exported into a frontendFD.
//
// +stateify savable
type exportedObject struct {
	client nvgpu.Handle
	object nvgpu.Handle
}

// ProcFDInfoExtra implements proc's procFDInfoExtra. Every exported fd is an
// open of /dev/nvidiactl, so this is how a process that receives one can tell
// which object it carries.
func (fd *frontendFD) ProcFDInfoExtra(ctx context.Context) string {
	fd.dev.nvp.fdsMu.Lock()
	exp := fd.exported
	fd.dev.nvp.fdsMu.Unlock()
	if exp.object.Val == 0 {
		return ""
	}
	return fmt.Sprintf("nvproxy_exported_object:\tclient=%#x object=%#x\n", exp.client.Val, exp.object.Val)
}

// ctrlExportToFD proxies an export control like ctrlHasFrontendFD, and records
// the object it exported, as given by exported, on the destination fd.
func ctrlExportToFD[Params any, PtrParams hasFrontendFDPtr[Params]](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS, exported func(PtrParams) (nvgpu.Handle, bool)) (uintptr, error) {
	return ctrlHasFrontendFDThen(fi, ioctlParams, func(fd *frontendFD, params PtrParams) {
		if object, ok := exported(params); ok {
			fd.dev.nvp.fdsMu.Lock()
			fd.exported = exportedObject{client: ioctlParams.HClient, object: object}
			fd.dev.nvp.fdsMu.Unlock()
		}
	})
}

func ctrlClientExportObjectToFD(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	return ctrlExportToFD(fi, ioctlParams, objectExported)
}

func ctrlClientExportObjectsToFD(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	return ctrlExportToFD(fi, ioctlParams, objectsExported)
}

// objectExported returns the object NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECT_TO_FD
// exports, if any.
func objectExported(params *nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) (nvgpu.Handle, bool) {
	if params.Flags&nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_FLAGS_EMPTY_FD != 0 ||
		params.Object.Type != nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TYPE_RM {
		return nvgpu.Handle{}, false
	}
	// Data is struct {hDevice, hParent, hObject}.
	return nvgpu.Handle{Val: binary.LittleEndian.Uint32(params.Object.Data[8:])}, true
}

// objectsExported returns the object NV0000_CTRL_CMD_OS_UNIX_EXPORT_OBJECTS_TO_FD
// exports into slot 0, where libcuda puts the allocation, if any.
func objectsExported(params *nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) (nvgpu.Handle, bool) {
	return params.Objects[0], params.Index == 0 && params.NumObjects > 0
}
