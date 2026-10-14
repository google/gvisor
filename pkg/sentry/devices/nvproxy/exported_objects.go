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

// exportedObject describes the RM object last exported into a frontendFD.
//
// The driver duplicates the object when exporting it, so the export outlives
// the exporter's handle, which may then be freed and reused. client and object
// therefore only say where the export came from; id identifies it.
//
// +stateify savable
type exportedObject struct {
	// id is unique among the sandbox's exports, and 0 if there is none.
	id     uint64
	client nvgpu.Handle
	object nvgpu.Handle
}

// ProcFDInfoExtra implements proc's procFDInfoExtra. Every exported fd is an
// open of /dev/nvidiactl, so this is how a process that receives one can tell
// which export it carries.
func (fd *frontendFD) ProcFDInfoExtra(ctx context.Context) string {
	fd.exportedMu.Lock()
	exp := fd.exported
	fd.exportedMu.Unlock()
	if exp.id == 0 {
		return ""
	}
	return fmt.Sprintf("nvproxy_exported_object:\tclient=%#x object=%#x id=%d\n", exp.client.Val, exp.object.Val, exp.id)
}

// ctrlExportToFD proxies an export control like ctrlHasFrontendFD, and records
// the object it exported, as given by exported, on the destination fd.
func ctrlExportToFD[Params any, PtrParams hasFrontendFDPtr[Params]](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS, exported func(PtrParams) (nvgpu.Handle, bool)) (uintptr, error) {
	return ctrlHasFrontendFDInvoke(fi, ioctlParams, func(fd *frontendFD, ctrlParams PtrParams) (uintptr, error) {
		// The driver lets a later export replace an earlier one, so record
		// under the same lock as the export, and before any copy-out that may
		// fail after the export happened.
		fd.exportedMu.Lock()
		n, err := rmControlInvokeHost(fi, ioctlParams, ctrlParams)
		if err == nil && ioctlParams.Status == nvgpu.NV_OK {
			if object, ok := exported(ctrlParams); ok {
				fd.exported = exportedObject{client: ioctlParams.HClient, object: object}
				if object.Val != 0 {
					fd.exported.id = fd.dev.nvp.lastExportID.Add(1)
				}
			}
		}
		fd.exportedMu.Unlock()
		if err != nil {
			return n, err
		}
		if _, err := ioctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
			return n, err
		}
		return n, nil
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
// puts into slot 0, where libcuda puts the allocation, if it sets slot 0. A
// zero handle empties the slot.
func objectsExported(params *nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) (nvgpu.Handle, bool) {
	return params.Objects[0], params.Index == 0 && params.NumObjects > 0
}
