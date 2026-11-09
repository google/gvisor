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
	"runtime"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
)

// timerGetTime invokes NV2080_CTRL_CMD_TIMER_GET_TIME on subdevice sub of
// client, from the NV_ESC_RM_CONTROL in fi, and returns the GPU time and RM's
// status.
func timerGetTime(fi *frontendIoctlState, client, sub nvgpu.Handle) (uint64, uint32, error) {
	var getTime nvgpu.NV2080_CTRL_TIMER_GET_TIME_PARAMS
	defer runtime.KeepAlive(&getTime) // since we convert to non-pointer-typed P64
	ioctlParams := nvgpu.NVOS54_PARAMETERS{
		HClient:    client,
		HObject:    sub,
		Cmd:        nvgpu.NV2080_CTRL_CMD_TIMER_GET_TIME,
		Params:     p64FromPtr(unsafe.Pointer(&getTime)),
		ParamsSize: uint32(getTime.SizeBytes()),
	}
	if _, err := frontendIoctlInvoke(fi, &ioctlParams); err != nil {
		return 0, 0, err
	}
	return getTime.TimeNsec, ioctlParams.Status, nil
}
