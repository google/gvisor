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

package nvgpu

// Status codes, from src/common/sdk/nvidia/inc/nvstatuscodes.h.
const (
	NV_ERR_INVALID_ADDRESS  = 0x0000001e
	NV_ERR_INVALID_ARGUMENT = 0x0000001f
	NV_ERR_INVALID_CLASS    = 0x00000022
	NV_ERR_INVALID_LIMIT    = 0x0000002e
	NV_ERR_NOT_SUPPORTED    = 0x00000056
)
