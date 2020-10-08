// Copyright 2020 The gVisor Authors.
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

package linux

// membarrier(2) commands, from include/uapi/linux/membarrier.h.
const (
	MEMBARRIER_CMD_QUERY                                = 0
	MEMBARRIER_CMD_GLOBAL                               = (1 << 0)
	MEMBARRIER_CMD_GLOBAL_EXPEDITED                     = (1 << 1)
	MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED            = (1 << 2)
	MEMBARRIER_CMD_PRIVATE_EXPEDITED                    = (1 << 3)
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED           = (1 << 4)
	MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE          = (1 << 5)
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE = (1 << 6)
	MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ               = (1 << 7)
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ      = (1 << 8)
)

// membarrier(2) flags, from include/uapi/linux/membarrier.h.
const (
	MEMBARRIER_CMD_FLAG_CPU = (1 << 0)
)
