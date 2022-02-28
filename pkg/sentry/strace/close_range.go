// Copyright 2022 The gVisor Authors.
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

package strace

import (
	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// CloseRangeFlagSet is the set of close_range(2) flags.
var CloseRangeFlagSet = abi.FlagSet{
	{
		Flag: uint64(linux.CLOSE_RANGE_CLOEXEC),
		Name: "CLOSE_RANGE_CLOEXEC",
	},
	{
		Flag: uint64(linux.CLOSE_RANGE_UNSHARE),
		Name: "CLOSE_RANGE_UNSHARE",
	},
}
