// Copyright 2019 The gVisor Authors.
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

// +build amd64

package filter

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

func init() {
	allowedSyscalls[syscall.SYS_ARCH_PRCTL] = append(allowedSyscalls[syscall.SYS_ARCH_PRCTL],
		seccomp.Rule{seccomp.AllowValue(linux.ARCH_GET_FS)},
		seccomp.Rule{seccomp.AllowValue(linux.ARCH_SET_FS)},
	)
}
