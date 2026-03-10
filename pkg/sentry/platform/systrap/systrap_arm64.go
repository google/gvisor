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

package systrap

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

func stackPointer(r *arch.Registers) uintptr {
	return uintptr(r.Sp)
}

// configureSystrapAddressSpace overrides the default 48-bit address space
// parameters when the host uses a different VA width. On 48-bit VA hosts,
// ConfigureAddressSpace(1<<48) re-affirms the defaults.
//
// This function MUST be called during systrap initialization, before any
// Context64 is created.
func configureSystrapAddressSpace() {
	arch.ConfigureAddressSpace(uintptr(linux.TaskSize))
}
