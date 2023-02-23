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
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

func stackPointer(r *arch.Registers) uintptr {
	return uintptr(r.Rsp)
}

// x86 use the fs_base register to store the TLS pointer which can be
// get/set in "func (t *thread) get/setRegs(regs *arch.Registers)".
// So both of the get/setTLS() operations are noop here.

// getTLS gets the thread local storage register.
func (t *thread) getTLS(tls *uint64) error {
	return nil
}

// setTLS sets the thread local storage register.
func (t *thread) setTLS(tls *uint64) error {
	return nil
}
