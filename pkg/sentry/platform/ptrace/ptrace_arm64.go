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

package ptrace

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// archContext is architecture-specific context.
type archContext struct {
	// fpLen is the size of the floating point state.
	fpLen int
}

// init initializes the archContext.
func (a *archContext) init(ctx pkgcontext.Context) {
	fs := cpuid.FromContext(ctx)
	fpLen, _ := fs.ExtendedStateSize()
	a.fpLen = int(fpLen)
}

// floatingPointLength returns the length of floating point state.
func (a *archContext) floatingPointLength() uint64 {
	return uint64(a.fpLen)
}

// floatingPointRegSet returns the register set to fetch.
func (a *archContext) floatingPointRegSet() uintptr {
	return linux.NT_PRFPREG
}

func stackPointer(r *arch.Registers) uintptr {
	return uintptr(r.Sp)
}
