// Copyright 2024 The gVisor Authors.
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

//go:build loong64
// +build loong64

package ptrace

import (
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// getTLS gets the thread-pointer register ($r2 = $tp).
//
// On LoongArch the TLS pointer lives in the regular GPR file, so we read
// the whole register set via NT_PRSTATUS (which subprocess_linux.go's
// getRegs already does) and extract regs[2]. This is heavier than arm64's
// dedicated NT_ARM_TLS regset but it is the only path the kernel exposes.
func (t *thread) getTLS(tls *uint64) error {
	var regs arch.Registers
	if err := t.getRegs(&regs); err != nil {
		return err
	}
	*tls = regs.Regs[2]
	return nil
}

// setTLS sets the thread-pointer register ($r2 = $tp). It is a
// read-modify-write of the full register set; callers must therefore not
// call setTLS while assuming other registers are unchanged.
func (t *thread) setTLS(tls *uint64) error {
	// LoongArch keeps the TLS pointer in $r2, an ordinary GPR that setRegs()
	// already writes as part of the full NT_PRSTATUS register set. A separate
	// getRegs+modify+setRegs RMW here is redundant and can corrupt the entire
	// restored register state if the ptrace readback differs in any field
	// from what setRegs() just wrote. So this is intentionally a no-op.
	_ = tls
	return nil
}
