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

//go:build arm64
// +build arm64

package kvm

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/kvm/testutil"
)

// TestTCRGranule verifies that the translation granule programmed into
// TCR_EL1 describes the same page size that the guest page tables are built
// for. If these disagree, every guest translation faults.
//
// The TG0 and TG1 fields use different encodings for the same granule sizes,
// so each is decoded here against the encoding given in the Arm ARM (D19.2.139
// TCR_EL1) rather than compared against the constants used to build
// _TCR_TG_FLAGS.
func TestTCRGranule(t *testing.T) {
	tg0Sizes := map[uintptr]int{0b00: 4096, 0b01: 65536, 0b10: 16384}
	tg1Sizes := map[uintptr]int{0b01: 16384, 0b10: 4096, 0b11: 65536}

	tg0 := uintptr(_TCR_TG_FLAGS>>_TCR_TG0_SHIFT) & 0x3
	if got, ok := tg0Sizes[tg0]; !ok {
		t.Errorf("TCR_EL1.TG0 = %#b is a reserved encoding", tg0)
	} else if got != hostarch.PageSize {
		t.Errorf("TCR_EL1.TG0 = %#b (%d-byte granule); want a %d-byte granule", tg0, got, hostarch.PageSize)
	}

	tg1 := uintptr(_TCR_TG_FLAGS>>_TCR_TG1_SHIFT) & 0x3
	if got, ok := tg1Sizes[tg1]; !ok {
		t.Errorf("TCR_EL1.TG1 = %#b is a reserved encoding", tg1)
	} else if got != hostarch.PageSize {
		t.Errorf("TCR_EL1.TG1 = %#b (%d-byte granule); want a %d-byte granule", tg1, got, hostarch.PageSize)
	}
}

func TestKernelTLS(t *testing.T) {
	bluepillTest(t, func(c *vCPU) {
		if !testutil.TLSWorks() {
			t.Errorf("tls does not work, and it should!")
		}
	})
}

// TestApplicationPAC checks that non-hint pointer authentication
// instructions work in guest user mode. On hosts with FEAT_PAuth, these
// instructions execute natively (Linux enables pointer authentication for
// all user tasks), so applications compiled for armv8.3+ may execute them
// unconditionally; they must not be treated as undefined instructions.
func TestApplicationPAC(t *testing.T) {
	applicationTest(t, true, testutil.AddrOfPACLoop(), func(c *vCPU, regs *arch.Registers, pt *pagetables.PageTables) bool {
		if !hasPtrauth {
			// Without FEAT_PAuth, PAC instructions are UNDEFINED and
			// SIGILL is the correct native behavior: nothing to test.
			t.Skip("pointer authentication is not supported by the host")
		}
		var si linux.SignalInfo
		if _, err := c.SwitchToUser(ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: &dummyFPState,
			PageTables:         pt,
		}, &si); err == platform.ErrContextInterrupt {
			return true // Retry.
		} else if err != nil {
			t.Errorf("PAC instructions raised (%v, %+v), expected a clean syscall return", err, si)
		}
		return false
	})
}
