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
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/kvm/testutil"
)

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
