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
	"errors"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sync"
)

// getCNTFRQ returns the frequency (in Hz) of the system counter read by
// cputicks(), as reported by CNTFRQ_EL0.
func getCNTFRQ() int64

// typicalCNTFRQ is a fallback system counter frequency (24MHz, a common
// reference-crystal value) used only if CNTFRQ_EL0 reads back as zero. The
// architecture requires firmware to program CNTFRQ_EL0, so real hardware always
// reports a non-zero value; this only guards against a misconfigured board.
// Actual frequencies vary widely -- from tens of MHz up to ~1GHz on newer
// cores -- so this is a best-effort guess, not a value that fits all hardware.
const typicalCNTFRQ = 24 * 1000 * 1000

// cputicksFreq returns the frequency in Hz of the counter read by cputicks().
// On arm64 cputicks() reads CNTVCT_EL0, whose frequency is reported exactly by
// CNTFRQ_EL0, so no calibration is needed. It always returns a non-zero value:
// the sleep-timeout conversion needs a frequency, and there is no sane
// cross-platform default (the counter rate is platform-specific and ranges from
// tens of MHz to ~GHz), so the fallback must be arch-specific.
func cputicksFreq() uint64 {
	if freq := getCNTFRQ(); freq > 0 {
		return uint64(freq)
	}
	return typicalCNTFRQ
}

func stackPointer(r *arch.Registers) uintptr {
	return uintptr(r.Sp)
}

// pointerAuthWarnOnce is used to ensure a warning about disabling PAC failing is only printed
// once to avoid console output spam.
var pointerAuthWarnOnce sync.Once

// disablePointerAuth disables all pointer authentication address keys for the
// thread.
func (t *thread) disablePointerAuth() error {
	if !cpuid.HostFeatureSet().HasPointerAuth() {
		// CPU doesn't support PAC; skip
		return nil
	}

	err := t.setEnabledPointerAuthKeys(0)
	if errors.Is(err, unix.EINVAL) {
		// Somewhat annoyingly, Linux appears to have added PAC support in 5.0 yet added support
		// for disabling it per-process in 5.13.
		// So disabling PAC will only work on kernels >=5.13.
		//
		// We ignore EINVAL in case we are on such a kernel version.
		pointerAuthWarnOnce.Do(func() {
			log.Warningf("Unable to disable pointer authentication for application processes (is the host kernel 5.13 or greater?): %v", err)
		})
		return nil
	}
	return err
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
