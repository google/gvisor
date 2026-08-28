// Copyright 2026 The gVisor Authors.
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

package time

import (
	"errors"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
)

// errNoTSCSample is returned by HostTSCRealtime if no usable sample could be
// collected.
var errNoTSCSample = errors.New("unable to collect a TSC sample")

func rawHostRdtsc() TSCValue {
	tsc := Rdtsc()
	if offset := tscOffset.Load(); offset != 0 && inKernelMode() {
		tsc -= TSCValue(offset)
	}
	return tsc
}

// HostTSCRealtime returns a raw host TSC value paired with the host
// CLOCK_REALTIME value in nanoseconds, both sampled at approximately the same
// instant.
//
// The realtime read is bracketed by two TSC reads and the midpoint of the
// bracket is returned, so the error in the pairing is bounded by half of the
// sampling overhead. Several samples are taken and the one with the lowest
// overhead is used. This is an approximation of an atomic (cycle, realtime)
// pair; callers that need an exact pair must obtain it from the host kernel.
//
// Samples wider than maxOverheadCycles are discarded rather than returned on a
// best-effort basis, since a bracket that was split by preemption or a thread
// migration says nothing useful about when the realtime read happened. If no
// sample qualifies, errNoTSCSample is returned and the caller is expected to
// proceed without a pair.
//
// The returned cycle count is the raw TSC. It deliberately does not include
// any guest TSC offset applied by the platform, unlike cycleClock.Cycles.
func HostTSCRealtime() (TSCValue, ReferenceNS, error) {
	var best sample
	found := false
	for i := 0; i < maxSampleLoops; i++ {
		var s sample
		s.before = rawHostRdtsc()

		// Don't call clockGettime to avoid a call which may call morestack.
		var ts unix.Timespec
		vdsoClockGettime(Realtime, &ts)

		s.after = rawHostRdtsc()
		if s.before > s.after {
			log.Warningf("TSC went backwards: %v > %v", s.before, s.after)
			continue
		}
		s.ref = ReferenceNS(ts.Nano())

		// Reject samples whose bracket was split by preemption or a thread
		// migration. A wide bracket means the realtime read cannot be
		// attributed to a specific cycle count, so the pair is unusable.
		if s.Overhead() > maxOverheadCycles {
			continue
		}

		if !found || s.Overhead() < best.Overhead() {
			best = s
			found = true
		}
	}
	if !found {
		return 0, 0, errNoTSCSample
	}

	return best.before + best.Overhead()/2, best.ref, nil
}
