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

package state

import (
	"strconv"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	ktime "gvisor.dev/gvisor/pkg/sentry/time"
)

// The save metadata keys for the TSC snapshot.
//
// NOTE: Tooling outside of gVisor relies on these, so keep these compatible
// and don't change their name.
const (
	metadataTSCSnapshotCycleKey        = "gvisor_tsc_snapshot_cycle"
	metadataTSCSnapshotFrequencyKey    = "gvisor_tsc_snapshot_frequency"
	metadataTSCSnapshotRealtimeNsecKey = "gvisor_tsc_snapshot_realtime_nsec"
)

// addTSCSaveMetadata records the TSC snapshot needed to re-derive a guest TSC
// offset on restore, deriving it from the kernel's clock source.
func addTSCSaveMetadata(m map[string]string, k *kernel.Kernel) {
	snapshot, ok := k.Timekeeper().TSCSnapshot()
	if !ok {
		snapshot, ok = sampleTSCSnapshot(k)
	}
	if !ok {
		log.Warningf("No TSC snapshot is available, unable to save TSC")
		return
	}

	m[metadataTSCSnapshotCycleKey] = strconv.FormatUint(snapshot.Cycle, 10)
	m[metadataTSCSnapshotFrequencyKey] = strconv.FormatUint(snapshot.Frequency, 10)
	m[metadataTSCSnapshotRealtimeNsecKey] = strconv.FormatUint(snapshot.RealtimeNsec, 10)
}

// sampleTSCSnapshot builds a snapshot by reading the host directly, pairing a
// TSC sample with the frequency the platform learned from the host.
//
// The clock source cannot answer until it has collected two samples spaced an
// update interval apart, which takes about a second after boot. A checkpoint
// in that window would otherwise save no snapshot at all, leaving restore with
// nothing to correct the guest TSC against.
func sampleTSCSnapshot(k *kernel.Kernel) (ktime.TSCSnapshot, bool) {
	tap, ok := k.Platform.(platform.TSCAdjustablePlatform)
	if !ok {
		// Without TSC adjustment there is nothing for restore to do with
		// a snapshot.
		return ktime.TSCSnapshot{}, false
	}
	frequency, ok := tap.TSCFrequency()
	if !ok {
		log.Warningf("Platform does not know the TSC frequency, unable to sample the TSC")
		return ktime.TSCSnapshot{}, false
	}
	cycle, realtime, err := ktime.HostTSCRealtime()
	if err != nil {
		log.Warningf("Unable to sample the host TSC: %v", err)
		return ktime.TSCSnapshot{}, false
	}
	// HostTSCRealtime reports the raw host TSC. Shift it into the guest TSC
	// domain that the snapshot is expressed in.
	return ktime.TSCSnapshot{
		Cycle:        uint64(cycle) + uint64(ktime.TSCOffset()),
		RealtimeNsec: uint64(realtime),
		Frequency:    frequency,
	}, true
}
