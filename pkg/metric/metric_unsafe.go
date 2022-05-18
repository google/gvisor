// Copyright 2022 The gVisor Authors.
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

package metric

import (
	"unsafe"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/sync"
)

// snapshotDistribution snapshots the sample data of distribution metrics in
// a non-consistent manner.
// Distribution metrics don't need to be read consistently, because any
// inconsistency (i.e. increments that race with the snapshot) will simply be
// detected during the next snapshot instead. Reading them consistently would
// require more synchronization during increments, which we need to be cheap.
func snapshotDistribution(samples []atomicbitops.Uint64) []uint64 {
	// The number of buckets within a distribution never changes, so there is
	// no race condition from getting the number of buckets upfront.
	numBuckets := len(samples)
	snapshot := make([]uint64, numBuckets)
	samplesHeader := (*gohacks.SliceHeader)(unsafe.Pointer(&samples))
	snapshotHeader := (*gohacks.SliceHeader)(unsafe.Pointer(&snapshot))
	if sync.RaceEnabled {
		// runtime.RaceDisable() doesn't actually stop the race detector, so it
		// can't help us here. Instead, call runtime.memmove directly, which is
		// not instrumented by the race detector.
		gohacks.Memmove(snapshotHeader.Data, samplesHeader.Data, unsafe.Sizeof(uint64(0))*uintptr(numBuckets))
	} else {
		for i := range samples {
			snapshot[i] = samples[i].RacyLoad()
		}
	}
	return snapshot
}

// CheapNowNano returns the current unix timestamp in nanoseconds.
//
//go:nosplit
func CheapNowNano() int64 {
	return gohacks.Nanotime()
}
