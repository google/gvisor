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
	"fmt"
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
	if sync.RaceEnabled {
		// runtime.RaceDisable() doesn't actually stop the race detector, so it
		// can't help us here. Instead, call runtime.memmove directly, which is
		// not instrumented by the race detector.
		gohacks.Memmove(unsafe.Pointer(&snapshot[0]), unsafe.Pointer(&samples[0]), unsafe.Sizeof(uint64(0))*uintptr(numBuckets))
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

// NewField defines a new Field that can be used to break down a metric.
// The set of allowedValues must have unique string pointers (i.e. one cannot
// be a prefix of another from the same underlying byte slice).
// The *same* string pointers must be used during metric modifications.
// In practice, in most cases, this means you should declare these strings as
// `const`s, and always use these `const` strings during metric modifications.
func NewField(name string, allowedValues []string) Field {
	// Verify that all string values have a unique pointer.
	// We do this because we try to match strings by pointer matching first,
	// as this will work in pretty much all cases.
	ptrMap := make(map[uintptr]string, len(allowedValues))
	for _, v := range allowedValues {
		ptr := uintptr(unsafe.Pointer(unsafe.StringData(v)))
		if duplicate, found := ptrMap[ptr]; found {
			panic(fmt.Sprintf("found duplicate string values: %q vs %q", v, duplicate))
		}
		ptrMap[ptr] = v
	}

	if useMap := len(allowedValues) > fieldMapperMapThreshold; !useMap {
		return Field{
			name:   name,
			values: allowedValues,
		}
	}

	valuesPtrMap := make(map[*byte]int, len(allowedValues))
	for i, v := range allowedValues {
		valuesPtrMap[unsafe.StringData(v)] = i
	}
	return Field{
		name:         name,
		values:       allowedValues,
		valuesPtrMap: valuesPtrMap,
	}
}

// lookupSingle looks up a single key for a single field within fieldMapper.
// It is used internally within lookupConcat.
// It returns the updated `idx` and `remainingCombinationBucket` values.
// +checkescape:all
//
//go:nosplit
func (m fieldMapper) lookupSingle(fieldIndex int, fieldValue string, idx, remainingCombinationBucket int) (int, int) {
	field := m.fields[fieldIndex]
	numValues := len(field.values)
	fieldValPtr := unsafe.StringData(fieldValue)

	// Are we doing a linear search?
	if field.valuesPtrMap == nil {
		// We scan by pointers only. This means the caller must pass the same
		// string as the one used in `NewField`.
		for valIdx, allowedVal := range field.values {
			if fieldValPtr == unsafe.StringData(allowedVal) {
				remainingCombinationBucket /= numValues
				idx += remainingCombinationBucket * valIdx
				return idx, remainingCombinationBucket
			}
		}
		panic("invalid field value or did not reuse the same string pointer as passed in NewField")
	}

	// Use map lookup instead.

	// Match using the raw byte pointer of the string.
	// This avoids the string hashing step that string maps otherwise do.
	valIdx, found := field.valuesPtrMap[fieldValPtr]
	if found {
		remainingCombinationBucket /= numValues
		idx += remainingCombinationBucket * valIdx
		return idx, remainingCombinationBucket
	}

	panic("invalid field value or did not reuse the same string pointer as passed in NewField")
}
