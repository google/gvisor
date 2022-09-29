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

package linux

// PreComputedIOSqRingOffsets returns precomputed values for IOSqRingOffsets.
func PreComputedIOSqRingOffsets() IOSqRingOffsets {
	return IOSqRingOffsets{
		Head: 0 + 0,
		Tail: 0 + 64,
		RingMask: 256,
		RingEntries: 264,
		Flags: 276,
		Dropped: 272,
	}
}

// PreComputedIOCqRingOffsets returns precomputed values for IOCqRingOffsets.
func PreComputedIOCqRingOffsets() IOCqRingOffsets {
	return IOCqRingOffsets {
		Head: 128 + 0,
		Tail: 128 + 64,
		RingMask: 260,
		RingEntries: 268,
		Overflow: 284,
		Flags: 280,
	}
}
