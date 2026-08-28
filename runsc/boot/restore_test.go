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

package boot

import (
	"math"
	"testing"
)

func TestTSCOffsetFromSnapshot(t *testing.T) {
	const (
		ghz3     = uint64(3_000_000_000)
		nsPerDay = uint64(86_400_000_000_000)
	)
	for _, tc := range []struct {
		name         string
		baseCycle    uint64
		baseFreq     uint64
		baseRealtime uint64
		curCycle     uint64
		curRealtime  uint64
		want         uint64
		wantOK       bool
	}{
		{
			name:         "NoTimeElapsed",
			baseCycle:    1000,
			baseFreq:     ghz3,
			baseRealtime: 5_000,
			curCycle:     400,
			curRealtime:  5_000,
			want:         600,
			wantOK:       true,
		},
		{
			name:         "RealtimeBehindSnapshot",
			baseCycle:    1000,
			baseFreq:     ghz3,
			baseRealtime: 10_000,
			curCycle:     400,
			curRealtime:  5_000,
			want:         600,
			wantOK:       true,
		},
		{
			name:         "OneSecond",
			baseCycle:    1000,
			baseFreq:     ghz3,
			baseRealtime: 0,
			curCycle:     1000,
			curRealtime:  1_000_000_000,
			want:         ghz3,
			wantOK:       true,
		},
		{
			// deltaNs * baseFreq overflows 64 bits here.
			name:         "OneDay",
			baseCycle:    1_000_000,
			baseFreq:     ghz3,
			baseRealtime: 1_000,
			curCycle:     1_000_000,
			curRealtime:  1_000 + nsPerDay,
			want:         86_400 * ghz3,
			wantOK:       true,
		},
		{
			name:         "NegativeOffset",
			baseCycle:    1000,
			baseFreq:     ghz3,
			baseRealtime: 0,
			curCycle:     5000,
			curRealtime:  0,
			want:         ^uint64(4000) + 1,
			wantOK:       true,
		},
		{
			name:         "ElapsedCyclesOverflow",
			baseCycle:    0,
			baseFreq:     math.MaxUint64,
			baseRealtime: 0,
			curCycle:     0,
			curRealtime:  2_000_000_000,
			wantOK:       false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tscOffsetFromSnapshot(tc.baseCycle, tc.baseFreq, tc.baseRealtime, tc.curCycle, tc.curRealtime)
			if ok != tc.wantOK {
				t.Fatalf("tscOffsetFromSnapshot() ok = %t, want %t", ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("tscOffsetFromSnapshot() = %d, want %d", got, tc.want)
			}
		})
	}
}
