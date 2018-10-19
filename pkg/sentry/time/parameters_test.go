// Copyright 2018 Google LLC
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
	"math"
	"testing"
	"time"
)

func TestParametersComputeTime(t *testing.T) {
	testCases := []struct {
		name   string
		params Parameters
		now    TSCValue
		want   int64
	}{
		{
			// Now is the same as the base cycles.
			name: "base-cycles",
			params: Parameters{
				BaseCycles: 10000,
				BaseRef:    ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
			now:  10000,
			want: 5000 * time.Millisecond.Nanoseconds(),
		},
		{
			// Now is the behind the base cycles. Time is frozen.
			name: "backwards",
			params: Parameters{
				BaseCycles: 10000,
				BaseRef:    ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
			now:  9000,
			want: 5000 * time.Millisecond.Nanoseconds(),
		},
		{
			// Now is ahead of the base cycles.
			name: "ahead",
			params: Parameters{
				BaseCycles: 10000,
				BaseRef:    ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
			now:  15000,
			want: 5500 * time.Millisecond.Nanoseconds(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.params.ComputeTime(tc.now)
			if !ok {
				t.Errorf("ComputeTime ok got %v want true", got)
			}
			if got != tc.want {
				t.Errorf("ComputeTime got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestParametersErrorAdjust(t *testing.T) {
	testCases := []struct {
		name      string
		oldParams Parameters
		now       TSCValue
		newParams Parameters
		want      Parameters
		errorNS   ReferenceNS
		wantErr   bool
	}{
		{
			// newParams are perfectly continuous with oldParams
			// and don't need adjustment.
			name: "continuous",
			oldParams: Parameters{
				BaseCycles: 0,
				BaseRef:    0,
				Frequency:  10000,
			},
			now: 50000,
			newParams: Parameters{
				BaseCycles: 50000,
				BaseRef:    ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
			want: Parameters{
				BaseCycles: 50000,
				BaseRef:    ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
		},
		{
			// Same as "continuous", but with now ahead of
			// newParams.BaseCycles. The result is the same as
			// there is no error to correct.
			name: "continuous-nowdiff",
			oldParams: Parameters{
				BaseCycles: 0,
				BaseRef:    0,
				Frequency:  10000,
			},
			now: 60000,
			newParams: Parameters{
				BaseCycles: 50000,
				BaseRef:    ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
			want: Parameters{
				BaseCycles: 50000,
				BaseRef:    ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
		},
		{
			// errorAdjust bails out if the TSC goes backwards.
			name: "tsc-backwards",
			oldParams: Parameters{
				BaseCycles: 10000,
				BaseRef:    ReferenceNS(1000 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
			now: 9000,
			newParams: Parameters{
				BaseCycles: 9000,
				BaseRef:    ReferenceNS(1100 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
			wantErr: true,
		},
		{
			// errorAdjust bails out if new params are from after now.
			name: "params-after-now",
			oldParams: Parameters{
				BaseCycles: 10000,
				BaseRef:    ReferenceNS(1000 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
			now: 11000,
			newParams: Parameters{
				BaseCycles: 12000,
				BaseRef:    ReferenceNS(1200 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
			wantErr: true,
		},
		{
			// Host clock sped up.
			name: "speed-up",
			oldParams: Parameters{
				BaseCycles: 0,
				BaseRef:    0,
				Frequency:  10000,
			},
			now: 45000,
			// Host frequency changed to 9000 immediately after
			// oldParams was returned.
			newParams: Parameters{
				BaseCycles: 45000,
				// From oldParams, we think ref = 4.5s at cycles = 45000.
				BaseRef:   ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency: 9000,
			},
			want: Parameters{
				BaseCycles: 45000,
				BaseRef:    ReferenceNS(4500 * time.Millisecond.Nanoseconds()),
				// We must decrease the new frequency by 50% to
				// correct 0.5s of error in 1s
				// (ApproxUpdateInterval).
				Frequency: 4500,
			},
			errorNS: ReferenceNS(-500 * time.Millisecond.Nanoseconds()),
		},
		{
			// Host clock sped up, with now ahead of newParams.
			name: "speed-up-nowdiff",
			oldParams: Parameters{
				BaseCycles: 0,
				BaseRef:    0,
				Frequency:  10000,
			},
			now: 50000,
			// Host frequency changed to 9000 immediately after
			// oldParams was returned.
			newParams: Parameters{
				BaseCycles: 45000,
				BaseRef:    ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency:  9000,
			},
			// nextRef = 6000ms
			// nextCycles = 9000 * (6000ms - 5000ms) + 45000
			// nextCycles = 9000 * (1s) + 45000
			// nextCycles = 54000
			// f = (54000 - 50000) / 1s = 4000
			//
			// ref = 5000ms - (50000 - 45000) / 4000
			// ref = 3.75s
			want: Parameters{
				BaseCycles: 45000,
				BaseRef:    ReferenceNS(3750 * time.Millisecond.Nanoseconds()),
				Frequency:  4000,
			},
			// oldNow = 50000 * 10000 = 5s
			// newNow = (50000 - 45000) / 9000 + 5s = 5.555s
			errorNS: ReferenceNS((5000*time.Millisecond - 5555555555).Nanoseconds()),
		},
		{
			// Host clock sped up. The new parameters are so far
			// ahead that the next update time already passed.
			name: "speed-up-uncorrectable-baseref",
			oldParams: Parameters{
				BaseCycles: 0,
				BaseRef:    0,
				Frequency:  10000,
			},
			now: 50000,
			// Host frequency changed to 5000 immediately after
			// oldParams was returned.
			newParams: Parameters{
				BaseCycles: 45000,
				BaseRef:    ReferenceNS(9000 * time.Millisecond.Nanoseconds()),
				Frequency:  5000,
			},
			// The next update should be at 10s, but newParams
			// already passed 6s.  Thus it is impossible to correct
			// the clock by then.
			wantErr: true,
		},
		{
			// Host clock sped up. The new parameters are moving so
			// fast that the next update should be before now.
			name: "speed-up-uncorrectable-frequency",
			oldParams: Parameters{
				BaseCycles: 0,
				BaseRef:    0,
				Frequency:  10000,
			},
			now: 55000,
			// Host frequency changed to 7500 immediately after
			// oldParams was returned.
			newParams: Parameters{
				BaseCycles: 45000,
				BaseRef:    ReferenceNS(6000 * time.Millisecond.Nanoseconds()),
				Frequency:  7500,
			},
			// The next update should be at 6.5s, but newParams are
			// so far ahead and fast that they reach 6.5s at cycle
			// 48750, which before now! Thus it is impossible to
			// correct the clock by then.
			wantErr: true,
		},
		{
			// Host clock slowed down.
			name: "slow-down",
			oldParams: Parameters{
				BaseCycles: 0,
				BaseRef:    0,
				Frequency:  10000,
			},
			now: 55000,
			// Host frequency changed to 11000 immediately after
			// oldParams was returned.
			newParams: Parameters{
				BaseCycles: 55000,
				// From oldParams, we think ref = 5.5s at cycles = 55000.
				BaseRef:   ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency: 11000,
			},
			want: Parameters{
				BaseCycles: 55000,
				BaseRef:    ReferenceNS(5500 * time.Millisecond.Nanoseconds()),
				// We must increase the new frequency by 50% to
				// correct 0.5s of error in 1s
				// (ApproxUpdateInterval).
				Frequency: 16500,
			},
			errorNS: ReferenceNS(500 * time.Millisecond.Nanoseconds()),
		},
		{
			// Host clock slowed down, with now ahead of newParams.
			name: "slow-down-nowdiff",
			oldParams: Parameters{
				BaseCycles: 0,
				BaseRef:    0,
				Frequency:  10000,
			},
			now: 60000,
			// Host frequency changed to 11000 immediately after
			// oldParams was returned.
			newParams: Parameters{
				BaseCycles: 55000,
				BaseRef:    ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency:  11000,
			},
			// nextRef = 7000ms
			// nextCycles = 11000 * (7000ms - 5000ms) + 55000
			// nextCycles = 11000 * (2000ms) + 55000
			// nextCycles = 77000
			// f = (77000 - 60000) / 1s = 17000
			//
			// ref = 6000ms - (60000 - 55000) / 17000
			// ref = 5705882353ns
			want: Parameters{
				BaseCycles: 55000,
				BaseRef:    ReferenceNS(5705882353),
				Frequency:  17000,
			},
			// oldNow = 60000 * 10000 = 6s
			// newNow = (60000 - 55000) / 11000 + 5s = 5.4545s
			errorNS: ReferenceNS((6*time.Second - 5454545454).Nanoseconds()),
		},
		{
			// Host time went backwards.
			name: "time-backwards",
			oldParams: Parameters{
				BaseCycles: 50000,
				BaseRef:    ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
			now: 60000,
			newParams: Parameters{
				BaseCycles: 60000,
				// From oldParams, we think ref = 6s at cycles = 60000.
				BaseRef:   ReferenceNS(4000 * time.Millisecond.Nanoseconds()),
				Frequency: 10000,
			},
			want: Parameters{
				BaseCycles: 60000,
				BaseRef:    ReferenceNS(6000 * time.Millisecond.Nanoseconds()),
				// We must increase the frequency by 200% to
				// correct 2s of error in 1s
				// (ApproxUpdateInterval).
				Frequency: 30000,
			},
			errorNS: ReferenceNS(2000 * time.Millisecond.Nanoseconds()),
		},
		{
			// Host time went backwards, with now ahead of newParams.
			name: "time-backwards-nowdiff",
			oldParams: Parameters{
				BaseCycles: 50000,
				BaseRef:    ReferenceNS(5000 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
			now: 65000,
			// nextRef = 7500ms
			// nextCycles = 10000 * (7500ms - 4000ms) + 60000
			// nextCycles = 10000 * (3500ms) + 60000
			// nextCycles = 95000
			// f = (95000 - 65000) / 1s = 30000
			//
			// ref = 6500ms - (65000 - 60000) / 30000
			// ref = 6333333333ns
			newParams: Parameters{
				BaseCycles: 60000,
				BaseRef:    ReferenceNS(4000 * time.Millisecond.Nanoseconds()),
				Frequency:  10000,
			},
			want: Parameters{
				BaseCycles: 60000,
				BaseRef:    ReferenceNS(6333333334),
				Frequency:  30000,
			},
			// oldNow = 65000 * 10000 = 6.5s
			// newNow = (65000 - 60000) / 10000 + 4s = 4.5s
			errorNS: ReferenceNS(2000 * time.Millisecond.Nanoseconds()),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, errorNS, err := errorAdjust(tc.oldParams, tc.newParams, tc.now)
			if err != nil && !tc.wantErr {
				t.Errorf("err got %v want nil", err)
			} else if err == nil && tc.wantErr {
				t.Errorf("err got nil want non-nil")
			}

			if got != tc.want {
				t.Errorf("Parameters got %+v want %+v", got, tc.want)
			}
			if errorNS != tc.errorNS {
				t.Errorf("errorNS got %v want %v", errorNS, tc.errorNS)
			}
		})
	}
}

func testMuldiv(t *testing.T, v uint64) {
	for i := uint64(1); i <= 1000000; i++ {
		mult := uint64(1000000000)
		div := i * mult
		res, ok := muldiv64(v, mult, div)
		if !ok {
			t.Errorf("Result of %v * %v / %v ok got false want true", v, mult, div)
		}
		if want := v / i; res != want {
			t.Errorf("Bad result of %v * %v / %v: got %v, want %v", v, mult, div, res, want)
		}
	}
}

func TestMulDiv(t *testing.T) {
	testMuldiv(t, math.MaxUint64)
	for i := int64(-10); i <= 10; i++ {
		testMuldiv(t, uint64(i))
	}
}

func TestMulDivZero(t *testing.T) {
	if r, ok := muldiv64(2, 4, 0); ok {
		t.Errorf("muldiv64(2, 4, 0) got %d, ok want !ok", r)
	}

	if r, ok := muldiv64(0, 0, 0); ok {
		t.Errorf("muldiv64(0, 0, 0) got %d, ok want !ok", r)
	}
}

func TestMulDivOverflow(t *testing.T) {
	testCases := []struct {
		name string
		val  uint64
		mult uint64
		div  uint64
		ok   bool
		ret  uint64
	}{
		{
			name: "2^62",
			val:  1 << 63,
			mult: 4,
			div:  8,
			ok:   true,
			ret:  1 << 62,
		},
		{
			name: "2^64-1",
			val:  0xffffffffffffffff,
			mult: 1,
			div:  1,
			ok:   true,
			ret:  0xffffffffffffffff,
		},
		{
			name: "2^64",
			val:  1 << 63,
			mult: 4,
			div:  2,
			ok:   false,
		},
		{
			name: "2^125",
			val:  1 << 63,
			mult: 1 << 63,
			div:  2,
			ok:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := muldiv64(tc.val, tc.mult, tc.div)
			if ok != tc.ok {
				t.Errorf("ok got %v want %v", ok, tc.ok)
			}
			if tc.ok && r != tc.ret {
				t.Errorf("ret got %v want %v", r, tc.ret)
			}
		})
	}
}
