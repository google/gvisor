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

package boot

import (
	"testing"

	rpb "gvisor.googlesource.com/gvisor/pkg/sentry/arch/registers_go_proto"
)

func TestOnceTracker(t *testing.T) {
	o := onceTracker{}
	if !o.shouldReport(nil) {
		t.Error("first call to checkAndMark, got: false, want: true")
	}
	o.onReported(nil)
	for i := 0; i < 2; i++ {
		if o.shouldReport(nil) {
			t.Error("after first call to checkAndMark, got: true, want: false")
		}
	}
}

func TestArgsTracker(t *testing.T) {
	for _, tc := range []struct {
		name string
		idx  []int
		rdi1 uint64
		rdi2 uint64
		rsi1 uint64
		rsi2 uint64
		want bool
	}{
		{name: "same rdi", idx: []int{0}, rdi1: 123, rdi2: 123, want: false},
		{name: "same rsi", idx: []int{1}, rsi1: 123, rsi2: 123, want: false},
		{name: "diff rdi", idx: []int{0}, rdi1: 123, rdi2: 321, want: true},
		{name: "diff rsi", idx: []int{1}, rsi1: 123, rsi2: 321, want: true},
		{name: "cmd is uint32", idx: []int{0}, rsi1: 0xdead00000123, rsi2: 0xbeef00000123, want: false},
		{name: "same 2 args", idx: []int{0, 1}, rsi1: 123, rdi1: 321, rsi2: 123, rdi2: 321, want: false},
		{name: "diff 2 args", idx: []int{0, 1}, rsi1: 123, rdi1: 321, rsi2: 789, rdi2: 987, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newArgsTracker(tc.idx...)
			regs := &rpb.AMD64Registers{Rdi: tc.rdi1, Rsi: tc.rsi1}
			if !c.shouldReport(regs) {
				t.Error("first call to shouldReport, got: false, want: true")
			}
			c.onReported(regs)

			regs.Rdi, regs.Rsi = tc.rdi2, tc.rsi2
			if got := c.shouldReport(regs); tc.want != got {
				t.Errorf("second call to shouldReport, got: %t, want: %t", got, tc.want)
			}
		})
	}
}

func TestArgsTrackerLimit(t *testing.T) {
	c := newArgsTracker(0, 1)
	for i := 0; i < reportLimit; i++ {
		regs := &rpb.AMD64Registers{Rdi: 123, Rsi: uint64(i)}
		if !c.shouldReport(regs) {
			t.Error("shouldReport before limit was reached, got: false, want: true")
		}
		c.onReported(regs)
	}

	// Should hit the count limit now.
	regs := &rpb.AMD64Registers{Rdi: 123, Rsi: 123456}
	if c.shouldReport(regs) {
		t.Error("shouldReport after limit was reached, got: true, want: false")
	}
}
