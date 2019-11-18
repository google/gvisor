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

package boot

import (
	"testing"
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
		name   string
		idx    []int
		arg1_1 uint64
		arg1_2 uint64
		arg2_1 uint64
		arg2_2 uint64
		want   bool
	}{
		{name: "same arg1", idx: []int{0}, arg1_1: 123, arg1_2: 123, want: false},
		{name: "same arg2", idx: []int{1}, arg2_1: 123, arg2_2: 123, want: false},
		{name: "diff arg1", idx: []int{0}, arg1_1: 123, arg1_2: 321, want: true},
		{name: "diff arg2", idx: []int{1}, arg2_1: 123, arg2_2: 321, want: true},
		{name: "cmd is uint32", idx: []int{0}, arg2_1: 0xdead00000123, arg2_2: 0xbeef00000123, want: false},
		{name: "same 2 args", idx: []int{0, 1}, arg2_1: 123, arg1_1: 321, arg2_2: 123, arg1_2: 321, want: false},
		{name: "diff 2 args", idx: []int{0, 1}, arg2_1: 123, arg1_1: 321, arg2_2: 789, arg1_2: 987, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newArgsTracker(tc.idx...)
			regs := newRegs()
			setArgVal(0, tc.arg1_1, regs)
			setArgVal(1, tc.arg2_1, regs)
			if !c.shouldReport(regs) {
				t.Error("first call to shouldReport, got: false, want: true")
			}
			c.onReported(regs)

			setArgVal(0, tc.arg1_2, regs)
			setArgVal(1, tc.arg2_2, regs)
			if got := c.shouldReport(regs); tc.want != got {
				t.Errorf("second call to shouldReport, got: %t, want: %t", got, tc.want)
			}
		})
	}
}

func TestArgsTrackerLimit(t *testing.T) {
	c := newArgsTracker(0, 1)
	for i := 0; i < reportLimit; i++ {
		regs := newRegs()
		setArgVal(0, 123, regs)
		setArgVal(1, uint64(i), regs)
		if !c.shouldReport(regs) {
			t.Error("shouldReport before limit was reached, got: false, want: true")
		}
		c.onReported(regs)
	}

	// Should hit the count limit now.
	regs := newRegs()
	setArgVal(0, 123, regs)
	setArgVal(1, 123456, regs)
	if c.shouldReport(regs) {
		t.Error("shouldReport after limit was reached, got: true, want: false")
	}
}
