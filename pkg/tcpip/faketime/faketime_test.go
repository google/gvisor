// Copyright 2020 The gVisor Authors.
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

package faketime_test

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/faketime"
)

func TestManualClockAdvance(t *testing.T) {
	const timeout = time.Millisecond
	clock := faketime.NewManualClock()
	start := clock.NowMonotonicNS()
	clock.Advance(timeout)
	if got, want := time.Duration(clock.NowMonotonicNS()-start)*time.Nanosecond, timeout; got != want {
		t.Errorf("got = %d, want = %d", got, want)
	}
}

func TestManualClockAfterFunc(t *testing.T) {
	const (
		timeout1 = time.Millisecond     // timeout for counter1
		timeout2 = 2 * time.Millisecond // timeout for counter2
	)
	tests := []struct {
		name         string
		advance      time.Duration
		wantCounter1 int
		wantCounter2 int
	}{
		{
			name:         "before timeout1",
			advance:      timeout1 - 1,
			wantCounter1: 0,
			wantCounter2: 0,
		},
		{
			name:         "timeout1",
			advance:      timeout1,
			wantCounter1: 1,
			wantCounter2: 0,
		},
		{
			name:         "timeout2",
			advance:      timeout2,
			wantCounter1: 1,
			wantCounter2: 1,
		},
		{
			name:         "after timeout2",
			advance:      timeout2 + 1,
			wantCounter1: 1,
			wantCounter2: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			counter1 := 0
			counter2 := 0
			clock.AfterFunc(timeout1, func() {
				counter1++
			})
			clock.AfterFunc(timeout2, func() {
				counter2++
			})
			start := clock.NowMonotonicNS()
			clock.Advance(test.advance)
			if got, want := counter1, test.wantCounter1; got != want {
				t.Errorf("got counter1 = %d, want = %d", got, want)
			}
			if got, want := counter2, test.wantCounter2; got != want {
				t.Errorf("got counter2 = %d, want = %d", got, want)
			}
			if got, want := time.Duration(clock.NowMonotonicNS()-start)*time.Nanosecond, test.advance; got != want {
				t.Errorf("got elapsed = %d, want = %d", got, want)
			}
		})
	}
}
