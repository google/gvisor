// Copyright 2018 Google Inc.
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

package control

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/log"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
)

func init() {
	log.SetLevel(log.Debug)
}

// Tests that ProcessData.Table() prints with the correct format.
func TestProcessListTable(t *testing.T) {
	testCases := []struct {
		pl       []*Process
		expected string
	}{
		{
			pl:       []*Process{},
			expected: "UID       PID       PPID      C         STIME     TIME      CMD",
		},
		{
			pl: []*Process{
				{
					UID:   0,
					PID:   0,
					PPID:  0,
					C:     0,
					STime: "0",
					Time:  "0",
					Cmd:   "zero",
				},
				{
					UID:   1,
					PID:   1,
					PPID:  1,
					C:     1,
					STime: "1",
					Time:  "1",
					Cmd:   "one",
				},
			},
			expected: `UID       PID       PPID      C         STIME     TIME      CMD
0         0         0         0         0         0         zero
1         1         1         1         1         1         one`,
		},
	}

	for _, tc := range testCases {
		output := ProcessListToTable(tc.pl)

		if tc.expected != output {
			t.Errorf("PrintTable(%v): got:\n%s\nwant:\n%s", tc.pl, output, tc.expected)
		}
	}
}

func TestProcessListJSON(t *testing.T) {
	testCases := []struct {
		pl       []*Process
		expected string
	}{
		{
			pl:       []*Process{},
			expected: "[]",
		},
		{
			pl: []*Process{
				{
					UID:   0,
					PID:   0,
					PPID:  0,
					C:     0,
					STime: "0",
					Time:  "0",
					Cmd:   "zero",
				},
				{
					UID:   1,
					PID:   1,
					PPID:  1,
					C:     1,
					STime: "1",
					Time:  "1",
					Cmd:   "one",
				},
			},
			expected: "[0,1]",
		},
	}

	for _, tc := range testCases {
		output, err := PrintPIDsJSON(tc.pl)
		if err != nil {
			t.Errorf("failed to generate JSON: %v", err)
		}

		if tc.expected != output {
			t.Errorf("PrintJSON(%v): got:\n%s\nwant:\n%s", tc.pl, output, tc.expected)
		}
	}
}

func TestPercentCPU(t *testing.T) {
	testCases := []struct {
		stats     usage.CPUStats
		startTime ktime.Time
		now       ktime.Time
		expected  int32
	}{
		{
			// Verify that 100% use is capped at 99.
			stats:     usage.CPUStats{UserTime: 1e9, SysTime: 1e9},
			startTime: ktime.FromNanoseconds(7e9),
			now:       ktime.FromNanoseconds(9e9),
			expected:  99,
		},
		{
			// Verify that if usage > lifetime, we get at most 99%
			// usage.
			stats:     usage.CPUStats{UserTime: 2e9, SysTime: 2e9},
			startTime: ktime.FromNanoseconds(7e9),
			now:       ktime.FromNanoseconds(9e9),
			expected:  99,
		},
		{
			// Verify that 50% usage is reported correctly.
			stats:     usage.CPUStats{UserTime: 1e9, SysTime: 1e9},
			startTime: ktime.FromNanoseconds(12e9),
			now:       ktime.FromNanoseconds(16e9),
			expected:  50,
		},
		{
			// Verify that 0% usage is reported correctly.
			stats:     usage.CPUStats{UserTime: 0, SysTime: 0},
			startTime: ktime.FromNanoseconds(12e9),
			now:       ktime.FromNanoseconds(14e9),
			expected:  0,
		},
	}

	for _, tc := range testCases {
		if pcpu := percentCPU(tc.stats, tc.startTime, tc.now); pcpu != tc.expected {
			t.Errorf("percentCPU(%v, %v, %v): got %d, want %d", tc.stats, tc.startTime, tc.now, pcpu, tc.expected)
		}
	}
}
