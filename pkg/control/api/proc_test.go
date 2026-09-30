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

package api

import (
	"testing"
)

// Tests that ProcessData.Table() prints with the correct format.
func TestProcessListTable(t *testing.T) {
	testCases := []struct {
		pl       []*Process
		expected string
	}{
		{
			pl:       []*Process{},
			expected: "UID       PID       PPID      PGID      C         TTY       STIME     TIME      CMD",
		},
		{
			pl: []*Process{
				{
					UID:   0,
					PID:   0,
					PPID:  0,
					PGID:  0,
					C:     0,
					TTY:   "?",
					STime: "0",
					Time:  "0",
					Cmd:   "zero",
				},
				{
					UID:   1,
					PID:   1,
					PPID:  1,
					PGID:  1,
					C:     1,
					TTY:   "pts/4",
					STime: "1",
					Time:  "1",
					Cmd:   "one",
				},
			},
			expected: `UID       PID       PPID      PGID      C         TTY       STIME     TIME      CMD
0         0         0         0         0         ?         0         0         zero
1         1         1         1         1         pts/4     1         1         one`,
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
