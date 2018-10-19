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

package cgroup

import (
	"testing"
)

func TestCountCpuset(t *testing.T) {
	for _, tc := range []struct {
		str   string
		want  int
		error bool
	}{
		{str: "0", want: 1},
		{str: "0,1,2,8,9,10", want: 6},
		{str: "0-1", want: 2},
		{str: "0-7", want: 8},
		{str: "0-7,16,32-39,64,65", want: 19},
		{str: "a", error: true},
		{str: "5-a", error: true},
		{str: "a-5", error: true},
		{str: "-10", error: true},
		{str: "15-", error: true},
		{str: "-", error: true},
		{str: "--", error: true},
	} {
		t.Run(tc.str, func(t *testing.T) {
			got, err := countCpuset(tc.str)
			if tc.error {
				if err == nil {
					t.Errorf("countCpuset(%q) should have failed", tc.str)
				}
			} else {
				if err != nil {
					t.Errorf("countCpuset(%q) failed: %v", tc.str, err)
				}
				if tc.want != got {
					t.Errorf("countCpuset(%q) want: %d, got: %d", tc.str, tc.want, got)
				}
			}
		})
	}
}
