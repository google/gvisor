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

package reviver

import (
	"testing"
)

func TestParseIssueNo(t *testing.T) {
	testCases := []struct {
		issue     string
		expectErr bool
		expected  int
	}{
		{
			issue:    "gvisor.dev/issue/123",
			expected: 123,
		},
		{
			issue:    "gvisor.dev/issue/123/",
			expected: 123,
		},
		{
			issue:    "not a url",
			expected: 0,
		},
		{
			issue:     "gvisor.dev/issue//",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.issue, func(t *testing.T) {
			id, err := parseIssueNo(tc.issue)
			if err != nil && !tc.expectErr {
				t.Errorf("got error: %v", err)
			} else if tc.expected != id {
				t.Errorf("got: %v, want: %v", id, tc.expected)
			}
		})
	}
}
