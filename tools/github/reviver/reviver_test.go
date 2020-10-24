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

package reviver

import (
	"testing"
)

func TestProcessLine(t *testing.T) {
	for _, tc := range []struct {
		line string
		want *Todo
	}{
		{
			line: "// TODO(foobar.com/issue/123): comment, bla. blabla.",
			want: &Todo{
				Issue: "foobar.com/issue/123",
				Locations: []Location{
					{Comment: "comment, bla. blabla."},
				},
			},
		},
		{
			line: "// TODO(foobar.com/issues/123): comment, bla. blabla.",
			want: &Todo{
				Issue: "foobar.com/issues/123",
				Locations: []Location{
					{Comment: "comment, bla. blabla."},
				},
			},
		},
		{
			line: "// FIXME(b/123): internal bug",
			want: &Todo{
				Issue: "b/123",
				Locations: []Location{
					{Comment: "internal bug"},
				},
			},
		},
		{
			line: "TODO(issue): not todo",
		},
		{
			line: "FIXME(issue): not todo",
		},
		{
			line: "// TODO (issue): not todo",
		},
		{
			line: "// TODO(issue) not todo",
		},
		{
			line: "// todo(issue): not todo",
		},
		{
			line: "// TODO(issue):",
		},
	} {
		t.Logf("Testing: %s", tc.line)
		r := Reviver{}
		got := r.processLine(tc.line, "test", 0)
		if got == nil {
			if tc.want != nil {
				t.Errorf("failed to process line, want: %+v", tc.want)
			}
		} else {
			if tc.want == nil {
				t.Errorf("expected error, got: %+v", got)
				continue
			}
			if got.Issue != tc.want.Issue {
				t.Errorf("wrong issue, got: %v, want: %v", got.Issue, tc.want.Issue)
			}
			if len(got.Locations) != len(tc.want.Locations) {
				t.Errorf("wrong number of locations, got: %v, want: %v, locations: %+v", len(got.Locations), len(tc.want.Locations), got.Locations)
			}
			for i, wantLoc := range tc.want.Locations {
				if got.Locations[i].Comment != wantLoc.Comment {
					t.Errorf("wrong comment, got: %v, want: %v", got.Locations[i].Comment, wantLoc.Comment)
				}
			}
		}
	}
}
