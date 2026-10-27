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

package cmd

import (
	"errors"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIDMapSlice(t *testing.T) {
	for _, tc := range []struct {
		input   string
		want    idMapSlice
		wantErr error
	}{
		{input: "0 1000 1", want: idMapSlice{{ContainerID: 0, HostID: 1000, Size: 1}}},
		{input: "2147483648 4294967294 1", want: idMapSlice{{ContainerID: 2147483648, HostID: 4294967294, Size: 1}}},
		{input: "0 0 4294967295", want: idMapSlice{{ContainerID: 0, HostID: 0, Size: 4294967295}}},
		{input: "0 1000 1,100 2000 10", want: idMapSlice{{ContainerID: 0, HostID: 1000, Size: 1}, {ContainerID: 100, HostID: 2000, Size: 10}}},
		{input: "foo 1000 1", wantErr: strconv.ErrSyntax},
		{input: "0 foo 1", wantErr: strconv.ErrSyntax},
		{input: "0 1000 foo", wantErr: strconv.ErrSyntax},
		{input: "-1 1000 1", wantErr: strconv.ErrSyntax},
		{input: "0 -1 1", wantErr: strconv.ErrSyntax},
		{input: "0 1000 -1", wantErr: strconv.ErrSyntax},
		{input: "4294967296 1000 1", wantErr: strconv.ErrRange},
		{input: "0 4294967296 1", wantErr: strconv.ErrRange},
		{input: "0 1000 4294967297", wantErr: strconv.ErrRange},
	} {
		t.Run(tc.input, func(t *testing.T) {
			var got idMapSlice
			if err := got.Set(tc.input); !errors.Is(err, tc.wantErr) {
				t.Errorf("Set(%q): got error %v, want %v", tc.input, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Set(%q): unexpected mappings (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}
