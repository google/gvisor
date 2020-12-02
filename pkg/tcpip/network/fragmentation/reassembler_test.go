// Copyright 2018 The gVisor Authors.
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

package fragmentation

import (
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
)

type updateHolesParams struct {
	first     uint16
	last      uint16
	more      bool
	wantUsed  bool
	wantError error
}

func TestUpdateHoles(t *testing.T) {
	var tests = []struct {
		name   string
		params []updateHolesParams
		want   []hole
	}{
		{
			name:   "No fragments",
			params: nil,
			want:   []hole{{first: 0, last: math.MaxUint16, filled: false}},
		},
		{
			name:   "One fragment at beginning",
			params: []updateHolesParams{{first: 0, last: 1, more: true, wantUsed: true, wantError: nil}},
			want: []hole{
				{first: 0, last: 1, filled: true},
				{first: 2, last: math.MaxUint16, filled: false},
			},
		},
		{
			name:   "One fragment in the middle",
			params: []updateHolesParams{{first: 1, last: 2, more: true, wantUsed: true, wantError: nil}},
			want: []hole{
				{first: 1, last: 2, filled: true},
				{first: 0, last: 0, filled: false},
				{first: 3, last: math.MaxUint16, filled: false},
			},
		},
		{
			name:   "One fragment at the end",
			params: []updateHolesParams{{first: 1, last: 2, more: false, wantUsed: true, wantError: nil}},
			want: []hole{
				{first: 1, last: 2, filled: true},
				{first: 0, last: 0, filled: false},
			},
		},
		{
			name:   "One fragment completing a packet",
			params: []updateHolesParams{{first: 0, last: 1, more: false, wantUsed: true, wantError: nil}},
			want: []hole{
				{first: 0, last: 1, filled: true},
			},
		},
		{
			name: "Two fragments completing a packet",
			params: []updateHolesParams{
				{first: 0, last: 1, more: true, wantUsed: true, wantError: nil},
				{first: 2, last: 3, more: false, wantUsed: true, wantError: nil},
			},
			want: []hole{
				{first: 0, last: 1, filled: true},
				{first: 2, last: 3, filled: true},
			},
		},
		{
			name: "Two fragments completing a packet with a duplicate",
			params: []updateHolesParams{
				{first: 0, last: 1, more: true, wantUsed: true, wantError: nil},
				{first: 0, last: 1, more: true, wantUsed: false, wantError: nil},
				{first: 2, last: 3, more: false, wantUsed: true, wantError: nil},
			},
			want: []hole{
				{first: 0, last: 1, filled: true},
				{first: 2, last: 3, filled: true},
			},
		},
		{
			name: "Two overlapping fragments",
			params: []updateHolesParams{
				{first: 0, last: 10, more: true, wantUsed: true, wantError: nil},
				{first: 5, last: 15, more: false, wantUsed: false, wantError: ErrFragmentOverlap},
				{first: 11, last: 15, more: false, wantUsed: true, wantError: nil},
			},
			want: []hole{
				{first: 0, last: 10, filled: true},
				{first: 11, last: 15, filled: true},
			},
		},
		{
			name: "Out of bounds fragment",
			params: []updateHolesParams{
				{first: 0, last: 10, more: true, wantUsed: true, wantError: nil},
				{first: 11, last: 15, more: false, wantUsed: true, wantError: nil},
				{first: 16, last: 20, more: false, wantUsed: false, wantError: nil},
			},
			want: []hole{
				{first: 0, last: 10, filled: true},
				{first: 11, last: 15, filled: true},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := newReassembler(FragmentID{}, &faketime.NullClock{})
			for _, param := range test.params {
				used, err := r.updateHoles(param.first, param.last, param.more)
				if used != param.wantUsed || err != param.wantError {
					t.Errorf("got r.updateHoles(%d, %d, %t) = (%t, %v), want = (%t, %v)", param.first, param.last, param.more, used, err, param.wantUsed, param.wantError)
				}
			}
			if diff := cmp.Diff(test.want, r.holes, cmp.AllowUnexported(hole{})); diff != "" {
				t.Errorf("r.holes mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
