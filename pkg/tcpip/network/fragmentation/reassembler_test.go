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
	"reflect"
	"testing"
)

type updateHolesInput struct {
	first uint16
	last  uint16
	more  bool
}

var holesTestCases = []struct {
	comment string
	in      []updateHolesInput
	want    []hole
}{
	{
		comment: "No fragments. Expected holes: {[0 -> inf]}.",
		in:      []updateHolesInput{},
		want:    []hole{{first: 0, last: math.MaxUint16, deleted: false}},
	},
	{
		comment: "One fragment at beginning. Expected holes: {[2, inf]}.",
		in:      []updateHolesInput{{first: 0, last: 1, more: true}},
		want: []hole{
			{first: 0, last: math.MaxUint16, deleted: true},
			{first: 2, last: math.MaxUint16, deleted: false},
		},
	},
	{
		comment: "One fragment in the middle. Expected holes: {[0, 0], [3, inf]}.",
		in:      []updateHolesInput{{first: 1, last: 2, more: true}},
		want: []hole{
			{first: 0, last: math.MaxUint16, deleted: true},
			{first: 0, last: 0, deleted: false},
			{first: 3, last: math.MaxUint16, deleted: false},
		},
	},
	{
		comment: "One fragment at the end. Expected holes: {[0, 0]}.",
		in:      []updateHolesInput{{first: 1, last: 2, more: false}},
		want: []hole{
			{first: 0, last: math.MaxUint16, deleted: true},
			{first: 0, last: 0, deleted: false},
		},
	},
	{
		comment: "One fragment completing a packet. Expected holes: {}.",
		in:      []updateHolesInput{{first: 0, last: 1, more: false}},
		want: []hole{
			{first: 0, last: math.MaxUint16, deleted: true},
		},
	},
	{
		comment: "Two non-overlapping fragments completing a packet. Expected holes: {}.",
		in: []updateHolesInput{
			{first: 0, last: 1, more: true},
			{first: 2, last: 3, more: false},
		},
		want: []hole{
			{first: 0, last: math.MaxUint16, deleted: true},
			{first: 2, last: math.MaxUint16, deleted: true},
		},
	},
	{
		comment: "Two overlapping fragments completing a packet. Expected holes: {}.",
		in: []updateHolesInput{
			{first: 0, last: 2, more: true},
			{first: 2, last: 3, more: false},
		},
		want: []hole{
			{first: 0, last: math.MaxUint16, deleted: true},
			{first: 3, last: math.MaxUint16, deleted: true},
		},
	},
}

func TestUpdateHoles(t *testing.T) {
	for _, c := range holesTestCases {
		r := newReassembler(0)
		for _, i := range c.in {
			r.updateHoles(i.first, i.last, i.more)
		}
		if !reflect.DeepEqual(r.holes, c.want) {
			t.Errorf("Test \"%s\" produced unexepetced holes. Got %v. Want %v", c.comment, r.holes, c.want)
		}
	}
}
