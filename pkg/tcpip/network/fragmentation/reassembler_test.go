// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
