// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fragmentation

import (
	"container/heap"
	"reflect"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
)

var reassambleTestCases = []struct {
	comment string
	in      []fragment
	want    *buffer.VectorisedView
}{
	{
		comment: "Non-overlapping in-order",
		in: []fragment{
			{offset: 0, vv: vv(1, "0")},
			{offset: 1, vv: vv(1, "1")},
		},
		want: vv(2, "0", "1"),
	},
	{
		comment: "Non-overlapping out-of-order",
		in: []fragment{
			{offset: 1, vv: vv(1, "1")},
			{offset: 0, vv: vv(1, "0")},
		},
		want: vv(2, "0", "1"),
	},
	{
		comment: "Duplicated packets",
		in: []fragment{
			{offset: 0, vv: vv(1, "0")},
			{offset: 0, vv: vv(1, "0")},
		},
		want: vv(1, "0"),
	},
	{
		comment: "Overlapping in-order",
		in: []fragment{
			{offset: 0, vv: vv(2, "01")},
			{offset: 1, vv: vv(2, "12")},
		},
		want: vv(3, "01", "2"),
	},
	{
		comment: "Overlapping out-of-order",
		in: []fragment{
			{offset: 1, vv: vv(2, "12")},
			{offset: 0, vv: vv(2, "01")},
		},
		want: vv(3, "01", "2"),
	},
	{
		comment: "Overlapping subset in-order",
		in: []fragment{
			{offset: 0, vv: vv(3, "012")},
			{offset: 1, vv: vv(1, "1")},
		},
		want: vv(3, "012"),
	},
	{
		comment: "Overlapping subset out-of-order",
		in: []fragment{
			{offset: 1, vv: vv(1, "1")},
			{offset: 0, vv: vv(3, "012")},
		},
		want: vv(3, "012"),
	},
}

func TestReassamble(t *testing.T) {
	for _, c := range reassambleTestCases {
		h := (fragHeap)(make([]fragment, 0, 8))
		heap.Init(&h)
		for _, f := range c.in {
			heap.Push(&h, f)
		}
		got, _ := h.reassemble()

		if !reflect.DeepEqual(got, *c.want) {
			t.Errorf("Test \"%s\" reassembling failed. Got %v. Want %v", c.comment, got, *c.want)
		}
	}
}

func TestReassambleFailsForNonZeroOffset(t *testing.T) {
	h := (fragHeap)(make([]fragment, 0, 8))
	heap.Init(&h)
	heap.Push(&h, fragment{offset: 1, vv: vv(1, "0")})
	_, err := h.reassemble()
	if err == nil {
		t.Errorf("reassemble() did not fail when the first packet had offset != 0")
	}
}

func TestReassambleFailsForHoles(t *testing.T) {
	h := (fragHeap)(make([]fragment, 0, 8))
	heap.Init(&h)
	heap.Push(&h, fragment{offset: 0, vv: vv(1, "0")})
	heap.Push(&h, fragment{offset: 2, vv: vv(1, "1")})
	_, err := h.reassemble()
	if err == nil {
		t.Errorf("reassemble() did not fail when there was a hole in the packet")
	}
}
