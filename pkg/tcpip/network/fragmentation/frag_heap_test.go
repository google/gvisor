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
	want    buffer.VectorisedView
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
		t.Run(c.comment, func(t *testing.T) {
			h := make(fragHeap, 0, 8)
			heap.Init(&h)
			for _, f := range c.in {
				heap.Push(&h, f)
			}
			got, err := h.reassemble()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got reassemble(%+v) = %v, want = %v", c.in, got, c.want)
			}
		})
	}
}

func TestReassambleFailsForNonZeroOffset(t *testing.T) {
	h := make(fragHeap, 0, 8)
	heap.Init(&h)
	heap.Push(&h, fragment{offset: 1, vv: vv(1, "0")})
	_, err := h.reassemble()
	if err == nil {
		t.Errorf("reassemble() did not fail when the first packet had offset != 0")
	}
}

func TestReassambleFailsForHoles(t *testing.T) {
	h := make(fragHeap, 0, 8)
	heap.Init(&h)
	heap.Push(&h, fragment{offset: 0, vv: vv(1, "0")})
	heap.Push(&h, fragment{offset: 2, vv: vv(1, "1")})
	_, err := h.reassemble()
	if err == nil {
		t.Errorf("reassemble() did not fail when there was a hole in the packet")
	}
}
