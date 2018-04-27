// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fragmentation

import (
	"reflect"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
)

// vv is a helper to build VectorisedView from different strings.
func vv(size int, pieces ...string) *buffer.VectorisedView {
	views := make([]buffer.View, len(pieces))
	for i, p := range pieces {
		views[i] = []byte(p)
	}

	vv := buffer.NewVectorisedView(size, views)
	return &vv
}

func emptyVv() *buffer.VectorisedView {
	vv := buffer.NewVectorisedView(0, nil)
	return &vv
}

type processInput struct {
	id    uint32
	first uint16
	last  uint16
	more  bool
	vv    *buffer.VectorisedView
}

type processOutput struct {
	vv   *buffer.VectorisedView
	done bool
}

var processTestCases = []struct {
	comment string
	in      []processInput
	out     []processOutput
}{
	{
		comment: "One ID",
		in: []processInput{
			{id: 0, first: 0, last: 1, more: true, vv: vv(2, "01")},
			{id: 0, first: 2, last: 3, more: false, vv: vv(2, "23")},
		},
		out: []processOutput{
			{vv: emptyVv(), done: false},
			{vv: vv(4, "01", "23"), done: true},
		},
	},
	{
		comment: "Two IDs",
		in: []processInput{
			{id: 0, first: 0, last: 1, more: true, vv: vv(2, "01")},
			{id: 1, first: 0, last: 1, more: true, vv: vv(2, "ab")},
			{id: 1, first: 2, last: 3, more: false, vv: vv(2, "cd")},
			{id: 0, first: 2, last: 3, more: false, vv: vv(2, "23")},
		},
		out: []processOutput{
			{vv: emptyVv(), done: false},
			{vv: emptyVv(), done: false},
			{vv: vv(4, "ab", "cd"), done: true},
			{vv: vv(4, "01", "23"), done: true},
		},
	},
}

func TestFragmentationProcess(t *testing.T) {
	for _, c := range processTestCases {
		f := NewFragmentation(1024, 512, DefaultReassembleTimeout)
		for i, in := range c.in {
			vv, done := f.Process(in.id, in.first, in.last, in.more, in.vv)
			if !reflect.DeepEqual(vv, *(c.out[i].vv)) {
				t.Errorf("Test \"%s\" Process() returned a wrong vv. Got %v. Want %v", c.comment, vv, *(c.out[i].vv))
			}
			if done != c.out[i].done {
				t.Errorf("Test \"%s\" Process() returned a wrong done. Got %t. Want %t", c.comment, done, c.out[i].done)
			}
			if c.out[i].done {
				if _, ok := f.reassemblers[in.id]; ok {
					t.Errorf("Test \"%s\" Process() didn't remove buffer from reassemblers.", c.comment)
				}
				for n := f.rList.Front(); n != nil; n = n.Next() {
					if n.id == in.id {
						t.Errorf("Test \"%s\" Process() didn't remove buffer from rList.", c.comment)
					}
				}
			}
		}
	}
}

func TestReassemblingTimeout(t *testing.T) {
	timeout := time.Millisecond
	f := NewFragmentation(1024, 512, timeout)
	// Send first fragment with id = 0, first = 0, last = 0, and more = true.
	f.Process(0, 0, 0, true, vv(1, "0"))
	// Sleep more than the timeout.
	time.Sleep(2 * timeout)
	// Send another fragment that completes a packet.
	// However, no packet should be reassembled because the fragment arrived after the timeout.
	_, done := f.Process(0, 1, 1, false, vv(1, "1"))
	if done {
		t.Errorf("Fragmentation does not respect the reassembling timeout.")
	}
}

func TestMemoryLimits(t *testing.T) {
	f := NewFragmentation(3, 1, DefaultReassembleTimeout)
	// Send first fragment with id = 0.
	f.Process(0, 0, 0, true, vv(1, "0"))
	// Send first fragment with id = 1.
	f.Process(1, 0, 0, true, vv(1, "1"))
	// Send first fragment with id = 2.
	f.Process(2, 0, 0, true, vv(1, "2"))

	// Send first fragment with id = 3. This should caused id = 0 and id = 1 to be
	// evicted.
	f.Process(3, 0, 0, true, vv(1, "3"))

	if _, ok := f.reassemblers[0]; ok {
		t.Errorf("Memory limits are not respected: id=0 has not been evicted.")
	}
	if _, ok := f.reassemblers[1]; ok {
		t.Errorf("Memory limits are not respected: id=1 has not been evicted.")
	}
	if _, ok := f.reassemblers[3]; !ok {
		t.Errorf("Implementation of memory limits is wrong: id=3 is not present.")
	}
}

func TestMemoryLimitsIgnoresDuplicates(t *testing.T) {
	f := NewFragmentation(1, 0, DefaultReassembleTimeout)
	// Send first fragment with id = 0.
	f.Process(0, 0, 0, true, vv(1, "0"))
	// Send the same packet again.
	f.Process(0, 0, 0, true, vv(1, "0"))

	got := f.size
	want := 1
	if got != want {
		t.Errorf("Wrong size, duplicates are not handled correctly: got=%d, want=%d.", got, want)
	}
}

func TestFragmentationViewsDoNotEscape(t *testing.T) {
	f := NewFragmentation(1024, 512, DefaultReassembleTimeout)
	in := vv(2, "0", "1")
	f.Process(0, 0, 1, true, in)
	// Modify input view.
	in.RemoveFirst()
	got, _ := f.Process(0, 2, 2, false, vv(1, "2"))
	want := vv(3, "0", "1", "2")
	if !reflect.DeepEqual(got, *want) {
		t.Errorf("Process() returned a wrong vv. Got %v. Want %v", got, *want)
	}
}
