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
	"errors"
	"reflect"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

// vv is a helper to build VectorisedView from different strings.
func vv(size int, pieces ...string) buffer.VectorisedView {
	views := make([]buffer.View, len(pieces))
	for i, p := range pieces {
		views[i] = []byte(p)
	}

	return buffer.NewVectorisedView(size, views)
}

type processInput struct {
	id    FragmentID
	first uint16
	last  uint16
	more  bool
	vv    buffer.VectorisedView
}

type processOutput struct {
	vv   buffer.VectorisedView
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
			{id: FragmentID{ID: 0}, first: 0, last: 1, more: true, vv: vv(2, "01")},
			{id: FragmentID{ID: 0}, first: 2, last: 3, more: false, vv: vv(2, "23")},
		},
		out: []processOutput{
			{vv: buffer.VectorisedView{}, done: false},
			{vv: vv(4, "01", "23"), done: true},
		},
	},
	{
		comment: "Two IDs",
		in: []processInput{
			{id: FragmentID{ID: 0}, first: 0, last: 1, more: true, vv: vv(2, "01")},
			{id: FragmentID{ID: 1}, first: 0, last: 1, more: true, vv: vv(2, "ab")},
			{id: FragmentID{ID: 1}, first: 2, last: 3, more: false, vv: vv(2, "cd")},
			{id: FragmentID{ID: 0}, first: 2, last: 3, more: false, vv: vv(2, "23")},
		},
		out: []processOutput{
			{vv: buffer.VectorisedView{}, done: false},
			{vv: buffer.VectorisedView{}, done: false},
			{vv: vv(4, "ab", "cd"), done: true},
			{vv: vv(4, "01", "23"), done: true},
		},
	},
}

func TestFragmentationProcess(t *testing.T) {
	for _, c := range processTestCases {
		t.Run(c.comment, func(t *testing.T) {
			f := NewFragmentation(minBlockSize, 1024, 512, DefaultReassembleTimeout)
			for i, in := range c.in {
				vv, done, err := f.Process(in.id, in.first, in.last, in.more, in.vv)
				if err != nil {
					t.Fatalf("f.Process(%+v, %+d, %+d, %t, %+v) failed: %v", in.id, in.first, in.last, in.more, in.vv, err)
				}
				if !reflect.DeepEqual(vv, c.out[i].vv) {
					t.Errorf("got Process(%d) = %+v, want = %+v", i, vv, c.out[i].vv)
				}
				if done != c.out[i].done {
					t.Errorf("got Process(%d) = %+v, want = %+v", i, done, c.out[i].done)
				}
				if c.out[i].done {
					if _, ok := f.reassemblers[in.id]; ok {
						t.Errorf("Process(%d) did not remove buffer from reassemblers", i)
					}
					for n := f.rList.Front(); n != nil; n = n.Next() {
						if n.id == in.id {
							t.Errorf("Process(%d) did not remove buffer from rList", i)
						}
					}
				}
			}
		})
	}
}

func TestReassemblingTimeout(t *testing.T) {
	timeout := time.Millisecond
	f := NewFragmentation(minBlockSize, 1024, 512, timeout)
	// Send first fragment with id = 0, first = 0, last = 0, and more = true.
	f.Process(FragmentID{}, 0, 0, true, vv(1, "0"))
	// Sleep more than the timeout.
	time.Sleep(2 * timeout)
	// Send another fragment that completes a packet.
	// However, no packet should be reassembled because the fragment arrived after the timeout.
	_, done, err := f.Process(FragmentID{}, 1, 1, false, vv(1, "1"))
	if err != nil {
		t.Fatalf("f.Process(0, 1, 1, false, vv(1, \"1\")) failed: %v", err)
	}
	if done {
		t.Errorf("Fragmentation does not respect the reassembling timeout.")
	}
}

func TestMemoryLimits(t *testing.T) {
	f := NewFragmentation(minBlockSize, 3, 1, DefaultReassembleTimeout)
	// Send first fragment with id = 0.
	f.Process(FragmentID{ID: 0}, 0, 0, true, vv(1, "0"))
	// Send first fragment with id = 1.
	f.Process(FragmentID{ID: 1}, 0, 0, true, vv(1, "1"))
	// Send first fragment with id = 2.
	f.Process(FragmentID{ID: 2}, 0, 0, true, vv(1, "2"))

	// Send first fragment with id = 3. This should caused id = 0 and id = 1 to be
	// evicted.
	f.Process(FragmentID{ID: 3}, 0, 0, true, vv(1, "3"))

	if _, ok := f.reassemblers[FragmentID{ID: 0}]; ok {
		t.Errorf("Memory limits are not respected: id=0 has not been evicted.")
	}
	if _, ok := f.reassemblers[FragmentID{ID: 1}]; ok {
		t.Errorf("Memory limits are not respected: id=1 has not been evicted.")
	}
	if _, ok := f.reassemblers[FragmentID{ID: 3}]; !ok {
		t.Errorf("Implementation of memory limits is wrong: id=3 is not present.")
	}
}

func TestMemoryLimitsIgnoresDuplicates(t *testing.T) {
	f := NewFragmentation(minBlockSize, 1, 0, DefaultReassembleTimeout)
	// Send first fragment with id = 0.
	f.Process(FragmentID{}, 0, 0, true, vv(1, "0"))
	// Send the same packet again.
	f.Process(FragmentID{}, 0, 0, true, vv(1, "0"))

	got := f.size
	want := 1
	if got != want {
		t.Errorf("Wrong size, duplicates are not handled correctly: got=%d, want=%d.", got, want)
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name      string
		blockSize uint16
		first     uint16
		last      uint16
		more      bool
		data      string
		err       error
	}{
		{
			name:      "exact block size without more",
			blockSize: 2,
			first:     2,
			last:      3,
			more:      false,
			data:      "01",
		},
		{
			name:      "exact block size with more",
			blockSize: 2,
			first:     2,
			last:      3,
			more:      true,
			data:      "01",
		},
		{
			name:      "exact block size with more and extra data",
			blockSize: 2,
			first:     2,
			last:      3,
			more:      true,
			data:      "012",
		},
		{
			name:      "exact block size with more and too little data",
			blockSize: 2,
			first:     2,
			last:      3,
			more:      true,
			data:      "0",
			err:       ErrInvalidArgs,
		},
		{
			name:      "not exact block size with more",
			blockSize: 2,
			first:     2,
			last:      2,
			more:      true,
			data:      "0",
			err:       ErrInvalidArgs,
		},
		{
			name:      "not exact block size without more",
			blockSize: 2,
			first:     2,
			last:      2,
			more:      false,
			data:      "0",
		},
		{
			name:      "first not a multiple of block size",
			blockSize: 2,
			first:     3,
			last:      4,
			more:      true,
			data:      "01",
			err:       ErrInvalidArgs,
		},
		{
			name:      "first more than last",
			blockSize: 2,
			first:     4,
			last:      3,
			more:      true,
			data:      "01",
			err:       ErrInvalidArgs,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := NewFragmentation(test.blockSize, HighFragThreshold, LowFragThreshold, DefaultReassembleTimeout)
			_, done, err := f.Process(FragmentID{}, test.first, test.last, test.more, vv(len(test.data), test.data))
			if !errors.Is(err, test.err) {
				t.Errorf("got Proceess(_, %d, %d, %t, %q) = (_, _, %v), want = (_, _, %v)", test.first, test.last, test.more, test.data, err, test.err)
			}
			if done {
				t.Errorf("got Proceess(_, %d, %d, %t, %q) = (_, true, _), want = (_, false, _)", test.first, test.last, test.more, test.data)
			}
		})
	}
}
