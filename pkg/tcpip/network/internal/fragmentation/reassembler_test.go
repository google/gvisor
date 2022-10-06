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
	"bytes"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type processParams struct {
	first     uint16
	last      uint16
	more      bool
	pkt       stack.PacketBufferPtr
	wantDone  bool
	wantError error
}

func TestReassemblerProcess(t *testing.T) {
	const proto = 99

	v := func(size int) *bufferv2.View {
		payload := bufferv2.NewViewSize(size)
		for i := 1; i < size; i++ {
			payload.WriteAt([]byte{uint8(i) * 3}, i)
		}
		return payload
	}

	pkt := func(sizes ...int) stack.PacketBufferPtr {
		var buf bufferv2.Buffer
		for _, size := range sizes {
			buf.Append(v(size))
		}
		return stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buf,
		})
	}

	var tests = []struct {
		name    string
		params  []processParams
		want    []hole
		wantPkt stack.PacketBufferPtr
	}{
		{
			name:   "No fragments",
			params: nil,
			want:   []hole{{first: 0, last: math.MaxUint16, filled: false, final: true}},
		},
		{
			name:   "One fragment at beginning",
			params: []processParams{{first: 0, last: 1, more: true, pkt: pkt(2), wantDone: false, wantError: nil}},
			want: []hole{
				{first: 0, last: 1, filled: true, final: false, pkt: pkt(2)},
				{first: 2, last: math.MaxUint16, filled: false, final: true},
			},
		},
		{
			name:   "One fragment in the middle",
			params: []processParams{{first: 1, last: 2, more: true, pkt: pkt(2), wantDone: false, wantError: nil}},
			want: []hole{
				{first: 1, last: 2, filled: true, final: false, pkt: pkt(2)},
				{first: 0, last: 0, filled: false, final: false},
				{first: 3, last: math.MaxUint16, filled: false, final: true},
			},
		},
		{
			name:   "One fragment at the end",
			params: []processParams{{first: 1, last: 2, more: false, pkt: pkt(2), wantDone: false, wantError: nil}},
			want: []hole{
				{first: 1, last: 2, filled: true, final: true, pkt: pkt(2)},
				{first: 0, last: 0, filled: false},
			},
		},
		{
			name:   "One fragment completing a packet",
			params: []processParams{{first: 0, last: 1, more: false, pkt: pkt(2), wantDone: true, wantError: nil}},
			want: []hole{
				{first: 0, last: 1, filled: true, final: true},
			},
			wantPkt: pkt(2),
		},
		{
			name: "Two fragments completing a packet",
			params: []processParams{
				{first: 0, last: 1, more: true, pkt: pkt(2), wantDone: false, wantError: nil},
				{first: 2, last: 3, more: false, pkt: pkt(2), wantDone: true, wantError: nil},
			},
			want: []hole{
				{first: 0, last: 1, filled: true, final: false},
				{first: 2, last: 3, filled: true, final: true},
			},
			wantPkt: pkt(2, 2),
		},
		{
			name: "Two fragments completing a packet with a duplicate",
			params: []processParams{
				{first: 0, last: 1, more: true, pkt: pkt(2), wantDone: false, wantError: nil},
				{first: 0, last: 1, more: true, pkt: pkt(2), wantDone: false, wantError: nil},
				{first: 2, last: 3, more: false, pkt: pkt(2), wantDone: true, wantError: nil},
			},
			want: []hole{
				{first: 0, last: 1, filled: true, final: false},
				{first: 2, last: 3, filled: true, final: true},
			},
			wantPkt: pkt(2, 2),
		},
		{
			name: "Two fragments completing a packet with a partial duplicate",
			params: []processParams{
				{first: 0, last: 3, more: true, pkt: pkt(4), wantDone: false, wantError: nil},
				{first: 1, last: 2, more: true, pkt: pkt(2), wantDone: false, wantError: nil},
				{first: 4, last: 5, more: false, pkt: pkt(2), wantDone: true, wantError: nil},
			},
			want: []hole{
				{first: 0, last: 3, filled: true, final: false},
				{first: 4, last: 5, filled: true, final: true},
			},
			wantPkt: pkt(4, 2),
		},
		{
			name: "Two overlapping fragments",
			params: []processParams{
				{first: 0, last: 10, more: true, pkt: pkt(11), wantDone: false, wantError: nil},
				{first: 5, last: 15, more: false, pkt: pkt(11), wantDone: false, wantError: ErrFragmentOverlap},
			},
			want: []hole{
				{first: 0, last: 10, filled: true, final: false, pkt: pkt(11)},
				{first: 11, last: math.MaxUint16, filled: false, final: true},
			},
		},
		{
			name: "Two final fragments with different ends",
			params: []processParams{
				{first: 10, last: 14, more: false, pkt: pkt(5), wantDone: false, wantError: nil},
				{first: 0, last: 9, more: false, pkt: pkt(10), wantDone: false, wantError: ErrFragmentConflict},
			},
			want: []hole{
				{first: 10, last: 14, filled: true, final: true, pkt: pkt(5)},
				{first: 0, last: 9, filled: false, final: false},
			},
		},
		{
			name: "Two final fragments - duplicate",
			params: []processParams{
				{first: 5, last: 14, more: false, pkt: pkt(10), wantDone: false, wantError: nil},
				{first: 10, last: 14, more: false, pkt: pkt(5), wantDone: false, wantError: nil},
			},
			want: []hole{
				{first: 5, last: 14, filled: true, final: true, pkt: pkt(10)},
				{first: 0, last: 4, filled: false, final: false},
			},
		},
		{
			name: "Two final fragments - duplicate, with different ends",
			params: []processParams{
				{first: 5, last: 14, more: false, pkt: pkt(10), wantDone: false, wantError: nil},
				{first: 10, last: 13, more: false, pkt: pkt(4), wantDone: false, wantError: ErrFragmentConflict},
			},
			want: []hole{
				{first: 5, last: 14, filled: true, final: true, pkt: pkt(10)},
				{first: 0, last: 4, filled: false, final: false},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := newReassembler(FragmentID{}, &faketime.NullClock{})
			// Emulate a call to (*Fragmentation).release(), which always happens
			// after reassembler error or completion. Without release(), the
			// reassembler will leak PacketBuffers.
			defer func() {
				for _, h := range r.holes {
					if !h.pkt.IsNil() {
						h.pkt.DecRef()
					}
				}
				if !r.pkt.IsNil() {
					r.pkt.DecRef()
				}
			}()
			var resPkt stack.PacketBufferPtr
			var isDone bool
			for _, param := range test.params {
				pkt, _, done, _, err := r.process(param.first, param.last, param.more, proto, param.pkt)
				if !pkt.IsNil() {
					defer pkt.DecRef()
				}
				if done != param.wantDone || err != param.wantError {
					t.Errorf("got r.process(%d, %d, %t, %d, _) = (_, _, %t, _, %v), want = (%t, %v)", param.first, param.last, param.more, proto, done, err, param.wantDone, param.wantError)
				}
				if done {
					resPkt = pkt
					isDone = true
				}
			}

			ignorePkt := func(a, b stack.PacketBufferPtr) bool { return true }
			cmpPktData := func(a, b stack.PacketBufferPtr) bool {
				if a.IsNil() || b.IsNil() {
					return a == b
				}
				return bytes.Equal(a.Data().AsRange().ToSlice(), b.Data().AsRange().ToSlice())
			}

			if isDone {
				if diff := cmp.Diff(
					test.want, r.holes,
					cmp.AllowUnexported(hole{}),
					// Do not compare pkt in hole. Data will be altered.
					cmp.Comparer(ignorePkt),
				); diff != "" {
					t.Errorf("r.holes mismatch (-want +got):\n%s", diff)
				}
				if diff := cmp.Diff(test.wantPkt, resPkt, cmp.Comparer(cmpPktData)); diff != "" {
					t.Errorf("Reassembled pkt mismatch (-want +got):\n%s", diff)
				}
			} else {
				if diff := cmp.Diff(
					test.want, r.holes,
					cmp.AllowUnexported(hole{}),
					cmp.Comparer(cmpPktData),
				); diff != "" {
					t.Errorf("r.holes mismatch (-want +got):\n%s", diff)
				}
			}
		})
		for _, p := range test.params {
			if !p.pkt.IsNil() {
				p.pkt.DecRef()
			}
		}
		for _, w := range test.want {
			if !w.pkt.IsNil() {
				w.pkt.DecRef()
			}
		}
		if !test.wantPkt.IsNil() {
			test.wantPkt.DecRef()
		}
	}
}
