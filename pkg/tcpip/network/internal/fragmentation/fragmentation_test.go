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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// reassembleTimeout is dummy timeout used for testing, where the clock never
// advances.
const reassembleTimeout = 1

// vv is a helper to build VectorisedView from different strings.
func vv(size int, pieces ...string) buffer.VectorisedView {
	views := make([]buffer.View, len(pieces))
	for i, p := range pieces {
		views[i] = []byte(p)
	}

	return buffer.NewVectorisedView(size, views)
}

func pkt(size int, pieces ...string) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: vv(size, pieces...),
	})
}

type processInput struct {
	id    FragmentID
	first uint16
	last  uint16
	more  bool
	proto uint8
	pkt   *stack.PacketBuffer
}

type processOutput struct {
	vv    buffer.VectorisedView
	proto uint8
	done  bool
}

var processTestCases = []struct {
	comment string
	in      []processInput
	out     []processOutput
}{
	{
		comment: "One ID",
		in: []processInput{
			{id: FragmentID{ID: 0}, first: 0, last: 1, more: true, pkt: pkt(2, "01")},
			{id: FragmentID{ID: 0}, first: 2, last: 3, more: false, pkt: pkt(2, "23")},
		},
		out: []processOutput{
			{vv: buffer.VectorisedView{}, done: false},
			{vv: vv(4, "01", "23"), done: true},
		},
	},
	{
		comment: "Next Header protocol mismatch",
		in: []processInput{
			{id: FragmentID{ID: 0}, first: 0, last: 1, more: true, proto: 6, pkt: pkt(2, "01")},
			{id: FragmentID{ID: 0}, first: 2, last: 3, more: false, proto: 17, pkt: pkt(2, "23")},
		},
		out: []processOutput{
			{vv: buffer.VectorisedView{}, done: false},
			{vv: vv(4, "01", "23"), proto: 6, done: true},
		},
	},
	{
		comment: "Two IDs",
		in: []processInput{
			{id: FragmentID{ID: 0}, first: 0, last: 1, more: true, pkt: pkt(2, "01")},
			{id: FragmentID{ID: 1}, first: 0, last: 1, more: true, pkt: pkt(2, "ab")},
			{id: FragmentID{ID: 1}, first: 2, last: 3, more: false, pkt: pkt(2, "cd")},
			{id: FragmentID{ID: 0}, first: 2, last: 3, more: false, pkt: pkt(2, "23")},
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
			f := NewFragmentation(minBlockSize, 1024, 512, reassembleTimeout, &faketime.NullClock{}, nil)
			firstFragmentProto := c.in[0].proto
			for i, in := range c.in {
				resPkt, proto, done, err := f.Process(in.id, in.first, in.last, in.more, in.proto, in.pkt)
				if err != nil {
					t.Fatalf("f.Process(%+v, %d, %d, %t, %d, %#v) failed: %s",
						in.id, in.first, in.last, in.more, in.proto, in.pkt, err)
				}
				if done != c.out[i].done {
					t.Errorf("got Process(%+v, %d, %d, %t, %d, _) = (_, _, %t, _), want = (_, _, %t, _)",
						in.id, in.first, in.last, in.more, in.proto, done, c.out[i].done)
				}
				if c.out[i].done {
					if diff := cmp.Diff(c.out[i].vv.ToOwnedView(), resPkt.Data.ToOwnedView()); diff != "" {
						t.Errorf("got Process(%+v, %d, %d, %t, %d, %#v) result mismatch (-want, +got):\n%s",
							in.id, in.first, in.last, in.more, in.proto, in.pkt, diff)
					}
					if firstFragmentProto != proto {
						t.Errorf("got Process(%+v, %d, %d, %t, %d, _) = (_, %d, _, _), want = (_, %d, _, _)",
							in.id, in.first, in.last, in.more, in.proto, proto, firstFragmentProto)
					}
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
	const (
		reassemblyTimeout = time.Millisecond
		protocol          = 0xff
	)

	type fragment struct {
		first uint16
		last  uint16
		more  bool
		data  string
	}

	type event struct {
		// name is a nickname of this event.
		name string

		// clockAdvance is a duration to advance the clock. The clock advances
		// before a fragment specified in the fragment field is processed.
		clockAdvance time.Duration

		// fragment is a fragment to process. This can be nil if there is no
		// fragment to process.
		fragment *fragment

		// expectDone is true if the fragmentation instance should report the
		// reassembly is done after the fragment is processd.
		expectDone bool

		// memSizeAfterEvent is the expected memory size of the fragmentation
		// instance after the event.
		memSizeAfterEvent int
	}

	memSizeOfFrags := func(frags ...*fragment) int {
		var size int
		for _, frag := range frags {
			size += pkt(len(frag.data), frag.data).MemSize()
		}
		return size
	}

	half1 := &fragment{first: 0, last: 0, more: true, data: "0"}
	half2 := &fragment{first: 1, last: 1, more: false, data: "1"}

	tests := []struct {
		name   string
		events []event
	}{
		{
			name: "half1 and half2 are reassembled successfully",
			events: []event{
				{
					name:              "half1",
					fragment:          half1,
					expectDone:        false,
					memSizeAfterEvent: memSizeOfFrags(half1),
				},
				{
					name:              "half2",
					fragment:          half2,
					expectDone:        true,
					memSizeAfterEvent: 0,
				},
			},
		},
		{
			name: "half1 timeout, half2 timeout",
			events: []event{
				{
					name:              "half1",
					fragment:          half1,
					expectDone:        false,
					memSizeAfterEvent: memSizeOfFrags(half1),
				},
				{
					name:              "half1 just before reassembly timeout",
					clockAdvance:      reassemblyTimeout - 1,
					memSizeAfterEvent: memSizeOfFrags(half1),
				},
				{
					name:              "half1 reassembly timeout",
					clockAdvance:      1,
					memSizeAfterEvent: 0,
				},
				{
					name:              "half2",
					fragment:          half2,
					expectDone:        false,
					memSizeAfterEvent: memSizeOfFrags(half2),
				},
				{
					name:              "half2 just before reassembly timeout",
					clockAdvance:      reassemblyTimeout - 1,
					memSizeAfterEvent: memSizeOfFrags(half2),
				},
				{
					name:              "half2 reassembly timeout",
					clockAdvance:      1,
					memSizeAfterEvent: 0,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			f := NewFragmentation(minBlockSize, HighFragThreshold, LowFragThreshold, reassemblyTimeout, clock, nil)
			for _, event := range test.events {
				clock.Advance(event.clockAdvance)
				if frag := event.fragment; frag != nil {
					_, _, done, err := f.Process(FragmentID{}, frag.first, frag.last, frag.more, protocol, pkt(len(frag.data), frag.data))
					if err != nil {
						t.Fatalf("%s: f.Process failed: %s", event.name, err)
					}
					if done != event.expectDone {
						t.Fatalf("%s: got done = %t, want = %t", event.name, done, event.expectDone)
					}
				}
				if got, want := f.memSize, event.memSizeAfterEvent; got != want {
					t.Errorf("%s: got f.memSize = %d, want = %d", event.name, got, want)
				}
			}
		})
	}
}

func TestMemoryLimits(t *testing.T) {
	lowLimit := pkt(1, "0").MemSize()
	highLimit := 3 * lowLimit // Allow at most 3 such packets.
	f := NewFragmentation(minBlockSize, highLimit, lowLimit, reassembleTimeout, &faketime.NullClock{}, nil)
	// Send first fragment with id = 0.
	f.Process(FragmentID{ID: 0}, 0, 0, true, 0xFF, pkt(1, "0"))
	// Send first fragment with id = 1.
	f.Process(FragmentID{ID: 1}, 0, 0, true, 0xFF, pkt(1, "1"))
	// Send first fragment with id = 2.
	f.Process(FragmentID{ID: 2}, 0, 0, true, 0xFF, pkt(1, "2"))

	// Send first fragment with id = 3. This should caused id = 0 and id = 1 to be
	// evicted.
	f.Process(FragmentID{ID: 3}, 0, 0, true, 0xFF, pkt(1, "3"))

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
	memSize := pkt(1, "0").MemSize()
	f := NewFragmentation(minBlockSize, memSize, 0, reassembleTimeout, &faketime.NullClock{}, nil)
	// Send first fragment with id = 0.
	f.Process(FragmentID{}, 0, 0, true, 0xFF, pkt(1, "0"))
	// Send the same packet again.
	f.Process(FragmentID{}, 0, 0, true, 0xFF, pkt(1, "0"))

	if got, want := f.memSize, memSize; got != want {
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
			err:       ErrInvalidArgs,
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
			f := NewFragmentation(test.blockSize, HighFragThreshold, LowFragThreshold, reassembleTimeout, &faketime.NullClock{}, nil)
			_, _, done, err := f.Process(FragmentID{}, test.first, test.last, test.more, 0, pkt(len(test.data), test.data))
			if !errors.Is(err, test.err) {
				t.Errorf("got Process(_, %d, %d, %t, _, %q) = (_, _, _, %v), want = (_, _, _, %v)", test.first, test.last, test.more, test.data, err, test.err)
			}
			if done {
				t.Errorf("got Process(_, %d, %d, %t, _, %q) = (_, _, true, _), want = (_, _, false, _)", test.first, test.last, test.more, test.data)
			}
		})
	}
}

type fragmentInfo struct {
	remaining int
	copied    int
	offset    int
	more      bool
}

func TestPacketFragmenter(t *testing.T) {
	const (
		reserve = 60
		proto   = 0
	)

	tests := []struct {
		name               string
		fragmentPayloadLen uint32
		transportHeaderLen int
		payloadSize        int
		wantFragments      []fragmentInfo
	}{
		{
			name:               "Packet exactly fits in MTU",
			fragmentPayloadLen: 1280,
			transportHeaderLen: 0,
			payloadSize:        1280,
			wantFragments: []fragmentInfo{
				{remaining: 0, copied: 1280, offset: 0, more: false},
			},
		},
		{
			name:               "Packet exactly does not fit in MTU",
			fragmentPayloadLen: 1000,
			transportHeaderLen: 0,
			payloadSize:        1001,
			wantFragments: []fragmentInfo{
				{remaining: 1, copied: 1000, offset: 0, more: true},
				{remaining: 0, copied: 1, offset: 1000, more: false},
			},
		},
		{
			name:               "Packet has a transport header",
			fragmentPayloadLen: 560,
			transportHeaderLen: 40,
			payloadSize:        560,
			wantFragments: []fragmentInfo{
				{remaining: 1, copied: 560, offset: 0, more: true},
				{remaining: 0, copied: 40, offset: 560, more: false},
			},
		},
		{
			name:               "Packet has a huge transport header",
			fragmentPayloadLen: 500,
			transportHeaderLen: 1300,
			payloadSize:        500,
			wantFragments: []fragmentInfo{
				{remaining: 3, copied: 500, offset: 0, more: true},
				{remaining: 2, copied: 500, offset: 500, more: true},
				{remaining: 1, copied: 500, offset: 1000, more: true},
				{remaining: 0, copied: 300, offset: 1500, more: false},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkt := testutil.MakeRandPkt(test.transportHeaderLen, reserve, []int{test.payloadSize}, proto)
			var originalPayload buffer.VectorisedView
			originalPayload.AppendView(pkt.TransportHeader().View())
			originalPayload.Append(pkt.Data)
			var reassembledPayload buffer.VectorisedView
			pf := MakePacketFragmenter(pkt, test.fragmentPayloadLen, reserve)
			for i := 0; ; i++ {
				fragPkt, offset, copied, more := pf.BuildNextFragment()
				wantFragment := test.wantFragments[i]
				if got := pf.RemainingFragmentCount(); got != wantFragment.remaining {
					t.Errorf("(fragment #%d) got pf.RemainingFragmentCount() = %d, want = %d", i, got, wantFragment.remaining)
				}
				if copied != wantFragment.copied {
					t.Errorf("(fragment #%d) got copied = %d, want = %d", i, copied, wantFragment.copied)
				}
				if offset != wantFragment.offset {
					t.Errorf("(fragment #%d) got offset = %d, want = %d", i, offset, wantFragment.offset)
				}
				if more != wantFragment.more {
					t.Errorf("(fragment #%d) got more = %t, want = %t", i, more, wantFragment.more)
				}
				if got := uint32(fragPkt.Size()); got > test.fragmentPayloadLen {
					t.Errorf("(fragment #%d) got fragPkt.Size() = %d, want <= %d", i, got, test.fragmentPayloadLen)
				}
				if got := fragPkt.AvailableHeaderBytes(); got != reserve {
					t.Errorf("(fragment #%d) got fragPkt.AvailableHeaderBytes() = %d, want = %d", i, got, reserve)
				}
				if got := fragPkt.TransportHeader().View().Size(); got != 0 {
					t.Errorf("(fragment #%d) got fragPkt.TransportHeader().View().Size() = %d, want = 0", i, got)
				}
				reassembledPayload.Append(fragPkt.Data)
				if !more {
					if i != len(test.wantFragments)-1 {
						t.Errorf("got fragment count = %d, want = %d", i, len(test.wantFragments)-1)
					}
					break
				}
			}
			if diff := cmp.Diff(reassembledPayload.ToView(), originalPayload.ToView()); diff != "" {
				t.Errorf("reassembledPayload mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

type testTimeoutHandler struct {
	pkt *stack.PacketBuffer
}

func (h *testTimeoutHandler) OnReassemblyTimeout(pkt *stack.PacketBuffer) {
	h.pkt = pkt
}

func TestTimeoutHandler(t *testing.T) {
	const (
		proto = 99
	)

	pk1 := pkt(1, "1")
	pk2 := pkt(1, "2")

	type processParam struct {
		first uint16
		last  uint16
		more  bool
		pkt   *stack.PacketBuffer
	}

	tests := []struct {
		name      string
		params    []processParam
		wantError bool
		wantPkt   *stack.PacketBuffer
	}{
		{
			name: "onTimeout runs",
			params: []processParam{
				{
					first: 0,
					last:  0,
					more:  true,
					pkt:   pk1,
				},
			},
			wantError: false,
			wantPkt:   pk1,
		},
		{
			name: "no first fragment",
			params: []processParam{
				{
					first: 1,
					last:  1,
					more:  true,
					pkt:   pk1,
				},
			},
			wantError: false,
			wantPkt:   nil,
		},
		{
			name: "second pkt is ignored",
			params: []processParam{
				{
					first: 0,
					last:  0,
					more:  true,
					pkt:   pk1,
				},
				{
					first: 0,
					last:  0,
					more:  true,
					pkt:   pk2,
				},
			},
			wantError: false,
			wantPkt:   pk1,
		},
		{
			name: "invalid args - first is greater than last",
			params: []processParam{
				{
					first: 1,
					last:  0,
					more:  true,
					pkt:   pk1,
				},
			},
			wantError: true,
			wantPkt:   nil,
		},
	}

	id := FragmentID{ID: 0}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &testTimeoutHandler{pkt: nil}

			f := NewFragmentation(minBlockSize, HighFragThreshold, LowFragThreshold, reassembleTimeout, &faketime.NullClock{}, handler)

			for _, p := range test.params {
				if _, _, _, err := f.Process(id, p.first, p.last, p.more, proto, p.pkt); err != nil && !test.wantError {
					t.Errorf("f.Process error = %s", err)
				}
			}
			if !test.wantError {
				r, ok := f.reassemblers[id]
				if !ok {
					t.Fatal("Reassembler not found")
				}
				f.release(r, true)
			}
			switch {
			case handler.pkt != nil && test.wantPkt == nil:
				t.Errorf("got handler.pkt = not nil (pkt.Data = %x), want = nil", handler.pkt.Data.ToView())
			case handler.pkt == nil && test.wantPkt != nil:
				t.Errorf("got handler.pkt = nil, want = not nil (pkt.Data = %x)", test.wantPkt.Data.ToView())
			case handler.pkt != nil && test.wantPkt != nil:
				if diff := cmp.Diff(test.wantPkt.Data.ToView(), handler.pkt.Data.ToView()); diff != "" {
					t.Errorf("pkt.Data mismatch (-want, +got):\n%s", diff)
				}
			}
		})
	}
}
