// Copyright 2020 The gVisor Authors.
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

package nested_test

import (
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type mockEndpoint struct {
	stack.NetworkDispatcher
	stack.LinkEndpoint
}

func (m mockEndpoint) WritePackets(packets stack.PacketBufferList) (int, tcpip.Error) {
	len := len(packets.AsSlice())
	packets.DecRef()
	return len, nil
}

// newTestPacketBufferList generates `packets` packets.
//
// Each has a one-byte buffer. The first packet's single byte is `counterStart`, the second's is
// `counterStart + 1`, and so on.
func newTestPacketBufferList(packets, counterStart int) (ret stack.PacketBufferList) {
	for i := 0; i < packets; i++ {
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.NewWithData([]byte{byte(counterStart + i)})})
		ret.PushBack(packet)
	}
	return
}

func bufferPtrToSlicePtr(buf *stack.PacketBuffer) *[]byte {
	if buf == nil {
		return nil
	}

	var b []byte
	for _, slc := range buf.Slices() {
		b = append(b, slc...)
	}
	return &b
}

func buffersToSlices(bufs []*stack.PacketBuffer) []*[]byte {
	var ret []*[]byte
	for _, b := range bufs {
		ret = append(ret, bufferPtrToSlicePtr(b))
	}
	return ret
}

func packetsToSlices(pkts []nested.CapturedPacket) []*[]byte {
	var ret []*[]byte
	for _, p := range pkts {
		ret = append(ret, bufferPtrToSlicePtr(p.Pkt))
	}
	return ret
}

func TestPacketRingBuffer(t *testing.T) {
	e := nested.NewCaptureEndpoint(mockEndpoint{})
	defer e.ClearCapturedPackets()

	// Write 1/4 of the buffer size. This leaves the first 1/4 of the buffer initialized, and the
	// remaining 3/4 of the buffer containing nil values.
	e.WritePackets(newTestPacketBufferList(nested.CaptureBufferSize/4, 0))

	// Since "first" contains the packets which were pushed further in the past, here it contains
	// all nil values, and "second" contains the 1/4 of the buffer size of packets which were pushed
	// above.
	first, second := e.GetCapturedPackets()
	f := packetsToSlices(first)
	s := packetsToSlices(second)
	wantF := make([]*[]byte, (nested.CaptureBufferSize*3)/4)
	list := newTestPacketBufferList(nested.CaptureBufferSize/4, 0)
	defer list.DecRef()
	wantS := buffersToSlices(list.AsSlice())
	if !reflect.DeepEqual(f, wantF) {
		t.Errorf("Unexpected value for `f`: got %v; wanted %v", f, wantF)
	}
	if !reflect.DeepEqual(s, wantS) {
		t.Errorf("Unexpected value for `s`: got %v; wanted %v", s, wantS)
	}

	// Write another 1/4 of the buffer size. This leaves the first 1/2 of the buffer initialized, and
	// second 1/2 of the buffer containing nil values.
	e.WritePackets(newTestPacketBufferList(nested.CaptureBufferSize/4, nested.CaptureBufferSize/4))

	// As above, "first" should contain nil values, and "second" should contain the packets which
	// were pushed above.
	first, second = e.GetCapturedPackets()
	f = packetsToSlices(first)
	s = packetsToSlices(second)
	wantF = make([]*[]byte, nested.CaptureBufferSize/2)
	list = newTestPacketBufferList(nested.CaptureBufferSize/2, 0)
	defer list.DecRef()
	wantS = buffersToSlices(list.AsSlice())
	if !reflect.DeepEqual(f, wantF) {
		t.Errorf("Unexpected value for `f`: got %v; wanted %v", f, wantF)
	}
	if !reflect.DeepEqual(s, wantS) {
		t.Errorf("Unexpected value for `s`: got %v; wanted %v", s, wantS)
	}

	// Write an entire buffer size worth of packets. This leaves the second 1/2 of the buffer
	// initialized, and overwrites the first 1/2 of the buffer - which was already initialized - with
	// new packets.
	e.WritePackets(newTestPacketBufferList(nested.CaptureBufferSize, nested.CaptureBufferSize/2))

	// "first" should contain the older packets, and "second" should contain the newer ones. Here, the
	// older packets are those indexed [buffer size/2, buffer size) and the newer packets are those
	// indexed [buffer size, buffer size * 3/2).
	first, second = e.GetCapturedPackets()
	f = packetsToSlices(first)
	s = packetsToSlices(second)
	list = newTestPacketBufferList(nested.CaptureBufferSize/2, nested.CaptureBufferSize/2)
	defer list.DecRef()
	wantF = buffersToSlices(list.AsSlice())
	list = newTestPacketBufferList(nested.CaptureBufferSize/2, nested.CaptureBufferSize)
	defer list.DecRef()
	wantS = buffersToSlices(list.AsSlice())
	if !reflect.DeepEqual(f, wantF) {
		t.Errorf("Unexpected value for `f`: got %v; wanted %v", f, wantF)
	}
	if !reflect.DeepEqual(s, wantS) {
		t.Errorf("Unexpected value for `s`: got %v; wanted %v", s, wantS)
	}
}
