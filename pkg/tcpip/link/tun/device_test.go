// Copyright 2026 The gVisor Authors.
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

package tun

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type networkDispatcher func(tcpip.NetworkProtocolNumber, *stack.PacketBuffer)

func (d networkDispatcher) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d(proto, pkt)
}

func (networkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	panic("unexpected link packet")
}

func segmentedBuffer(parts ...[]byte) buffer.Buffer {
	var b buffer.Buffer
	for _, part := range parts {
		v := buffer.MakeWithData(part)
		b.Merge(&v)
	}
	return b
}

func TestWriteSplitHeaders(t *testing.T) {
	d := Device{endpoint: &tunEndpoint{Endpoint: channel.New(1, 1500, "")}, flags: Flags{TAP: true}}
	defer d.endpoint.Close()
	eth := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x08, 0x00}
	// Split the packet information and Ethernet headers across views.
	data := segmentedBuffer([]byte{0, 0, 0x08}, append([]byte{0}, eth[:5]...), eth[5:], []byte{0x45, 1}, []byte{2, 3})
	length := data.Size()
	views := data.AsViewList()
	network := views.Back().Prev().AsSlice()
	delivered := false
	d.endpoint.Attach(networkDispatcher(func(proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
		delivered = true
		if proto != header.IPv4ProtocolNumber || !bytes.Equal(pkt.LinkHeader().Slice(), eth) {
			t.Errorf("delivered protocol %#x and Ethernet header %x, want %#x and %x", proto, pkt.LinkHeader().Slice(), header.IPv4ProtocolNumber, eth)
		}
		hdr, ok := pkt.NetworkHeader().Consume(len(network))
		if !ok || !bytes.Equal(hdr, network) {
			t.Fatalf("consumed network header %x, %t, want %x", hdr, ok, network)
		}
		if &hdr[0] != &network[0] {
			t.Error("consuming the network header copied the exclusively owned payload")
		}
		tail := pkt.Data().ToBuffer()
		defer tail.Release()
		if got, want := tail.Flatten(), []byte{2, 3}; !bytes.Equal(got, want) {
			t.Errorf("remaining payload = %x, want %x", got, want)
		}
	}))
	if n, err := d.Write(data); err != nil || n != length || !delivered {
		t.Fatalf("Write = (%d, %v), delivered = %t; want (%d, nil), delivered", n, err, delivered, length)
	}
}

func TestReadPacketInfo(t *testing.T) {
	for _, tc := range []struct {
		name          string
		shared        bool
		firstViewSize int
	}{
		{"OwnedHeadroom", false, PacketInfoHeaderSize + 2},
		{"SharedHeadroom", true, PacketInfoHeaderSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Device{endpoint: &tunEndpoint{Endpoint: channel.New(1, 1500, "")}, flags: Flags{TUN: true}}
			defer d.endpoint.Close()
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: PacketInfoHeaderSize + 2,
				Payload:            segmentedBuffer([]byte{1, 2}, []byte{3, 4}),
			})
			pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
			copy(pkt.NetworkHeader().Push(2), []byte{0x45, 0})
			var packets stack.PacketBufferList
			packets.PushBack(pkt)
			n, err := d.endpoint.WritePackets(packets)
			if tc.shared {
				defer pkt.DecRef()
			} else {
				pkt.DecRef()
			}
			if err != nil || n != 1 {
				t.Fatalf("WritePackets = (%d, %v), want (1, nil)", n, err)
			}
			data, readErr := d.Read()
			if readErr != nil {
				t.Fatalf("Read: %v", readErr)
			}
			defer data.Release()
			if got, want := data.Flatten(), []byte{0, 0, 8, 0, 0x45, 0, 1, 2, 3, 4}; !bytes.Equal(got, want) {
				t.Fatalf("read packet = %x, want %x", got, want)
			}
			views := data.AsViewList()
			if got := views.Front().Size(); got != tc.firstViewSize {
				t.Errorf("first view size = %d, want %d", got, tc.firstViewSize)
			}
		})
	}
}
