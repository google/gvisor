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

package tcp

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func segmentationRoute(tb testing.TB) (*stack.Route, *channel.Endpoint) {
	tb.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocol}})
	tb.Cleanup(s.Destroy)
	link := channel.New(128, 1500, "")
	tb.Cleanup(link.Close)
	if err := s.CreateNICWithOptions(1, link, stack.NICOptions{EnableExperimentIPOption: true}); err != nil {
		tb.Fatal(err)
	}
	local := tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1})
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: local.WithPrefix()}, stack.AddressProperties{}); err != nil {
		tb.Fatal(err)
	}
	route, err := s.FindRoute(1, local, header.IPv6AllNodesMulticastAddress, ipv6.ProtocolNumber, false)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(route.Release)
	link.Drain()
	return route, link
}

func TestSegmentedIPv6HeaderReservation(t *testing.T) {
	route, link := segmentationRoute(t)
	const mss = 1400
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.IPv6MinimumSize + header.TCPMinimumSize + header.IPv6ExperimentHdrLength,
		Payload:            buffer.MakeWithData(make([]byte, 4*mss)),
	})
	defer pkt.DecRef()
	if err := sendTCPBatch(route, tcpFields{ttl: 64, expOptVal: 99}, pkt, stack.GSO{Type: stack.GSOGvisor, MSS: mss}, nil); err != nil {
		t.Fatal(err)
	}
	count, unusedHeaderBytes := 0, 0
	for out := link.Read(); out != nil; out = link.Read() {
		got := out.AvailableHeaderBytes()
		out.DecRef()
		if count == 0 {
			unusedHeaderBytes = got
		} else if got != unusedHeaderBytes {
			t.Errorf("segment %d unused header bytes = %d, first equal-sized segment = %d", count, got, unusedHeaderBytes)
		}
		count++
	}
	if count != 4 {
		t.Fatalf("got %d segments, want 4", count)
	}
}

func BenchmarkSendTCPBatch(b *testing.B) {
	for _, option := range []uint16{0, 99} {
		b.Run(fmt.Sprintf("experiment=%t", option != 0), func(b *testing.B) {
			route, link := segmentationRoute(b)
			payload := buffer.MakeWithData(make([]byte, 64<<10))
			defer payload.Release()
			headerSize := header.IPv6MinimumSize + header.TCPMinimumSize
			if option != 0 {
				headerSize += header.IPv6ExperimentHdrLength
			}
			b.SetBytes(payload.Size())
			b.ReportAllocs()
			for b.Loop() {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: headerSize, Payload: payload.Clone()})
				err := sendTCPBatch(route, tcpFields{ttl: 64, expOptVal: option}, pkt, stack.GSO{Type: stack.GSOGvisor, MSS: 1400}, nil)
				pkt.DecRef()
				if err != nil {
					b.Fatal(err)
				}
				link.Drain()
			}
		})
	}
}
