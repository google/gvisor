// Copyright 2019 The gVisor Authors.
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

package ipv4_test

import (
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/fragmentation"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	lladdr0 = tcpip.Address("\x10\x00\x00\x01")
	lladdr1 = tcpip.Address("\x10\x00\x00\x02")
)

const (
	// defaultMTU is the loopback MTU value
	defaultMTU = 65536
)

type stubLinkEndpoint struct {
	stack.LinkEndpoint
}

func (*stubLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return 0
}

func (*stubLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (*stubLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (*stubLinkEndpoint) WritePacket(*stack.Route, *stack.GSO, tcpip.NetworkProtocolNumber, tcpip.PacketBuffer) *tcpip.Error {
	return nil
}

func (*stubLinkEndpoint) Attach(stack.NetworkDispatcher) {
}

// MTU implements stack.LinkEndpoint.MTU. It just returns a constant that
// matches the linux loopback MTU.
func (*stubLinkEndpoint) MTU() uint32 {
	return defaultMTU
}

// vv is a helper to build VectorisedView from different strings.
func vv(size int, pieces ...string) buffer.VectorisedView {
	views := make([]buffer.View, len(pieces))
	for i, p := range pieces {
		views[i] = []byte(p)
	}
	return buffer.NewVectorisedView(size, views)
}

func TestReassemblingTimeout(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv4.NewProtocol()},
	})
	{
		if err := s.CreateNIC(1, &stubLinkEndpoint{}); err != nil {
			t.Fatalf("CreateNIC(_) = %s", err)
		}
		if err := s.AddAddress(1, ipv4.ProtocolNumber, lladdr0); err != nil {
			t.Fatalf("AddAddress(_, %d, %s) = %s", ipv4.ProtocolNumber, lladdr0, err)
		}
	}
	{
		subnet, err := tcpip.NewSubnet(lladdr1, tcpip.AddressMask(strings.Repeat("\xff", len(lladdr1))))
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable(
			[]tcpip.Route{{
				Destination: subnet,
				NIC:         1,
			}},
		)
	}

	ra, err := s.FindRoute(1, lladdr0, lladdr1, ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(_) = _, %s, want = _, nil", err)
	}
	defer ra.Release()

	totalLen := header.IPv4MinimumSize
	view := buffer.NewView(totalLen)
	ip := header.IPv4(view)
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: uint16(totalLen),
		TTL:         20,
		Protocol:    10,
		SrcAddr:     lladdr1,
		DstAddr:     lladdr0,
	})

	v1 := view.ToVectorisedView()
	f := fragmentation.NewFragmentation(1024, 512, time.Second)
	// Send first fragment with id = 0, first = 0, last = 0, and more = true.
	f.Process(0, 0, 0, true, vv(1, "0"), v1.First(), &ra)
	// Sleep more than the timeout.
	time.Sleep(31 * time.Second)
	// Send another fragment that completes a packet.
	// However, no packet should be reassembled because the fragment arrived after the timeout.
	_, done, err1 := f.Process(0, 1, 1, false, vv(1, "1"), v1.First(), &ra)
	if err1 != nil {
		t.Fatalf("f.Process(0, 1, 1, false, vv(1, \"1\")) failed: %v", err1)
	}
	if done {
		t.Errorf("Fragmentation does not respect the reassembling timeout.")
	}
}
