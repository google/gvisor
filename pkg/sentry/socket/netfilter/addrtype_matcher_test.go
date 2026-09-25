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

package netfilter

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func ipv4Packet(src, dst tcpip.Address) *stack.PacketBuffer {
	b := make([]byte, header.IPv4MinimumSize)
	header.IPv4(b).Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(b),
	})
	if _, ok := pkt.NetworkHeader().Consume(header.IPv4MinimumSize); !ok {
		panic("NetworkHeader.Consume failed")
	}
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	return pkt
}

func TestAddrTypeLocalAssignedAddress(t *testing.T) {
	local := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	remote := tcpip.AddrFrom4([4]byte{198, 51, 100, 1})

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		Clock:            &faketime.NullClock{},
	})
	defer s.Destroy()
	if err := s.CreateNIC(1, loopback.New()); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	pa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   local,
			PrefixLen: 32,
		},
	}
	if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}

	m := &addrTypeMatcher{dest: linux.XT_ADDRTYPE_LOCAL, stack: s}

	localPkt := ipv4Packet(remote, local)
	defer localPkt.DecRef()
	if matches, hotdrop := m.Match(stack.Input, localPkt, "", ""); !matches || hotdrop {
		t.Errorf("LOCAL match for assigned dest = (%v, %v), want (true, false); CheckLocalAddress(assigned)=%d", matches, hotdrop, s.CheckLocalAddress(0, header.IPv4ProtocolNumber, local))
	}

	remotePkt := ipv4Packet(local, remote)
	defer remotePkt.DecRef()
	if matches, hotdrop := m.Match(stack.Input, remotePkt, "", ""); matches || hotdrop {
		t.Errorf("LOCAL match for unassigned dest = (%v, %v), want (false, false)", matches, hotdrop)
	}

	noStack := &addrTypeMatcher{dest: linux.XT_ADDRTYPE_LOCAL}
	if matches, _ := noStack.Match(stack.Input, localPkt, "", ""); matches {
		t.Error("LOCAL matched assigned dest without a stack; kube-proxy relies on the stack lookup")
	}
}

func TestAddrTypeLoopbackIsLocal(t *testing.T) {
	m := &addrTypeMatcher{dest: linux.XT_ADDRTYPE_LOCAL}
	pkt := ipv4Packet(header.IPv4Loopback, header.IPv4Loopback)
	defer pkt.DecRef()
	if matches, hotdrop := m.Match(stack.Input, pkt, "", ""); !matches || hotdrop {
		t.Errorf("LOCAL match for 127.0.0.1 = (%v, %v), want (true, false)", matches, hotdrop)
	}
}

func TestAddrTypeMulticastAndBroadcast(t *testing.T) {
	mcast := tcpip.AddrFrom4([4]byte{224, 0, 0, 1})
	src := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})

	mcastMatcher := &addrTypeMatcher{dest: linux.XT_ADDRTYPE_MULTICAST}
	pkt := ipv4Packet(src, mcast)
	defer pkt.DecRef()
	if matches, _ := mcastMatcher.Match(stack.Input, pkt, "", ""); !matches {
		t.Error("MULTICAST dest did not match")
	}
	if matches, _ := (&addrTypeMatcher{dest: linux.XT_ADDRTYPE_LOCAL}).Match(stack.Input, pkt, "", ""); matches {
		t.Error("MULTICAST dest matched LOCAL")
	}

	bcastPkt := ipv4Packet(src, header.IPv4Broadcast)
	defer bcastPkt.DecRef()
	if matches, _ := (&addrTypeMatcher{dest: linux.XT_ADDRTYPE_BROADCAST}).Match(stack.Input, bcastPkt, "", ""); !matches {
		t.Error("limited broadcast dest did not match BROADCAST")
	}
}

func TestAddrTypeFIBTypesRejected(t *testing.T) {
	raw := make([]byte, linux.SizeOfXTAddrtypeInfoV1)
	hostarch.ByteOrder.PutUint16(raw[offAddrTypeDest:], linux.XT_ADDRTYPE_BLACKHOLE)
	if _, err := (addrTypeMarshaler{}).unmarshal(nil, raw, stack.IPHeaderFilter{}); err == nil {
		t.Fatal("unmarshal of BLACKHOLE dest type succeeded, want error")
	}
}
