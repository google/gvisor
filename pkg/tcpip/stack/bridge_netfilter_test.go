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

package bridge_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/nftables"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nfBridgeID   = 40
	nfBridgeName = "br0"
	nfBridgeMAC  = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")
	nfPortAMAC   = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
	nfPortBMAC   = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x03")
	nfPortCMAC   = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x04")
	nfUplinkMAC  = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x05")
	nfHostAMAC   = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x0a")
	nfHostBMAC   = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x0b")
	nfUnknownMAC = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x0c")
	nfHostCMAC   = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x0d")
	// nfUplinkHostMAC is the link address of the host behind the uplink.
	nfUplinkHostMAC = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x0e")

	// nfPortA, nfPortB and nfPortC index nfEnv.chs and nfPortIDs, and
	// nfUplink indexes nfEnv.chs.
	nfPortA  = 0
	nfPortB  = 1
	nfPortC  = 2
	nfUplink = 3

	// nfUplinkID is the ID of a NIC that isn't a port of the bridge.
	nfUplinkID = 45

	nfVIPPort     = 80
	nfServicePort = 8080
	nfClientPort  = 5000
)

var nfPortIDs = [3]tcpip.NICID{41, 42, 43}

// nfAddrs are the addresses of a network protocol in nfEnv. Hosts A and B
// are behind ports A and B.
type nfAddrs struct {
	proto  tcpip.NetworkProtocolNumber
	prefix int
	bridge tcpip.Address
	hostA  tcpip.Address
	hostB  tcpip.Address
	// hostC is an address of no host that the bridge learned.
	hostC tcpip.Address
	// vip is a virtual address that the tests DNAT.
	vip tcpip.Address
	// uplink is the address of the uplink, and uplinkHost the address of the
	// host behind it.
	uplink     tcpip.Address
	uplinkHost tcpip.Address
}

var (
	nfIPv4 = nfAddrs{
		proto:      ipv4.ProtocolNumber,
		prefix:     24,
		bridge:     tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
		hostA:      tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
		hostB:      tcpip.AddrFrom4([4]byte{10, 0, 0, 3}),
		hostC:      tcpip.AddrFrom4([4]byte{10, 0, 0, 4}),
		vip:        tcpip.AddrFrom4([4]byte{10, 96, 0, 10}),
		uplink:     tcpip.AddrFrom4([4]byte{192, 168, 1, 1}),
		uplinkHost: tcpip.AddrFrom4([4]byte{192, 168, 1, 2}),
	}
	nfIPv6 = nfAddrs{
		proto:      ipv6.ProtocolNumber,
		prefix:     64,
		bridge:     tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
		hostA:      tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
		hostB:      tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}),
		hostC:      tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}),
		vip:        tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 0x96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}),
		uplink:     tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
		uplinkHost: tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
	}
	nfProtocols = []nfAddrs{nfIPv4, nfIPv6}
)

func (a nfAddrs) name() string {
	if a.proto == ipv4.ProtocolNumber {
		return "IPv4"
	}
	return "IPv6"
}

func (a nfAddrs) isIPv6() bool {
	return a.proto == ipv6.ProtocolNumber
}

// hostFilter returns a filter that matches the transport protocol proto, and
// the source and destination addresses src and dst when they are set.
func (a nfAddrs) filter(proto tcpip.TransportProtocolNumber, src, dst tcpip.Address) stack.IPHeaderFilter {
	f := stack.EmptyFilter4()
	full := tcpip.AddrFrom4([4]byte{0xff, 0xff, 0xff, 0xff})
	if a.isIPv6() {
		f = stack.EmptyFilter6()
		full = tcpip.AddrFrom16([16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	}
	f.Protocol = proto
	f.CheckProtocol = true
	if src.Len() != 0 {
		f.Src = src
		f.SrcMask = full
	}
	if dst.Len() != 0 {
		f.Dst = dst
		f.DstMask = full
	}
	return f
}

// nfEnv is a stack with a bridge named br0 with ports A, B and C, and an
// uplink. The bridge has learned that host A is behind port A and host B
// behind port B.
type nfEnv struct {
	s      *stack.Stack
	bridge *stack.BridgeEndpoint
	chs    [4]*channel.Endpoint
}

func newNFEnv(t *testing.T, nf stack.BridgeNetfilter) *nfEnv {
	t.Helper()
	env := &nfEnv{
		s: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol, arp.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
		}),
	}
	t.Cleanup(func() {
		drainChannels(env.chs[:]...)
		for _, ch := range env.chs {
			ch.Close()
		}
		env.s.Destroy()
	})
	env.bridge = stack.NewBridgeEndpoint(1500)
	env.bridge.SetLinkAddress(nfBridgeMAC)
	if err := env.s.CreateNICWithOptions(nfBridgeID, env.bridge, stack.NICOptions{Name: nfBridgeName, DeliverLinkPackets: true}); err != nil {
		t.Fatalf("s.CreateNICWithOptions(%d, _, _): %s", nfBridgeID, err)
	}
	for i, mac := range [3]tcpip.LinkAddress{nfPortAMAC, nfPortBMAC, nfPortCMAC} {
		env.chs[i] = channel.New(16, 1500, mac)
		if err := env.s.CreateNIC(nfPortIDs[i], ethernet.New(env.chs[i])); err != nil {
			t.Fatalf("s.CreateNIC(%d, _): %s", nfPortIDs[i], err)
		}
		if err := env.s.SetNICCoordinator(nfPortIDs[i], nfBridgeID); err != nil {
			t.Fatalf("s.SetNICCoordinator(%d, %d): %s", nfPortIDs[i], nfBridgeID, err)
		}
	}
	env.chs[nfUplink] = channel.New(16, 1500, nfUplinkMAC)
	if err := env.s.CreateNIC(nfUplinkID, ethernet.New(env.chs[nfUplink])); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nfUplinkID, err)
	}
	var routes []tcpip.Route
	for _, a := range nfProtocols {
		for _, nicAddr := range []struct {
			id   tcpip.NICID
			addr tcpip.Address
		}{{nfBridgeID, a.bridge}, {nfUplinkID, a.uplink}} {
			addr := tcpip.AddressWithPrefix{Address: nicAddr.addr, PrefixLen: a.prefix}
			if err := env.s.AddProtocolAddress(nicAddr.id, tcpip.ProtocolAddress{Protocol: a.proto, AddressWithPrefix: addr}, stack.AddressProperties{}); err != nil {
				t.Fatalf("s.AddProtocolAddress(%d, %s, {}): %s", nicAddr.id, addr, err)
			}
			routes = append(routes, tcpip.Route{Destination: addr.Subnet(), NIC: nicAddr.id})
		}
		if err := env.s.AddStaticNeighbor(nfUplinkID, a.proto, a.uplinkHost, nfUplinkHostMAC); err != nil {
			t.Fatalf("s.AddStaticNeighbor(%d, %d, %s, %s): %s", nfUplinkID, a.proto, a.uplinkHost, nfUplinkHostMAC, err)
		}
	}
	env.s.SetRouteTable(routes)
	if err := env.s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, true): %s", ipv4.ProtocolNumber, err)
	}
	env.s.SetBridgeNetfilter(nf)

	// Learn the hosts from frames that netfilter doesn't see.
	env.injectFrame(nfPortA, nfHostAMAC, nfUnknownMAC, 0x88b5, nil)
	env.injectFrame(nfPortB, nfHostBMAC, nfUnknownMAC, 0x88b5, nil)
	drainChannels(env.chs[:]...)
	return env
}

func (env *nfEnv) injectFrame(port int, src, dst tcpip.LinkAddress, proto tcpip.NetworkProtocolNumber, payload []byte) {
	pkt := makeEthernetFrame(src, dst, proto, payload)
	env.chs[port].InjectInbound(proto, pkt)
	pkt.DecRef()
}

// inject injects an IP packet from host A or B, as selected by port, to the
// link address dst.
func (env *nfEnv) inject(port int, dst tcpip.LinkAddress, proto tcpip.NetworkProtocolNumber, payload []byte) {
	src := nfHostAMAC
	if port == nfPortB {
		src = nfHostBMAC
	}
	env.injectFrame(port, src, dst, proto, payload)
}

// read returns the next frame port sent out that isn't a neighbor frame, or
// nil.
func (env *nfEnv) read(port int) *stack.PacketBuffer {
	for {
		pkt := env.chs[port].Read()
		if pkt == nil || !isNeighborFrame(pkt) {
			return pkt
		}
		pkt.DecRef()
	}
}

// readWait is like read, but waits for a frame.
func (env *nfEnv) readWait(t *testing.T, port int) *stack.PacketBuffer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		pkt := env.chs[port].ReadContext(ctx)
		if pkt == nil {
			t.Fatalf("port %d sent out no frame", port)
		}
		if !isNeighborFrame(pkt) {
			return pkt
		}
		pkt.DecRef()
	}
}

// isNeighborFrame returns whether pkt is ARP, or ICMPv6 other than a
// destination unreachable message, such as NDP and MLD.
func isNeighborFrame(pkt *stack.PacketBuffer) bool {
	v := pkt.ToView()
	defer v.Release()
	b := v.AsSlice()
	switch header.Ethernet(b).Type() {
	case header.ARPProtocolNumber:
		return true
	case header.IPv6ProtocolNumber:
		ip := header.IPv6(b[header.EthernetMinimumSize:])
		return ip.NextHeader() == uint8(header.ICMPv6ProtocolNumber) && header.ICMPv6(ip.Payload()).Type() != header.ICMPv6DstUnreachable
	}
	return false
}

// expectNone checks that no port sent out a frame.
func (env *nfEnv) expectNone(t *testing.T) {
	t.Helper()
	for port := range env.chs {
		if pkt := env.read(port); pkt != nil {
			t.Errorf("port %d sent out a frame: %+v", port, parseFrame(t, pkt))
		}
	}
}

// setRule replaces the rule of the built-in chain hook of a table with a rule
// with filter and target.
func setRule(s *stack.Stack, id stack.TableID, hook stack.Hook, a nfAddrs, filter stack.IPHeaderFilter, target stack.Target) {
	ipt := s.IPTables()
	table := ipt.GetTable(id, a.isIPv6())
	i := table.BuiltinChains[hook]
	table.Rules[i].Filter = filter
	table.Rules[i].Target = target
	// Accept the packets the rule doesn't match.
	table.Rules[i+1].Target = &stack.AcceptTarget{NetworkProtocol: a.proto}
	ipt.ForceReplaceTable(id, table, a.isIPv6())
}

// udpPacket returns an IP packet with a UDP datagram with valid checksums.
func udpPacket(a nfAddrs, src, dst tcpip.Address, srcPort, dstPort uint16, ttl uint8) []byte {
	payload := []byte("bridge netfilter")
	udpLen := header.UDPMinimumSize + len(payload)
	ipLen := header.IPv4MinimumSize
	if a.isIPv6() {
		ipLen = header.IPv6MinimumSize
	}
	b := make([]byte, ipLen+udpLen)
	if a.isIPv6() {
		header.IPv6(b).Encode(&header.IPv6Fields{
			PayloadLength:     uint16(udpLen),
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          ttl,
			SrcAddr:           src,
			DstAddr:           dst,
		})
	} else {
		ip := header.IPv4(b)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(b)),
			TTL:         ttl,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     src,
			DstAddr:     dst,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
	}
	u := header.UDP(b[ipLen:])
	u.Encode(&header.UDPFields{SrcPort: srcPort, DstPort: dstPort, Length: uint16(udpLen)})
	copy(u.Payload(), payload)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(udpLen))
	xsum = checksum.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))
	return b
}

// tcpSYN returns an IP packet with a TCP SYN segment with valid checksums.
func tcpSYN(a nfAddrs, src, dst tcpip.Address, srcPort, dstPort uint16) []byte {
	ipLen := header.IPv4MinimumSize
	if a.isIPv6() {
		ipLen = header.IPv6MinimumSize
	}
	b := make([]byte, ipLen+header.TCPMinimumSize)
	if a.isIPv6() {
		header.IPv6(b).Encode(&header.IPv6Fields{
			PayloadLength:     header.TCPMinimumSize,
			TransportProtocol: header.TCPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           src,
			DstAddr:           dst,
		})
	} else {
		ip := header.IPv4(b)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(b)),
			TTL:         64,
			Protocol:    uint8(header.TCPProtocolNumber),
			SrcAddr:     src,
			DstAddr:     dst,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
	}
	tcpHdr := header.TCP(b[ipLen:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     1000,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, header.TCPMinimumSize)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(xsum))
	return b
}

// frame is a frame with a UDP datagram or a TCP segment.
type frame struct {
	srcMAC, dstMAC   tcpip.LinkAddress
	src, dst         tcpip.Address
	srcPort, dstPort uint16
	ttl              uint8
	tcpFlags         header.TCPFlags
	// validChecksums is whether the IPv4 header checksum and the transport
	// checksum, recomputed from scratch, match the ones in the frame.
	validChecksums bool
}

// parseFrame parses a frame sent out of a port and releases it.
func parseFrame(t *testing.T, pkt *stack.PacketBuffer) frame {
	t.Helper()
	v := pkt.ToView()
	defer v.Release()
	defer pkt.DecRef()
	b := v.AsSlice()
	eth := header.Ethernet(b)
	f := frame{srcMAC: eth.SourceAddress(), dstMAC: eth.DestinationAddress(), validChecksums: true}
	b = b[header.EthernetMinimumSize:]
	var (
		transProto tcpip.TransportProtocolNumber
		payload    []byte
	)
	switch eth.Type() {
	case header.IPv4ProtocolNumber:
		ip := header.IPv4(b)
		if !ip.IsValid(len(b)) {
			t.Fatalf("got invalid IPv4 packet % x", v.AsSlice())
		}
		f.src, f.dst, f.ttl = ip.SourceAddress(), ip.DestinationAddress(), ip.TTL()
		f.validChecksums = ip.IsChecksumValid()
		transProto, payload = ip.TransportProtocol(), ip.Payload()
	case header.IPv6ProtocolNumber:
		ip := header.IPv6(b)
		f.src, f.dst, f.ttl = ip.SourceAddress(), ip.DestinationAddress(), ip.HopLimit()
		transProto, payload = tcpip.TransportProtocolNumber(ip.NextHeader()), ip.Payload()
	default:
		t.Fatalf("got frame with type %#x, want IPv4 or IPv6", eth.Type())
	}
	switch transProto {
	case header.UDPProtocolNumber:
		u := header.UDP(payload)
		f.srcPort, f.dstPort = u.SourcePort(), u.DestinationPort()
		f.validChecksums = f.validChecksums && u.IsChecksumValid(f.src, f.dst, checksum.Checksum(u.Payload(), 0))
	case header.TCPProtocolNumber:
		tcpHdr := header.TCP(payload)
		f.srcPort, f.dstPort, f.tcpFlags = tcpHdr.SourcePort(), tcpHdr.DestinationPort(), tcpHdr.Flags()
		payloadLen := uint16(len(payload) - int(tcpHdr.DataOffset()))
		f.validChecksums = f.validChecksums && tcpHdr.IsChecksumValid(f.src, f.dst, checksum.Checksum(payload[tcpHdr.DataOffset():], 0), payloadLen)
	default:
		t.Fatalf("got transport protocol %d, want UDP or TCP", transProto)
	}
	return f
}

// TestBridgeNetfilterForwardDrop checks that bridged frames go through the
// Forward hook, with the bridge as the input and output interface, only when
// bridge-nf-call-iptables or bridge-nf-call-ip6tables is set.
func TestBridgeNetfilterForwardDrop(t *testing.T) {
	for _, a := range nfProtocols {
		for _, call := range []bool{false, true} {
			name := a.name() + "/call off"
			if call {
				name = a.name() + "/call on"
			}
			t.Run(name, func(t *testing.T) {
				env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: call, CallIP6Tables: call})
				filter := a.filter(header.UDPProtocolNumber, tcpip.Address{}, tcpip.Address{})
				filter.InputInterface = nfBridgeName
				filter.OutputInterface = nfBridgeName
				setRule(env.s, stack.FilterID, stack.Forward, a, filter, &stack.DropTarget{NetworkProtocol: a.proto})

				env.inject(nfPortA, nfHostBMAC, a.proto, udpPacket(a, a.hostA, a.hostB, nfClientPort, nfServicePort, 64))
				pkt := env.read(nfPortB)
				if call {
					if pkt != nil {
						t.Errorf("port B sent out a frame dropped by the Forward hook: %+v", parseFrame(t, pkt))
					}
					return
				}
				if pkt == nil {
					t.Fatal("port B didn't send out the frame")
				}
				if got, want := parseFrame(t, pkt), (frame{srcMAC: nfHostAMAC, dstMAC: nfHostBMAC, src: a.hostA, dst: a.hostB, srcPort: nfClientPort, dstPort: nfServicePort, ttl: 64, validChecksums: true}); got != want {
					t.Errorf("got frame %+v, want %+v", got, want)
				}
			})
		}
	}
}

// TestBridgeNetfilterDefaultUnchanged checks that, with the default settings
// and no rules, frames are bridged as they are, while frames with a malformed
// IP header are dropped as br_validate_ipv4 and br_validate_ipv6 do.
func TestBridgeNetfilterDefaultUnchanged(t *testing.T) {
	s := stack.New(stack.Options{})
	defaults := s.BridgeNetfilter()
	s.Destroy()
	if want := (stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true, CallARPTables: true}); defaults != want {
		t.Fatalf("got default settings %+v, want %+v", defaults, want)
	}
	for _, a := range nfProtocols {
		for _, call := range []bool{false, true} {
			name := a.name() + "/call off"
			if call {
				name = a.name() + "/call on"
			}
			t.Run(name, func(t *testing.T) {
				env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: call, CallIP6Tables: call})
				env.inject(nfPortA, nfHostBMAC, a.proto, udpPacket(a, a.hostA, a.hostB, nfClientPort, nfServicePort, 64))
				pkt := env.read(nfPortB)
				if pkt == nil {
					t.Fatal("port B didn't send out the frame")
				}
				if got, want := parseFrame(t, pkt), (frame{srcMAC: nfHostAMAC, dstMAC: nfHostBMAC, src: a.hostA, dst: a.hostB, srcPort: nfClientPort, dstPort: nfServicePort, ttl: 64, validChecksums: true}); got != want {
					t.Errorf("got frame %+v, want %+v", got, want)
				}

				// A truncated packet.
				packet := udpPacket(a, a.hostA, a.hostB, nfClientPort, nfServicePort, 64)
				env.inject(nfPortA, nfHostBMAC, a.proto, packet[:len(packet)-1])
				pkt = env.read(nfPortB)
				if gotFwd := pkt != nil; gotFwd == call {
					t.Errorf("got truncated frame forwarded = %t, want %t", gotFwd, !call)
				}
				if pkt != nil {
					pkt.DecRef()
				}
			})
		}
	}
}

// TestBridgeNetfilterDNATBridged checks that, as br_nf_pre_routing_finish
// does, a frame DNATed in the Prerouting hook to a host on the bridge stays
// bridged: its destination link address becomes the host's, its source link
// address and TTL are kept, and IPv4 does so only when forwarding is enabled.
// Without bridge netfilter, the same frame is routed by the network layer.
func TestBridgeNetfilterDNATBridged(t *testing.T) {
	tests := []struct {
		name       string
		a          nfAddrs
		call       bool
		forwarding bool
		// want is the frame sent out of port B, if any.
		want *frame
	}{
		{
			name:       "IPv4",
			a:          nfIPv4,
			call:       true,
			forwarding: true,
			want:       &frame{srcMAC: nfHostAMAC, dstMAC: nfHostBMAC, src: nfIPv4.hostA, dst: nfIPv4.hostB, srcPort: nfClientPort, dstPort: nfServicePort, ttl: 64, validChecksums: true},
		},
		{
			name: "IPv4 without forwarding",
			a:    nfIPv4,
			call: true,
		},
		{
			name: "IPv6 without forwarding",
			a:    nfIPv6,
			call: true,
			want: &frame{srcMAC: nfHostAMAC, dstMAC: nfHostBMAC, src: nfIPv6.hostA, dst: nfIPv6.hostB, srcPort: nfClientPort, dstPort: nfServicePort, ttl: 64, validChecksums: true},
		},
		{
			// The network layer DNATs and routes the frame instead.
			name:       "IPv4 routed without bridge netfilter",
			a:          nfIPv4,
			forwarding: true,
			want:       &frame{srcMAC: nfBridgeMAC, dstMAC: nfHostBMAC, src: nfIPv4.hostA, dst: nfIPv4.hostB, srcPort: nfClientPort, dstPort: nfServicePort, ttl: 63, validChecksums: true},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := test.a
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: test.call, CallIP6Tables: test.call})
			if err := env.s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, test.forwarding); err != nil {
				t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, %t): %s", ipv4.ProtocolNumber, test.forwarding, err)
			}
			if err := env.s.AddStaticNeighbor(nfBridgeID, a.proto, a.hostB, nfHostBMAC); err != nil {
				t.Fatalf("s.AddStaticNeighbor(%d, %d, %s, %s): %s", nfBridgeID, a.proto, a.hostB, nfHostBMAC, err)
			}
			setRule(env.s, stack.NATID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, tcpip.Address{}, a.vip), &stack.DNATTarget{
				Addr:            a.hostB,
				Port:            nfServicePort,
				NetworkProtocol: a.proto,
				ChangeAddress:   true,
				ChangePort:      true,
			})

			env.inject(nfPortA, nfBridgeMAC, a.proto, udpPacket(a, a.hostA, a.vip, nfClientPort, nfVIPPort, 64))
			pkt := env.read(nfPortB)
			switch {
			case test.want == nil && pkt != nil:
				t.Errorf("port B sent out frame %+v, want none", parseFrame(t, pkt))
			case test.want != nil && pkt == nil:
				t.Errorf("port B didn't send out a frame, want %+v", *test.want)
			case test.want != nil:
				if got := parseFrame(t, pkt); got != *test.want {
					t.Errorf("got frame %+v, want %+v", got, *test.want)
				}
			}
			if !test.call {
				// The bridge floods what the network layer routes out of it.
				drainChannels(env.chs[nfPortA], env.chs[nfPortC])
			}
			env.expectNone(t)
		})
	}
}

// injectNeighborReply injects the ARP reply or NDP neighbor advertisement of
// the host with link address mac and address addr behind port.
func (env *nfEnv) injectNeighborReply(a nfAddrs, port int, mac tcpip.LinkAddress, addr tcpip.Address) {
	if !a.isIPv6() {
		reply := make([]byte, header.ARPSize)
		h := header.ARP(reply)
		h.SetIPv4OverEthernet()
		h.SetOp(header.ARPReply)
		copy(h.HardwareAddressSender(), mac)
		copy(h.ProtocolAddressSender(), addr.AsSlice())
		copy(h.HardwareAddressTarget(), nfBridgeMAC)
		copy(h.ProtocolAddressTarget(), a.bridge.AsSlice())
		env.injectFrame(port, mac, nfBridgeMAC, header.ARPProtocolNumber, reply)
		return
	}
	ser := header.NDPOptionsSerializer{header.NDPTargetLinkLayerAddressOption(mac)}
	naSize := header.ICMPv6NeighborAdvertMinimumSize + ser.Length()
	b := make([]byte, header.IPv6MinimumSize+naSize)
	header.IPv6(b).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(naSize),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          header.NDPHopLimit,
		SrcAddr:           addr,
		DstAddr:           a.bridge,
	})
	icmp := header.ICMPv6(b[header.IPv6MinimumSize:])
	icmp.SetType(header.ICMPv6NeighborAdvert)
	na := header.NDPNeighborAdvert(icmp.MessageBody())
	na.SetSolicitedFlag(true)
	na.SetOverrideFlag(true)
	na.SetTargetAddress(addr)
	na.Options().Serialize(ser)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: addr, Dst: a.bridge}))
	env.injectFrame(port, mac, nfBridgeMAC, header.IPv6ProtocolNumber, b)
}

// linkHeaders is a packet endpoint that records the link addresses of the
// frames with a link header that a NIC sends, as they are when the NIC sends
// them. A packet socket queues the frame's buffer without copying it, as
// dev_queue_xmit_nit queues a clone in Linux. Frames that the bridge's network
// layer sends, such as neighbor solicitations, get their link header from the
// port they are sent out of.
type linkHeaders struct {
	mu sync.Mutex
	// +checklocks:mu
	addrs [][2]tcpip.LinkAddress
}

// HandlePacket implements stack.PacketEndpoint.HandlePacket.
func (l *linkHeaders) HandlePacket(_ tcpip.NICID, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if pkt.PktType != tcpip.PacketOutgoing || len(pkt.LinkHeader().Slice()) < header.EthernetMinimumSize {
		return
	}
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	l.mu.Lock()
	defer l.mu.Unlock()
	l.addrs = append(l.addrs, [2]tcpip.LinkAddress{eth.SourceAddress(), eth.DestinationAddress()})
}

// get returns the source and destination link addresses of the frames l
// recorded.
func (l *linkHeaders) get() [][2]tcpip.LinkAddress {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.addrs)
}

// TestBridgeNetfilterDNATSlowPath checks that a frame DNATed to a host on the
// bridge whose link address isn't known waits for it, as
// br_nf_pre_routing_finish_bridge_slow does: the bridge sends it from its own
// link address, as packet sockets on the bridge see, and the frame leaves with
// its source link address restored.
func TestBridgeNetfilterDNATSlowPath(t *testing.T) {
	for _, a := range nfProtocols {
		t.Run(a.name(), func(t *testing.T) {
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
			var headers linkHeaders
			if err := env.s.RegisterPacketEndpoint(nfBridgeID, header.EthernetProtocolAll, &headers); err != nil {
				t.Fatalf("s.RegisterPacketEndpoint(%d, %d, _): %s", nfBridgeID, header.EthernetProtocolAll, err)
			}
			defer env.s.UnregisterPacketEndpoint(nfBridgeID, header.EthernetProtocolAll, &headers)
			setRule(env.s, stack.NATID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, tcpip.Address{}, a.vip), &stack.DNATTarget{
				Addr:            a.hostB,
				Port:            nfServicePort,
				NetworkProtocol: a.proto,
				ChangeAddress:   true,
				ChangePort:      true,
			})

			env.inject(nfPortA, nfBridgeMAC, a.proto, udpPacket(a, a.hostA, a.vip, nfClientPort, nfVIPPort, 64))
			if pkt := env.read(nfPortB); pkt != nil {
				t.Fatalf("port B sent out frame %+v before the link address of host B was resolved", parseFrame(t, pkt))
			}
			env.injectNeighborReply(a, nfPortB, nfHostBMAC, a.hostB)

			want := frame{srcMAC: nfHostAMAC, dstMAC: nfHostBMAC, src: a.hostA, dst: a.hostB, srcPort: nfClientPort, dstPort: nfServicePort, ttl: 64, validChecksums: true}
			if got := parseFrame(t, env.readWait(t, nfPortB)); got != want {
				t.Errorf("got frame %+v, want %+v", got, want)
			}
			env.expectNone(t)
			if got, want := headers.get(), [][2]tcpip.LinkAddress{{nfBridgeMAC, nfHostBMAC}}; !slices.Equal(got, want) {
				t.Errorf("got frames sent by the bridge with link addresses (source, destination) %q, want %q", got, want)
			}
		})
	}
}

// TestBridgeNetfilterDNATLocal checks that a frame for another host that is
// DNATed to a local address is passed up and delivered, as
// br_nf_pre_routing_finish does by giving it the bridge's link address.
// Without bridge netfilter, the frame is bridged to that other host.
func TestBridgeNetfilterDNATLocal(t *testing.T) {
	for _, a := range nfProtocols {
		for _, call := range []bool{false, true} {
			name := a.name() + "/call off"
			if call {
				name = a.name() + "/call on"
			}
			t.Run(name, func(t *testing.T) {
				env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: call, CallIP6Tables: call})
				var wq waiter.Queue
				ep, err := env.s.NewEndpoint(udp.ProtocolNumber, a.proto, &wq)
				if err != nil {
					t.Fatalf("s.NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, a.proto, err)
				}
				defer ep.Close()
				if err := ep.Bind(tcpip.FullAddress{Addr: a.bridge, Port: nfServicePort}); err != nil {
					t.Fatalf("ep.Bind(%s:%d): %s", a.bridge, nfServicePort, err)
				}
				setRule(env.s, stack.NATID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, tcpip.Address{}, a.vip), &stack.DNATTarget{
					Addr:            a.bridge,
					Port:            nfServicePort,
					NetworkProtocol: a.proto,
					ChangeAddress:   true,
					ChangePort:      true,
				})

				env.inject(nfPortA, nfHostBMAC, a.proto, udpPacket(a, a.hostA, a.vip, nfClientPort, nfVIPPort, 64))
				var buf bytes.Buffer
				res, readErr := ep.Read(&buf, tcpip.ReadOptions{NeedRemoteAddr: true})
				pkt := env.read(nfPortB)
				if !call {
					if readErr == nil {
						t.Errorf("got datagram from %+v delivered, want none", res.RemoteAddr)
					}
					if pkt == nil {
						t.Fatal("port B didn't send out the frame")
					}
					if got := parseFrame(t, pkt); got.dst != a.vip {
						t.Errorf("got frame for %s, want for %s", got.dst, a.vip)
					}
					return
				}
				if readErr != nil {
					t.Fatalf("ep.Read(): %s", readErr)
				}
				if want := (tcpip.FullAddress{Addr: a.hostA, Port: nfClientPort}); res.RemoteAddr.Addr != want.Addr || res.RemoteAddr.Port != want.Port {
					t.Errorf("got datagram from %+v, want from %+v", res.RemoteAddr, want)
				}
				if pkt != nil {
					t.Errorf("port B sent out frame %+v, want none", parseFrame(t, pkt))
				}
			})
		}
	}
}

// TestBridgeNetfilterConntrackReply checks that the reply to a DNATed
// bridged frame is un-DNATed in the Postrouting hook, with checksums that
// match the rewritten headers, and that frames of other flows are not.
func TestBridgeNetfilterConntrackReply(t *testing.T) {
	for _, a := range nfProtocols {
		t.Run(a.name(), func(t *testing.T) {
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
			if err := env.s.AddStaticNeighbor(nfBridgeID, a.proto, a.hostB, nfHostBMAC); err != nil {
				t.Fatalf("s.AddStaticNeighbor(%d, %d, %s, %s): %s", nfBridgeID, a.proto, a.hostB, nfHostBMAC, err)
			}
			setRule(env.s, stack.NATID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, tcpip.Address{}, a.vip), &stack.DNATTarget{
				Addr:            a.hostB,
				Port:            nfServicePort,
				NetworkProtocol: a.proto,
				ChangeAddress:   true,
				ChangePort:      true,
			})
			env.inject(nfPortA, nfBridgeMAC, a.proto, udpPacket(a, a.hostA, a.vip, nfClientPort, nfVIPPort, 64))
			pkt := env.read(nfPortB)
			if pkt == nil {
				t.Fatal("port B didn't send out the DNATed frame")
			}
			pkt.DecRef()

			env.inject(nfPortB, nfHostAMAC, a.proto, udpPacket(a, a.hostB, a.hostA, nfServicePort, nfClientPort, 64))
			pkt = env.read(nfPortA)
			if pkt == nil {
				t.Fatal("port A didn't send out the reply")
			}
			if got, want := parseFrame(t, pkt), (frame{srcMAC: nfHostBMAC, dstMAC: nfHostAMAC, src: a.vip, dst: a.hostA, srcPort: nfVIPPort, dstPort: nfClientPort, ttl: 64, validChecksums: true}); got != want {
				t.Errorf("got reply %+v, want %+v", got, want)
			}

			// A frame of another flow is left alone.
			env.inject(nfPortB, nfHostAMAC, a.proto, udpPacket(a, a.hostB, a.hostA, nfServicePort+1, nfClientPort, 64))
			pkt = env.read(nfPortA)
			if pkt == nil {
				t.Fatal("port A didn't send out the frame of another flow")
			}
			if got, want := parseFrame(t, pkt), (frame{srcMAC: nfHostBMAC, dstMAC: nfHostAMAC, src: a.hostB, dst: a.hostA, srcPort: nfServicePort + 1, dstPort: nfClientPort, ttl: 64, validChecksums: true}); got != want {
				t.Errorf("got frame %+v, want %+v", got, want)
			}
		})
	}
}

// TestBridgeNetfilterMasqueradeHairpin checks a host reaching itself through a
// virtual address, as kube-proxy sets up: the frame is DNATed back to the
// host, MASQUERADEd to the bridge's address and sent back out of the port in
// hairpin mode, and the reply is un-NATed the same way.
func TestBridgeNetfilterMasqueradeHairpin(t *testing.T) {
	for _, a := range nfProtocols {
		for _, hairpin := range []bool{false, true} {
			name := a.name() + "/hairpin off"
			if hairpin {
				name = a.name() + "/hairpin on"
			}
			t.Run(name, func(t *testing.T) {
				env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
				if hairpin {
					if err := env.s.SetBridgePortFlags(nfPortIDs[nfPortA], stack.BridgePortHairpin, 0); err != nil {
						t.Fatalf("s.SetBridgePortFlags(%d, %#x, 0): %s", nfPortIDs[nfPortA], stack.BridgePortHairpin, err)
					}
				}
				if err := env.s.AddStaticNeighbor(nfBridgeID, a.proto, a.hostA, nfHostAMAC); err != nil {
					t.Fatalf("s.AddStaticNeighbor(%d, %d, %s, %s): %s", nfBridgeID, a.proto, a.hostA, nfHostAMAC, err)
				}
				setRule(env.s, stack.NATID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, tcpip.Address{}, a.vip), &stack.DNATTarget{
					Addr:            a.hostA,
					Port:            nfServicePort,
					NetworkProtocol: a.proto,
					ChangeAddress:   true,
					ChangePort:      true,
				})
				setRule(env.s, stack.NATID, stack.Postrouting, a, a.filter(header.UDPProtocolNumber, a.hostA, a.hostA), &stack.MasqueradeTarget{NetworkProtocol: a.proto})

				env.inject(nfPortA, nfBridgeMAC, a.proto, udpPacket(a, a.hostA, a.vip, nfClientPort, nfVIPPort, 64))
				pkt := env.read(nfPortA)
				if !hairpin {
					if pkt != nil {
						t.Errorf("port A sent out frame %+v without hairpin mode", parseFrame(t, pkt))
					}
					env.expectNone(t)
					return
				}
				if pkt == nil {
					t.Fatal("port A didn't send out the frame")
				}
				got := parseFrame(t, pkt)
				if want := (frame{srcMAC: nfHostAMAC, dstMAC: nfHostAMAC, src: a.bridge, dst: a.hostA, srcPort: got.srcPort, dstPort: nfServicePort, ttl: 64, validChecksums: true}); got != want {
					t.Errorf("got frame %+v, want %+v", got, want)
				}

				env.inject(nfPortA, nfBridgeMAC, a.proto, udpPacket(a, a.hostA, a.bridge, nfServicePort, got.srcPort, 64))
				pkt = env.read(nfPortA)
				if pkt == nil {
					t.Fatal("port A didn't send out the reply")
				}
				if got, want := parseFrame(t, pkt), (frame{srcMAC: nfHostAMAC, dstMAC: nfHostAMAC, src: a.vip, dst: a.hostA, srcPort: nfVIPPort, dstPort: nfClientPort, ttl: 64, validChecksums: true}); got != want {
					t.Errorf("got reply %+v, want %+v", got, want)
				}
				env.expectNone(t)
			})
		}
	}
}

// TestBridgeNetfilterReset checks that, as nf_send_reset and nf_send_reset6
// do, the TCP reset for a bridged segment is sent out of the port it was
// received on, from the link address it was sent to.
func TestBridgeNetfilterReset(t *testing.T) {
	for _, a := range nfProtocols {
		for _, call := range []bool{false, true} {
			name := a.name() + "/call off"
			if call {
				name = a.name() + "/call on"
			}
			t.Run(name, func(t *testing.T) {
				env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: call, CallIP6Tables: call})
				var target stack.Target
				if a.isIPv6() {
					target = &stack.RejectIPv6Target{
						Handler:    env.s.NetworkProtocolInstance(a.proto).(stack.RejectIPv6WithHandler),
						RejectWith: stack.RejectIPv6WithTCPReset,
					}
				} else {
					target = &stack.RejectIPv4Target{
						Handler:    env.s.NetworkProtocolInstance(a.proto).(stack.RejectIPv4WithHandler),
						RejectWith: stack.RejectIPv4WithTCPReset,
					}
				}
				setRule(env.s, stack.FilterID, stack.Forward, a, a.filter(header.TCPProtocolNumber, tcpip.Address{}, tcpip.Address{}), target)

				env.inject(nfPortA, nfHostBMAC, a.proto, tcpSYN(a, a.hostA, a.hostB, nfClientPort, nfServicePort))
				if !call {
					pkt := env.read(nfPortB)
					if pkt == nil {
						t.Fatal("port B didn't send out the segment")
					}
					if got := parseFrame(t, pkt); got.tcpFlags != header.TCPFlagSyn {
						t.Errorf("got segment with flags %s, want %s", got.tcpFlags, header.TCPFlagSyn)
					}
					env.expectNone(t)
					return
				}
				pkt := env.read(nfPortA)
				if pkt == nil {
					t.Fatal("port A didn't send out a reset")
				}
				got := parseFrame(t, pkt)
				want := frame{srcMAC: nfHostBMAC, dstMAC: nfHostAMAC, src: a.hostB, dst: a.hostA, srcPort: nfServicePort, dstPort: nfClientPort, ttl: got.ttl, tcpFlags: header.TCPFlagRst | header.TCPFlagAck, validChecksums: true}
				if got != want {
					t.Errorf("got reset %+v, want %+v", got, want)
				}
				env.expectNone(t)
			})
		}
	}
}

// TestBridgeNetfilterShortARP checks that, as br_nf_forward_arp does, a
// forwarded ARP frame too short for an ARP header is dropped only when
// bridge-nf-call-arptables is set.
func TestBridgeNetfilterShortARP(t *testing.T) {
	for _, call := range []bool{false, true} {
		name := "call off"
		if call {
			name = "call on"
		}
		t.Run(name, func(t *testing.T) {
			env := newNFEnv(t, stack.BridgeNetfilter{CallARPTables: call})
			for _, size := range []int{7, 8} {
				env.inject(nfPortA, nfHostBMAC, header.ARPProtocolNumber, make([]byte, size))
				pkt := env.chs[nfPortB].Read()
				want := size == 8 || !call
				if got := pkt != nil; got != want {
					t.Errorf("got %d-byte ARP frame forwarded = %t, want %t", size, got, want)
				}
				if pkt != nil {
					pkt.DecRef()
				}
			}
		})
	}
}

// TestBridgeNetfilterPreroutingOnce checks that, as ip_sabotage_in does, a
// frame that went through the Prerouting hook on the bridge doesn't go
// through it again when it is passed up.
func TestBridgeNetfilterPreroutingOnce(t *testing.T) {
	for _, a := range nfProtocols {
		t.Run(a.name(), func(t *testing.T) {
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
			var wq waiter.Queue
			ep, err := env.s.NewEndpoint(udp.ProtocolNumber, a.proto, &wq)
			if err != nil {
				t.Fatalf("s.NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, a.proto, err)
			}
			defer ep.Close()
			if err := ep.Bind(tcpip.FullAddress{Addr: a.bridge, Port: nfServicePort}); err != nil {
				t.Fatalf("ep.Bind(%s:%d): %s", a.bridge, nfServicePort, err)
			}
			setRule(env.s, stack.NATID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, tcpip.Address{}, a.vip), &stack.DNATTarget{
				Addr:            a.bridge,
				Port:            nfServicePort,
				NetworkProtocol: a.proto,
				ChangeAddress:   true,
				ChangePort:      true,
			})
			// Only a second pass through the hook sees the DNATed address.
			setRule(env.s, stack.MangleID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, tcpip.Address{}, a.bridge), &stack.DropTarget{NetworkProtocol: a.proto})

			env.inject(nfPortA, nfBridgeMAC, a.proto, udpPacket(a, a.hostA, a.vip, nfClientPort, nfVIPPort, 64))
			var buf bytes.Buffer
			res, err := ep.Read(&buf, tcpip.ReadOptions{NeedRemoteAddr: true})
			if err != nil {
				t.Fatalf("ep.Read(): %s", err)
			}
			if want := (tcpip.FullAddress{Addr: a.hostA, Port: nfClientPort}); res.RemoteAddr.Addr != want.Addr || res.RemoteAddr.Port != want.Port {
				t.Errorf("got datagram from %+v, want from %+v", res.RemoteAddr, want)
			}
		})
	}
}

// ifnameData returns the data of an nftables comparison with an interface
// name.
func ifnameData(name string) string {
	var b [16]byte
	copy(b[:], name)
	var words []string
	for i := 0; i < len(b); i += 4 {
		words = append(words, fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(b[i:])))
	}
	return strings.Join(words, " ")
}

// TestBridgeNetfilterNFTablesForward checks that bridged frames go through
// the nftables Forward hook with the bridge as the input and output
// interface, as br_nf_forward_ip passes them.
func TestBridgeNetfilterNFTablesForward(t *testing.T) {
	for _, a := range nfProtocols {
		for _, call := range []bool{false, true} {
			name := a.name() + "/call off"
			if call {
				name = a.name() + "/call on"
			}
			t.Run(name, func(t *testing.T) {
				nftables.EnableNFTables()
				env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: call, CallIP6Tables: call})
				nf := nftables.NewNFTables(env.s, env.s.Clock(), env.s.SecureRNG())
				family := stack.IP
				if a.isIPv6() {
					family = stack.IP6
				}
				tab, err := nf.AddTable(family, "filter", false /* errorOnDuplicate */)
				if err != nil {
					t.Fatalf("nf.AddTable(%v, filter, false): %s", family, err)
				}
				chain, err := nf.AddChainToTable(tab, "forward", nftables.NewBaseChainInfo(nftables.BaseChainTypeFilter, stack.NFForward, nftables.NewIntPriority(0), "" /* device */, false /* policyDrop */), "" /* comment */, false /* errorOnDuplicate */, 0 /* chainFlags */, nil /* udata */, linux.NF_ACCEPT)
				if err != nil {
					t.Fatalf("nf.AddChainToTable(_, forward, ...): %s", err)
				}
				// iifname "br0" oifname "br0" drop
				rule, err := nftables.InterpretRule(fmt.Sprintf(`
[ meta load iifname => reg 1 ]
[ cmp eq reg 1 %[1]s ]
[ meta load oifname => reg 1 ]
[ cmp eq reg 1 %[1]s ]
[ immediate reg 0 drop ]`, ifnameData(nfBridgeName)))
				if err != nil {
					t.Fatalf("nftables.InterpretRule(_): %s", err)
				}
				if err := chain.RegisterRule(rule, -1); err != nil {
					t.Fatalf("chain.RegisterRule(_, -1): %s", err)
				}
				env.s.SetNFTables(nf)
				env.s.SetNFTablesConfigured(true)

				env.inject(nfPortA, nfHostBMAC, a.proto, udpPacket(a, a.hostA, a.hostB, nfClientPort, nfServicePort, 64))
				pkt := env.read(nfPortB)
				if gotFwd := pkt != nil; gotFwd == call {
					t.Errorf("got frame forwarded = %t, want %t", gotFwd, !call)
				}
				if pkt != nil {
					pkt.DecRef()
				}
			})
		}
	}
}

// TestBridgeNetfilterDNATRouted checks that, as br_nf_pre_routing_finish
// does, a bridged frame DNATed to a host behind another interface is given
// the bridge's link address and routed by the network layer.
func TestBridgeNetfilterDNATRouted(t *testing.T) {
	for _, a := range nfProtocols {
		t.Run(a.name(), func(t *testing.T) {
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
			if err := env.s.SetForwardingDefaultAndAllNICs(a.proto, true); err != nil {
				t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, true): %s", a.proto, err)
			}
			setRule(env.s, stack.NATID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, tcpip.Address{}, a.vip), &stack.DNATTarget{
				Addr:            a.uplinkHost,
				Port:            nfServicePort,
				NetworkProtocol: a.proto,
				ChangeAddress:   true,
				ChangePort:      true,
			})

			// The frame is for host B, so the bridge would bridge it there
			// without routing it.
			env.inject(nfPortA, nfHostBMAC, a.proto, udpPacket(a, a.hostA, a.vip, nfClientPort, nfVIPPort, 64))
			pkt := env.read(nfUplink)
			if pkt == nil {
				t.Fatal("the uplink didn't send out the frame")
			}
			if got, want := parseFrame(t, pkt), (frame{srcMAC: nfUplinkMAC, dstMAC: nfUplinkHostMAC, src: a.hostA, dst: a.uplinkHost, srcPort: nfClientPort, dstPort: nfServicePort, ttl: 63, validChecksums: true}); got != want {
				t.Errorf("got frame %+v, want %+v", got, want)
			}
			env.expectNone(t)
		})
	}
}

// TestBridgeNetfilterPreroutingDropNotLearned checks that the bridge learns
// the source of a frame only once the Prerouting hook accepted it, as
// br_nf_pre_routing runs before br_handle_frame_finish.
func TestBridgeNetfilterPreroutingDropNotLearned(t *testing.T) {
	for _, a := range nfProtocols {
		t.Run(a.name(), func(t *testing.T) {
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
			setRule(env.s, stack.MangleID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, a.hostC, tcpip.Address{}), &stack.DropTarget{NetworkProtocol: a.proto})

			env.injectFrame(nfPortA, nfHostCMAC, nfHostBMAC, a.proto, udpPacket(a, a.hostC, a.hostB, nfClientPort, nfServicePort, 64))
			env.expectNone(t)
			if got := env.bridge.FindFDBEntry(nfHostCMAC).PortLinkAddress(); got != "" {
				t.Errorf("got %s learned behind the port with link address %s from a dropped frame, want not learned", nfHostCMAC, got)
			}

			env.injectFrame(nfPortA, nfHostCMAC, nfHostBMAC, a.proto, udpPacket(a, a.hostA, a.hostB, nfClientPort, nfServicePort, 64))
			pkt := env.read(nfPortB)
			if pkt == nil {
				t.Fatal("port B didn't send out the frame")
			}
			pkt.DecRef()
			if got := env.bridge.FindFDBEntry(nfHostCMAC).PortLinkAddress(); got != nfPortAMAC {
				t.Errorf("got %s learned behind the port with link address %q, want %s", nfHostCMAC, got, nfPortAMAC)
			}
		})
	}
}

// countTarget is a target that counts the packets it sees and accepts them.
type countTarget struct {
	n int
}

// Action implements stack.Target.Action.
func (c *countTarget) Action(*stack.PacketBuffer, stack.Hook, *stack.Route, stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	c.n++
	return stack.RuleAccept, 0
}

// TestBridgeNetfilterForwardFlood checks that, as br_flood passes each
// clone, a flooded frame goes through the Forward hook once for each port it
// is sent out of.
func TestBridgeNetfilterForwardFlood(t *testing.T) {
	for _, a := range nfProtocols {
		t.Run(a.name(), func(t *testing.T) {
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
			var count countTarget
			setRule(env.s, stack.FilterID, stack.Forward, a, a.filter(header.UDPProtocolNumber, a.hostA, tcpip.Address{}), &count)

			env.inject(nfPortA, nfUnknownMAC, a.proto, udpPacket(a, a.hostA, a.hostB, nfClientPort, nfServicePort, 64))
			for _, port := range []int{nfPortB, nfPortC} {
				pkt := env.read(port)
				if pkt == nil {
					t.Fatalf("port %d didn't send out the flooded frame", port)
				}
				if got, want := parseFrame(t, pkt), (frame{srcMAC: nfHostAMAC, dstMAC: nfUnknownMAC, src: a.hostA, dst: a.hostB, srcPort: nfClientPort, dstPort: nfServicePort, ttl: 64, validChecksums: true}); got != want {
					t.Errorf("got frame %+v out of port %d, want %+v", got, port, want)
				}
			}
			env.expectNone(t)
			if got, want := count.n, 2; got != want {
				t.Errorf("got %d frames through the Forward hook, want %d", got, want)
			}
		})
	}
}

// TestBridgeNetfilterFloodGSO checks that each copy of a flooded frame keeps
// its GSO options, so that NAT keeps its partial checksum.
func TestBridgeNetfilterFloodGSO(t *testing.T) {
	for _, a := range nfProtocols {
		t.Run(a.name(), func(t *testing.T) {
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
			// Conntrack doesn't validate a partial checksum, as nf_ip_checksum
			// doesn't for CHECKSUM_PARTIAL.
			env.chs[nfPortA].LinkEPCapabilities |= stack.CapabilityRXChecksumOffload
			setRule(env.s, stack.NATID, stack.Postrouting, a, a.filter(header.TCPProtocolNumber, a.hostA, tcpip.Address{}), &stack.SNATTarget{
				Addr:            a.hostC,
				NetworkProtocol: a.proto,
				ChangeAddress:   true,
			})

			b := tcpSYN(a, a.hostA, a.hostB, nfClientPort, nfServicePort)
			gso := stack.GSO{Type: stack.GSOTCPv4, NeedsCsum: true, CsumOffset: 16, MSS: 1000, L3HdrLen: header.IPv4MinimumSize}
			if a.isIPv6() {
				gso.Type, gso.L3HdrLen = stack.GSOTCPv6, header.IPv6MinimumSize
			}
			header.TCP(b[gso.L3HdrLen:]).SetChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, a.hostA, a.hostB, 0))
			pkt := makeEthernetFrame(nfHostAMAC, nfUnknownMAC, a.proto, b)
			pkt.GSOOptions = gso
			env.chs[nfPortA].InjectInbound(a.proto, pkt)
			pkt.DecRef()

			wantXsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, a.hostC, a.hostB, 0)
			for _, port := range []int{nfPortB, nfPortC} {
				pkt := env.read(port)
				if pkt == nil {
					t.Fatalf("port %d didn't send out the flooded frame", port)
				}
				if pkt.GSOOptions != gso {
					t.Errorf("got GSO options %+v out of port %d, want %+v", pkt.GSOOptions, port, gso)
				}
				v := pkt.ToView()
				b := v.AsSlice()[header.EthernetMinimumSize:]
				var src tcpip.Address
				if a.isIPv6() {
					src = header.IPv6(b).SourceAddress()
				} else {
					src = header.IPv4(b).SourceAddress()
				}
				xsum := header.TCP(b[gso.L3HdrLen:]).Checksum()
				v.Release()
				pkt.DecRef()
				if src != a.hostC {
					t.Errorf("got frame from %s out of port %d, want from %s", src, port, a.hostC)
				}
				if xsum != wantXsum {
					t.Errorf("got partial checksum %#04x out of port %d, want %#04x", xsum, port, wantXsum)
				}
			}
			env.expectNone(t)
		})
	}
}

// unreachable is an ICMP or ICMPv6 destination unreachable message.
type unreachable struct {
	dstMAC tcpip.LinkAddress
	dst    tcpip.Address
	code   uint8
}

// parseUnreachable parses an ICMP or ICMPv6 destination unreachable message
// sent out of a port and releases it.
func parseUnreachable(t *testing.T, a nfAddrs, pkt *stack.PacketBuffer) unreachable {
	t.Helper()
	v := pkt.ToView()
	defer v.Release()
	defer pkt.DecRef()
	b := v.AsSlice()
	u := unreachable{dstMAC: header.Ethernet(b).DestinationAddress()}
	b = b[header.EthernetMinimumSize:]
	if a.isIPv6() {
		ip := header.IPv6(b)
		icmp := header.ICMPv6(ip.Payload())
		if ip.NextHeader() != uint8(header.ICMPv6ProtocolNumber) || icmp.Type() != header.ICMPv6DstUnreachable {
			t.Fatalf("got packet % x, want an ICMPv6 destination unreachable message", v.AsSlice())
		}
		u.dst, u.code = ip.DestinationAddress(), uint8(icmp.Code())
		return u
	}
	ip := header.IPv4(b)
	icmp := header.ICMPv4(ip.Payload())
	if ip.TransportProtocol() != header.ICMPv4ProtocolNumber || icmp.Type() != header.ICMPv4DstUnreachable {
		t.Fatalf("got packet % x, want an ICMP destination unreachable message", v.AsSlice())
	}
	u.dst, u.code = ip.DestinationAddress(), uint8(icmp.Code())
	return u
}

// TestBridgeNetfilterDNATLinkResolutionFailure checks that, when the link
// address of the host on the bridge a frame is DNATed to can't be resolved,
// the source of the frame gets an ICMP host unreachable or ICMPv6 address
// unreachable, as arp_error_report and ndisc_error_report send.
func TestBridgeNetfilterDNATLinkResolutionFailure(t *testing.T) {
	for _, a := range nfProtocols {
		t.Run(a.name(), func(t *testing.T) {
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
			cfg := stack.DefaultNUDConfigurations()
			cfg.MaxMulticastProbes = 1
			cfg.RetransmitTimer = time.Millisecond
			if err := env.s.SetNUDConfigurations(nfBridgeID, a.proto, cfg); err != nil {
				t.Fatalf("s.SetNUDConfigurations(%d, %d, _): %s", nfBridgeID, a.proto, err)
			}
			if err := env.s.AddStaticNeighbor(nfBridgeID, a.proto, a.hostA, nfHostAMAC); err != nil {
				t.Fatalf("s.AddStaticNeighbor(%d, %d, %s, %s): %s", nfBridgeID, a.proto, a.hostA, nfHostAMAC, err)
			}
			setRule(env.s, stack.NATID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, tcpip.Address{}, a.vip), &stack.DNATTarget{
				Addr:            a.hostB,
				Port:            nfServicePort,
				NetworkProtocol: a.proto,
				ChangeAddress:   true,
				ChangePort:      true,
			})

			env.inject(nfPortA, nfBridgeMAC, a.proto, udpPacket(a, a.hostA, a.vip, nfClientPort, nfVIPPort, 64))
			want := unreachable{dstMAC: nfHostAMAC, dst: a.hostA, code: uint8(header.ICMPv4HostUnreachable)}
			if a.isIPv6() {
				want.code = uint8(header.ICMPv6AddressUnreachable)
			}
			if got := parseUnreachable(t, a, env.readWait(t, nfPortA)); got != want {
				t.Errorf("got %+v, want %+v", got, want)
			}
			// The bridge floods what the network layer sends out of it.
			for _, port := range []int{nfPortB, nfPortC} {
				pkt := env.read(port)
				if pkt == nil {
					continue
				}
				if got := parseUnreachable(t, a, pkt); got != want {
					t.Errorf("got %+v out of port %d, want %+v or nothing", got, port, want)
				}
			}
		})
	}
}

// TestBridgeNetfilterDNATBridgedWithoutAddress checks that a frame DNATed to
// a host on a bridge without an address stays bridged, as ip_route_input and
// ip6_route_input route it without one. The route takes the address of the
// uplink, which must forward for it to be valid, but IPv6 still doesn't need
// forwarding on the bridge.
func TestBridgeNetfilterDNATBridgedWithoutAddress(t *testing.T) {
	for _, a := range nfProtocols {
		t.Run(a.name(), func(t *testing.T) {
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
			if _, err := env.s.SetNICForwarding(nfUplinkID, a.proto, true); err != nil {
				t.Fatalf("s.SetNICForwarding(%d, %d, true): %s", nfUplinkID, a.proto, err)
			}
			if err := env.s.RemoveAddress(nfBridgeID, a.bridge); err != nil {
				t.Fatalf("s.RemoveAddress(%d, %s): %s", nfBridgeID, a.bridge, err)
			}
			if err := env.s.AddStaticNeighbor(nfBridgeID, a.proto, a.hostB, nfHostBMAC); err != nil {
				t.Fatalf("s.AddStaticNeighbor(%d, %d, %s, %s): %s", nfBridgeID, a.proto, a.hostB, nfHostBMAC, err)
			}
			setRule(env.s, stack.NATID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, tcpip.Address{}, a.vip), &stack.DNATTarget{
				Addr:            a.hostB,
				Port:            nfServicePort,
				NetworkProtocol: a.proto,
				ChangeAddress:   true,
				ChangePort:      true,
			})

			env.inject(nfPortA, nfBridgeMAC, a.proto, udpPacket(a, a.hostA, a.vip, nfClientPort, nfVIPPort, 64))
			pkt := env.read(nfPortB)
			if pkt == nil {
				t.Fatal("port B didn't send out the frame")
			}
			if got, want := parseFrame(t, pkt), (frame{srcMAC: nfHostAMAC, dstMAC: nfHostBMAC, src: a.hostA, dst: a.hostB, srcPort: nfClientPort, dstPort: nfServicePort, ttl: 64, validChecksums: true}); got != want {
				t.Errorf("got frame %+v, want %+v", got, want)
			}
			env.expectNone(t)
		})
	}
}

// groupDst returns the broadcast or multicast address and link address of a
// frame that the bridge floods and passes up.
func (a nfAddrs) groupDst() (tcpip.Address, tcpip.LinkAddress) {
	if a.isIPv6() {
		return header.IPv6AllNodesMulticastAddress, header.EthernetAddressFromMulticastIPv6Address(header.IPv6AllNodesMulticastAddress)
	}
	return tcpip.AddrFrom4([4]byte{10, 0, 0, 255}), header.EthernetBroadcastAddress
}

// injectWithHeadroom is like inject, but the frame has room for the headers
// of any port, so that it isn't copied for that.
func (env *nfEnv) injectWithHeadroom(port int, dst tcpip.LinkAddress, proto tcpip.NetworkProtocolNumber, payload []byte) {
	frame := make([]byte, header.EthernetMinimumSize+len(payload))
	header.Ethernet(frame).Encode(&header.EthernetFields{SrcAddr: nfHostAMAC, DstAddr: dst, Type: proto})
	copy(frame[header.EthernetMinimumSize:], payload)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 128,
		Payload:            buffer.MakeWithData(frame),
	})
	env.chs[port].InjectInbound(proto, pkt)
	pkt.DecRef()
}

// TestBridgeNetfilterFloodPassUpRewrite checks that a frame that is flooded
// and passed up is copied before the Forward hook rewrites it, as
// nft_payload_set_eval unshares the clones br_flood makes, so the copy passed
// up is as it was received.
func TestBridgeNetfilterFloodPassUpRewrite(t *testing.T) {
	for _, a := range nfProtocols {
		t.Run(a.name(), func(t *testing.T) {
			nftables.EnableNFTables()
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
			nf := nftables.NewNFTables(env.s, env.s.Clock(), env.s.SecureRNG())
			family := stack.IP
			// Set the TTL, updating the header checksum, or the hop limit to 7.
			write := "[ payload write reg 1 => 1b @ network header + 8 csum_type 1 csum_off 10 csum_flags 0x0 ]"
			if a.isIPv6() {
				family = stack.IP6
				write = "[ payload write reg 1 => 1b @ network header + 7 csum_type 0 csum_off 0 csum_flags 0x0 ]"
			}
			tab, err := nf.AddTable(family, "filter", false /* errorOnDuplicate */)
			if err != nil {
				t.Fatalf("nf.AddTable(%v, filter, false): %s", family, err)
			}
			chain, err := nf.AddChainToTable(tab, "forward", nftables.NewBaseChainInfo(nftables.BaseChainTypeFilter, stack.NFForward, nftables.NewIntPriority(0), "" /* device */, false /* policyDrop */), "" /* comment */, false /* errorOnDuplicate */, 0 /* chainFlags */, nil /* udata */, linux.NF_ACCEPT)
			if err != nil {
				t.Fatalf("nf.AddChainToTable(_, forward, ...): %s", err)
			}
			rule, err := nftables.InterpretRule("[ immediate reg 1 0x07070707 ]\n" + write)
			if err != nil {
				t.Fatalf("nftables.InterpretRule(_): %s", err)
			}
			if err := chain.RegisterRule(rule, -1); err != nil {
				t.Fatalf("chain.RegisterRule(_, -1): %s", err)
			}
			env.s.SetNFTables(nf)
			env.s.SetNFTablesConfigured(true)

			var wq waiter.Queue
			ep, tcpipErr := env.s.NewEndpoint(udp.ProtocolNumber, a.proto, &wq)
			if tcpipErr != nil {
				t.Fatalf("s.NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, a.proto, tcpipErr)
			}
			defer ep.Close()
			ep.SocketOptions().SetReceiveTTL(true)
			ep.SocketOptions().SetReceiveHopLimit(true)
			if err := ep.Bind(tcpip.FullAddress{Port: nfServicePort}); err != nil {
				t.Fatalf("ep.Bind(:%d): %s", nfServicePort, err)
			}

			dst, dstMAC := a.groupDst()
			env.injectWithHeadroom(nfPortA, dstMAC, a.proto, udpPacket(a, a.hostA, dst, nfClientPort, nfServicePort, 64))
			for _, port := range []int{nfPortB, nfPortC} {
				pkt := env.read(port)
				if pkt == nil {
					t.Fatalf("port %d didn't send out the frame", port)
				}
				if got, want := parseFrame(t, pkt), (frame{srcMAC: nfHostAMAC, dstMAC: dstMAC, src: a.hostA, dst: dst, srcPort: nfClientPort, dstPort: nfServicePort, ttl: 7, validChecksums: true}); got != want {
					t.Errorf("got frame %+v out of port %d, want %+v", got, port, want)
				}
			}
			var buf bytes.Buffer
			res, readErr := ep.Read(&buf, tcpip.ReadOptions{NeedRemoteAddr: true})
			if readErr != nil {
				t.Fatalf("ep.Read(): %s", readErr)
			}
			ttl := res.ControlMessages.TTL
			if a.isIPv6() {
				ttl = res.ControlMessages.HopLimit
			}
			if res.RemoteAddr.Addr != a.hostA || ttl != 64 {
				t.Errorf("got datagram from %s with TTL %d passed up, want from %s with TTL 64", res.RemoteAddr.Addr, ttl, a.hostA)
			}
		})
	}
}

// TestBridgeNetfilterFloodPassUpSNAT checks that the copy of a flooded frame
// that is passed up shares its connection, so it is SNATed as the flooded
// copies are, as nf_nat_ipv4_local_in and nf_nat_ipv6_local_in apply the
// binding that the Postrouting hook made.
func TestBridgeNetfilterFloodPassUpSNAT(t *testing.T) {
	for _, a := range nfProtocols {
		t.Run(a.name(), func(t *testing.T) {
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
			setRule(env.s, stack.NATID, stack.Postrouting, a, a.filter(header.UDPProtocolNumber, a.hostA, tcpip.Address{}), &stack.SNATTarget{Addr: a.hostC, NetworkProtocol: a.proto, ChangeAddress: true})
			var wq waiter.Queue
			ep, tcpipErr := env.s.NewEndpoint(udp.ProtocolNumber, a.proto, &wq)
			if tcpipErr != nil {
				t.Fatalf("s.NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, a.proto, tcpipErr)
			}
			defer ep.Close()
			if err := ep.Bind(tcpip.FullAddress{Port: nfServicePort}); err != nil {
				t.Fatalf("ep.Bind(:%d): %s", nfServicePort, err)
			}

			dst, dstMAC := a.groupDst()
			env.injectWithHeadroom(nfPortA, dstMAC, a.proto, udpPacket(a, a.hostA, dst, nfClientPort, nfServicePort, 64))
			for _, port := range []int{nfPortB, nfPortC} {
				pkt := env.read(port)
				if pkt == nil {
					t.Fatalf("port %d didn't send out the frame", port)
				}
				if got, want := parseFrame(t, pkt), (frame{srcMAC: nfHostAMAC, dstMAC: dstMAC, src: a.hostC, dst: dst, srcPort: nfClientPort, dstPort: nfServicePort, ttl: 64, validChecksums: true}); got != want {
					t.Errorf("got frame %+v out of port %d, want %+v", got, port, want)
				}
			}
			var buf bytes.Buffer
			res, readErr := ep.Read(&buf, tcpip.ReadOptions{NeedRemoteAddr: true})
			if readErr != nil {
				t.Fatalf("ep.Read(): %s", readErr)
			}
			if res.RemoteAddr.Addr != a.hostC {
				t.Errorf("got datagram from %s passed up, want from %s", res.RemoteAddr.Addr, a.hostC)
			}
		})
	}
}

// TestBridgeNetfilterDNATSourceInterface checks the interface whose address
// the route of a frame DNATed to a host on a bridge without an address takes:
// as in inet_select_addr, the interfaces are tried in index order and
// loopback addresses are skipped, and the first one that forwards is taken.
func TestBridgeNetfilterDNATSourceInterface(t *testing.T) {
	const (
		loopbackID = 1
		otherID    = 2
	)
	for _, a := range nfProtocols {
		for _, uplinkForwards := range []bool{true, false} {
			if !uplinkForwards && !a.isIPv6() {
				// IPv4 passes up a frame without a route to the network layer,
				// which may route it.
				continue
			}
			name := a.name() + "/uplink forwards"
			if !uplinkForwards {
				name = a.name() + "/only loopback forwards"
			}
			t.Run(name, func(t *testing.T) {
				env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
				loopbackAddr := tcpip.AddressWithPrefix{Address: header.IPv4Loopback, PrefixLen: 8}
				otherAddr := tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{172, 16, 0, 1}), PrefixLen: 24}
				if a.isIPv6() {
					loopbackAddr = tcpip.AddressWithPrefix{Address: header.IPv6Loopback, PrefixLen: 128}
					otherAddr = tcpip.AddressWithPrefix{Address: tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), PrefixLen: 64}
				}
				other := channel.New(1, 1500, "\x02\x00\x00\x00\x00\x06")
				defer other.Close()
				for _, nic := range []struct {
					id      tcpip.NICID
					ep      stack.LinkEndpoint
					addr    tcpip.AddressWithPrefix
					forward bool
				}{
					{loopbackID, loopback.New(), loopbackAddr, true},
					{otherID, ethernet.New(other), otherAddr, false},
				} {
					if err := env.s.CreateNIC(nic.id, nic.ep); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nic.id, err)
					}
					if err := env.s.AddProtocolAddress(nic.id, tcpip.ProtocolAddress{Protocol: a.proto, AddressWithPrefix: nic.addr}, stack.AddressProperties{}); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %s, {}): %s", nic.id, nic.addr, err)
					}
					if _, err := env.s.SetNICForwarding(nic.id, a.proto, nic.forward); err != nil {
						t.Fatalf("s.SetNICForwarding(%d, %d, %t): %s", nic.id, a.proto, nic.forward, err)
					}
				}
				if _, err := env.s.SetNICForwarding(nfUplinkID, a.proto, uplinkForwards); err != nil {
					t.Fatalf("s.SetNICForwarding(%d, %d, %t): %s", nfUplinkID, a.proto, uplinkForwards, err)
				}
				if err := env.s.RemoveAddress(nfBridgeID, a.bridge); err != nil {
					t.Fatalf("s.RemoveAddress(%d, %s): %s", nfBridgeID, a.bridge, err)
				}
				if err := env.s.AddStaticNeighbor(nfBridgeID, a.proto, a.hostB, nfHostBMAC); err != nil {
					t.Fatalf("s.AddStaticNeighbor(%d, %d, %s, %s): %s", nfBridgeID, a.proto, a.hostB, nfHostBMAC, err)
				}
				setRule(env.s, stack.NATID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, tcpip.Address{}, a.vip), &stack.DNATTarget{
					Addr:            a.hostB,
					Port:            nfServicePort,
					NetworkProtocol: a.proto,
					ChangeAddress:   true,
					ChangePort:      true,
				})

				// The NICs are kept in a map, so try many times to catch an
				// order that depends on iterating it.
				for i := uint16(0); i < 32; i++ {
					env.inject(nfPortA, nfBridgeMAC, a.proto, udpPacket(a, a.hostA, a.vip, nfClientPort+i, nfVIPPort, 64))
					pkt := env.read(nfPortB)
					if !uplinkForwards {
						if pkt != nil {
							t.Fatalf("port B sent out frame %+v with the route taking a loopback address", parseFrame(t, pkt))
						}
						continue
					}
					if pkt == nil {
						t.Fatalf("port B didn't send out frame %d", i)
					}
					if got, want := parseFrame(t, pkt), (frame{srcMAC: nfHostAMAC, dstMAC: nfHostBMAC, src: a.hostA, dst: a.hostB, srcPort: nfClientPort + i, dstPort: nfServicePort, ttl: 64, validChecksums: true}); got != want {
						t.Fatalf("got frame %+v, want %+v", got, want)
					}
				}
				env.expectNone(t)
			})
		}
	}
}

// isSolicitation returns whether pkt is an ARP request or an NDP neighbor
// solicitation for target.
func isSolicitation(pkt *stack.PacketBuffer, target tcpip.Address) bool {
	v := pkt.ToView()
	defer v.Release()
	b := v.AsSlice()
	switch header.Ethernet(b).Type() {
	case header.ARPProtocolNumber:
		arpHdr := header.ARP(b[header.EthernetMinimumSize:])
		return arpHdr.Op() == header.ARPRequest && tcpip.AddrFromSlice(arpHdr.ProtocolAddressTarget()) == target
	case header.IPv6ProtocolNumber:
		ip := header.IPv6(b[header.EthernetMinimumSize:])
		if ip.NextHeader() != uint8(header.ICMPv6ProtocolNumber) {
			return false
		}
		icmp := header.ICMPv6(ip.Payload())
		return icmp.Type() == header.ICMPv6NeighborSolicit && header.NDPNeighborSolicit(icmp.MessageBody()).TargetAddress() == target
	}
	return false
}

// TestBridgeNetfilterDNATSlowPathWithoutAddress checks what happens to a frame
// DNATed to a host on a bridge without an address whose link address isn't
// known. The bridge doesn't solicit it: ARP and NDP take the source address
// of a solicitation only from the interface it is sent out of. For IPv4, this
// differs from arp_solicit, which takes the address of another interface
// with inet_select_addr and bridges the frame once the host replies; the
// frame is reported unreachable instead. For IPv6, ndisc_send_ns doesn't
// solicit without a link-local address either, and the frame is dropped.
func TestBridgeNetfilterDNATSlowPathWithoutAddress(t *testing.T) {
	for _, a := range nfProtocols {
		t.Run(a.name(), func(t *testing.T) {
			env := newNFEnv(t, stack.BridgeNetfilter{CallIPTables: true, CallIP6Tables: true})
			cfg := stack.DefaultNUDConfigurations()
			cfg.MaxMulticastProbes = 1
			cfg.RetransmitTimer = time.Millisecond
			if err := env.s.SetNUDConfigurations(nfBridgeID, a.proto, cfg); err != nil {
				t.Fatalf("s.SetNUDConfigurations(%d, %d, _): %s", nfBridgeID, a.proto, err)
			}
			if _, err := env.s.SetNICForwarding(nfUplinkID, a.proto, true); err != nil {
				t.Fatalf("s.SetNICForwarding(%d, %d, true): %s", nfUplinkID, a.proto, err)
			}
			if err := env.s.RemoveAddress(nfBridgeID, a.bridge); err != nil {
				t.Fatalf("s.RemoveAddress(%d, %s): %s", nfBridgeID, a.bridge, err)
			}
			if err := env.s.AddStaticNeighbor(nfBridgeID, a.proto, a.hostA, nfHostAMAC); err != nil {
				t.Fatalf("s.AddStaticNeighbor(%d, %d, %s, %s): %s", nfBridgeID, a.proto, a.hostA, nfHostAMAC, err)
			}
			setRule(env.s, stack.NATID, stack.Prerouting, a, a.filter(header.UDPProtocolNumber, tcpip.Address{}, a.vip), &stack.DNATTarget{
				Addr:            a.hostB,
				Port:            nfServicePort,
				NetworkProtocol: a.proto,
				ChangeAddress:   true,
				ChangePort:      true,
			})

			env.inject(nfPortA, nfBridgeMAC, a.proto, udpPacket(a, a.hostA, a.vip, nfClientPort, nfVIPPort, 64))
			// Wait for link resolution to fail.
			deadline := time.Now().Add(5 * time.Second)
			for {
				neighbors, err := env.s.Neighbors(nfBridgeID, a.proto)
				if err != nil {
					t.Fatalf("s.Neighbors(%d, %d): %s", nfBridgeID, a.proto, err)
				}
				i := slices.IndexFunc(neighbors, func(n stack.NeighborEntry) bool { return n.Addr == a.hostB })
				if i >= 0 && neighbors[i].State == stack.Unreachable {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("link resolution of %s didn't fail within 5s: %+v", a.hostB, neighbors)
				}
				time.Sleep(time.Millisecond)
			}
			var unreachables []unreachable
			for port, ch := range env.chs {
				for pkt := ch.Read(); pkt != nil; pkt = ch.Read() {
					switch {
					case isSolicitation(pkt, a.hostB):
						t.Errorf("port %d sent out a solicitation for %s", port, a.hostB)
						pkt.DecRef()
					case isNeighborFrame(pkt):
						pkt.DecRef()
					case port == nfPortA:
						unreachables = append(unreachables, parseUnreachable(t, a, pkt))
					default:
						// The bridge floods what the network layer sends out of it.
						if got := parseUnreachable(t, a, pkt); port == nfUplink || got.dst != a.hostA {
							t.Errorf("port %d sent out %+v", port, got)
						}
					}
				}
			}
			var want []unreachable
			if !a.isIPv6() {
				want = []unreachable{{dstMAC: nfHostAMAC, dst: a.hostA, code: uint8(header.ICMPv4HostUnreachable)}}
			}
			if !slices.Equal(unreachables, want) {
				t.Errorf("got %+v out of port A, want %+v", unreachables, want)
			}
		})
	}
}
