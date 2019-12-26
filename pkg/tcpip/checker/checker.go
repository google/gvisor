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

// Package checker provides helper functions to check networking packets for
// validity.
package checker

import (
	"encoding/binary"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// NetworkChecker is a function to check a property of a network packet.
type NetworkChecker func(*testing.T, []header.Network)

// TransportChecker is a function to check a property of a transport packet.
type TransportChecker func(*testing.T, header.Transport)

// IPv4 checks the validity and properties of the given IPv4 packet. It is
// expected to be used in conjunction with other network checkers for specific
// properties. For example, to check the source and destination address, one
// would call:
//
// checker.IPv4(t, b, checker.SrcAddr(x), checker.DstAddr(y))
func IPv4(t *testing.T, b []byte, checkers ...NetworkChecker) {
	t.Helper()

	ipv4 := header.IPv4(b)

	if !ipv4.IsValid(len(b)) {
		t.Error("Not a valid IPv4 packet")
	}

	xsum := ipv4.CalculateChecksum()
	if xsum != 0 && xsum != 0xffff {
		t.Errorf("Bad checksum: 0x%x, checksum in packet: 0x%x", xsum, ipv4.Checksum())
	}

	for _, f := range checkers {
		f(t, []header.Network{ipv4})
	}
	if t.Failed() {
		t.FailNow()
	}
}

// IPv6 checks the validity and properties of the given IPv6 packet. The usage
// is similar to IPv4.
func IPv6(t *testing.T, b []byte, checkers ...NetworkChecker) {
	t.Helper()

	ipv6 := header.IPv6(b)
	if !ipv6.IsValid(len(b)) {
		t.Error("Not a valid IPv6 packet")
	}

	for _, f := range checkers {
		f(t, []header.Network{ipv6})
	}
	if t.Failed() {
		t.FailNow()
	}
}

// SrcAddr creates a checker that checks the source address.
func SrcAddr(addr tcpip.Address) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		if a := h[0].SourceAddress(); a != addr {
			t.Errorf("Bad source address, got %v, want %v", a, addr)
		}
	}
}

// DstAddr creates a checker that checks the destination address.
func DstAddr(addr tcpip.Address) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		if a := h[0].DestinationAddress(); a != addr {
			t.Errorf("Bad destination address, got %v, want %v", a, addr)
		}
	}
}

// TTL creates a checker that checks the TTL (ipv4) or HopLimit (ipv6).
func TTL(ttl uint8) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		var v uint8
		switch ip := h[0].(type) {
		case header.IPv4:
			v = ip.TTL()
		case header.IPv6:
			v = ip.HopLimit()
		}
		if v != ttl {
			t.Fatalf("Bad TTL, got %v, want %v", v, ttl)
		}
	}
}

// PayloadLen creates a checker that checks the payload length.
func PayloadLen(plen int) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		if l := len(h[0].Payload()); l != plen {
			t.Errorf("Bad payload length, got %v, want %v", l, plen)
		}
	}
}

// FragmentOffset creates a checker that checks the FragmentOffset field.
func FragmentOffset(offset uint16) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		// We only do this of IPv4 for now.
		switch ip := h[0].(type) {
		case header.IPv4:
			if v := ip.FragmentOffset(); v != offset {
				t.Errorf("Bad fragment offset, got %v, want %v", v, offset)
			}
		}
	}
}

// FragmentFlags creates a checker that checks the fragment flags field.
func FragmentFlags(flags uint8) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		// We only do this of IPv4 for now.
		switch ip := h[0].(type) {
		case header.IPv4:
			if v := ip.Flags(); v != flags {
				t.Errorf("Bad fragment offset, got %v, want %v", v, flags)
			}
		}
	}
}

// TOS creates a checker that checks the TOS field.
func TOS(tos uint8, label uint32) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		if v, l := h[0].TOS(); v != tos || l != label {
			t.Errorf("Bad TOS, got (%v, %v), want (%v,%v)", v, l, tos, label)
		}
	}
}

// Raw creates a checker that checks the bytes of payload.
// The checker always checks the payload of the last network header.
// For instance, in case of IPv6 fragments, the payload that will be checked
// is the one containing the actual data that the packet is carrying, without
// the bytes added by the IPv6 fragmentation.
func Raw(want []byte) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		if got := h[len(h)-1].Payload(); !reflect.DeepEqual(got, want) {
			t.Errorf("Wrong payload, got %v, want %v", got, want)
		}
	}
}

// IPv6Fragment creates a checker that validates an IPv6 fragment.
func IPv6Fragment(checkers ...NetworkChecker) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		if p := h[0].TransportProtocol(); p != header.IPv6FragmentHeader {
			t.Errorf("Bad protocol, got %v, want %v", p, header.UDPProtocolNumber)
		}

		ipv6Frag := header.IPv6Fragment(h[0].Payload())
		if !ipv6Frag.IsValid() {
			t.Error("Not a valid IPv6 fragment")
		}

		for _, f := range checkers {
			f(t, []header.Network{h[0], ipv6Frag})
		}
		if t.Failed() {
			t.FailNow()
		}
	}
}

// TCP creates a checker that checks that the transport protocol is TCP and
// potentially additional transport header fields.
func TCP(checkers ...TransportChecker) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		first := h[0]
		last := h[len(h)-1]

		if p := last.TransportProtocol(); p != header.TCPProtocolNumber {
			t.Errorf("Bad protocol, got %v, want %v", p, header.TCPProtocolNumber)
		}

		// Verify the checksum.
		tcp := header.TCP(last.Payload())
		l := uint16(len(tcp))

		xsum := header.Checksum([]byte(first.SourceAddress()), 0)
		xsum = header.Checksum([]byte(first.DestinationAddress()), xsum)
		xsum = header.Checksum([]byte{0, byte(last.TransportProtocol())}, xsum)
		xsum = header.Checksum([]byte{byte(l >> 8), byte(l)}, xsum)
		xsum = header.Checksum(tcp, xsum)

		if xsum != 0 && xsum != 0xffff {
			t.Errorf("Bad checksum: 0x%x, checksum in segment: 0x%x", xsum, tcp.Checksum())
		}

		// Run the transport checkers.
		for _, f := range checkers {
			f(t, tcp)
		}
		if t.Failed() {
			t.FailNow()
		}
	}
}

// UDP creates a checker that checks that the transport protocol is UDP and
// potentially additional transport header fields.
func UDP(checkers ...TransportChecker) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		last := h[len(h)-1]

		if p := last.TransportProtocol(); p != header.UDPProtocolNumber {
			t.Errorf("Bad protocol, got %v, want %v", p, header.UDPProtocolNumber)
		}

		udp := header.UDP(last.Payload())
		for _, f := range checkers {
			f(t, udp)
		}
		if t.Failed() {
			t.FailNow()
		}
	}
}

// SrcPort creates a checker that checks the source port.
func SrcPort(port uint16) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		if p := h.SourcePort(); p != port {
			t.Errorf("Bad source port, got %v, want %v", p, port)
		}
	}
}

// DstPort creates a checker that checks the destination port.
func DstPort(port uint16) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		if p := h.DestinationPort(); p != port {
			t.Errorf("Bad destination port, got %v, want %v", p, port)
		}
	}
}

// SeqNum creates a checker that checks the sequence number.
func SeqNum(seq uint32) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}

		if s := tcp.SequenceNumber(); s != seq {
			t.Errorf("Bad sequence number, got %v, want %v", s, seq)
		}
	}
}

// AckNum creates a checker that checks the ack number.
func AckNum(seq uint32) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()
		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}

		if s := tcp.AckNumber(); s != seq {
			t.Errorf("Bad ack number, got %v, want %v", s, seq)
		}
	}
}

// Window creates a checker that checks the tcp window.
func Window(window uint16) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}

		if w := tcp.WindowSize(); w != window {
			t.Errorf("Bad window, got 0x%x, want 0x%x", w, window)
		}
	}
}

// TCPFlags creates a checker that checks the tcp flags.
func TCPFlags(flags uint8) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}

		if f := tcp.Flags(); f != flags {
			t.Errorf("Bad flags, got 0x%x, want 0x%x", f, flags)
		}
	}
}

// TCPFlagsMatch creates a checker that checks that the tcp flags, masked by the
// given mask, match the supplied flags.
func TCPFlagsMatch(flags, mask uint8) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}

		if f := tcp.Flags(); (f & mask) != (flags & mask) {
			t.Errorf("Bad masked flags, got 0x%x, want 0x%x, mask 0x%x", f, flags, mask)
		}
	}
}

// TCPSynOptions creates a checker that checks the presence of TCP options in
// SYN segments.
//
// If wndscale is negative, the window scale option must not be present.
func TCPSynOptions(wantOpts header.TCPSynOptions) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}
		opts := tcp.Options()
		limit := len(opts)
		foundMSS := false
		foundWS := false
		foundTS := false
		foundSACKPermitted := false
		tsVal := uint32(0)
		tsEcr := uint32(0)
		for i := 0; i < limit; {
			switch opts[i] {
			case header.TCPOptionEOL:
				i = limit
			case header.TCPOptionNOP:
				i++
			case header.TCPOptionMSS:
				v := uint16(opts[i+2])<<8 | uint16(opts[i+3])
				if wantOpts.MSS != v {
					t.Errorf("Bad MSS: got %v, want %v", v, wantOpts.MSS)
				}
				foundMSS = true
				i += 4
			case header.TCPOptionWS:
				if wantOpts.WS < 0 {
					t.Error("WS present when it shouldn't be")
				}
				v := int(opts[i+2])
				if v != wantOpts.WS {
					t.Errorf("Bad WS: got %v, want %v", v, wantOpts.WS)
				}
				foundWS = true
				i += 3
			case header.TCPOptionTS:
				if i+9 >= limit {
					t.Errorf("TS Option truncated , option is only: %d bytes, want 10", limit-i)
				}
				if opts[i+1] != 10 {
					t.Errorf("Bad length %d for TS option, limit: %d", opts[i+1], limit)
				}
				tsVal = binary.BigEndian.Uint32(opts[i+2:])
				tsEcr = uint32(0)
				if tcp.Flags()&header.TCPFlagAck != 0 {
					// If the syn is an SYN-ACK then read
					// the tsEcr value as well.
					tsEcr = binary.BigEndian.Uint32(opts[i+6:])
				}
				foundTS = true
				i += 10
			case header.TCPOptionSACKPermitted:
				if i+1 >= limit {
					t.Errorf("SACKPermitted option truncated, option is only : %d bytes, want 2", limit-i)
				}
				if opts[i+1] != 2 {
					t.Errorf("Bad length %d for SACKPermitted option, limit: %d", opts[i+1], limit)
				}
				foundSACKPermitted = true
				i += 2

			default:
				i += int(opts[i+1])
			}
		}

		if !foundMSS {
			t.Errorf("MSS option not found. Options: %x", opts)
		}

		if !foundWS && wantOpts.WS >= 0 {
			t.Errorf("WS option not found. Options: %x", opts)
		}
		if wantOpts.TS && !foundTS {
			t.Errorf("TS option not found. Options: %x", opts)
		}
		if foundTS && tsVal == 0 {
			t.Error("TS option specified but the timestamp value is zero")
		}
		if foundTS && tsEcr == 0 && wantOpts.TSEcr != 0 {
			t.Errorf("TS option specified but TSEcr is incorrect: got %d, want: %d", tsEcr, wantOpts.TSEcr)
		}
		if wantOpts.SACKPermitted && !foundSACKPermitted {
			t.Errorf("SACKPermitted option not found. Options: %x", opts)
		}
	}
}

// TCPTimestampChecker creates a checker that validates that a TCP segment has a
// TCP Timestamp option if wantTS is true, it also compares the wantTSVal and
// wantTSEcr values with those in the TCP segment (if present).
//
// If wantTSVal or wantTSEcr is zero then the corresponding comparison is
// skipped.
func TCPTimestampChecker(wantTS bool, wantTSVal uint32, wantTSEcr uint32) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}
		opts := []byte(tcp.Options())
		limit := len(opts)
		foundTS := false
		tsVal := uint32(0)
		tsEcr := uint32(0)
		for i := 0; i < limit; {
			switch opts[i] {
			case header.TCPOptionEOL:
				i = limit
			case header.TCPOptionNOP:
				i++
			case header.TCPOptionTS:
				if i+9 >= limit {
					t.Errorf("TS option found, but option is truncated, option length: %d, want 10 bytes", limit-i)
				}
				if opts[i+1] != 10 {
					t.Errorf("TS option found, but bad length specified: %d, want: 10", opts[i+1])
				}
				tsVal = binary.BigEndian.Uint32(opts[i+2:])
				tsEcr = binary.BigEndian.Uint32(opts[i+6:])
				foundTS = true
				i += 10
			default:
				// We don't recognize this option, just skip over it.
				if i+2 > limit {
					return
				}
				l := int(opts[i+1])
				if i < 2 || i+l > limit {
					return
				}
				i += l
			}
		}

		if wantTS != foundTS {
			t.Errorf("TS Option mismatch: got TS= %v, want TS= %v", foundTS, wantTS)
		}
		if wantTS && wantTSVal != 0 && wantTSVal != tsVal {
			t.Errorf("Timestamp value is incorrect: got: %d, want: %d", tsVal, wantTSVal)
		}
		if wantTS && wantTSEcr != 0 && tsEcr != wantTSEcr {
			t.Errorf("Timestamp Echo Reply is incorrect: got: %d, want: %d", tsEcr, wantTSEcr)
		}
	}
}

// TCPNoSACKBlockChecker creates a checker that verifies that the segment does not
// contain any SACK blocks in the TCP options.
func TCPNoSACKBlockChecker() TransportChecker {
	return TCPSACKBlockChecker(nil)
}

// TCPSACKBlockChecker creates a checker that verifies that the segment does
// contain the specified SACK blocks in the TCP options.
func TCPSACKBlockChecker(sackBlocks []header.SACKBlock) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()
		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}
		var gotSACKBlocks []header.SACKBlock

		opts := []byte(tcp.Options())
		limit := len(opts)
		for i := 0; i < limit; {
			switch opts[i] {
			case header.TCPOptionEOL:
				i = limit
			case header.TCPOptionNOP:
				i++
			case header.TCPOptionSACK:
				if i+2 > limit {
					// Malformed SACK block.
					t.Errorf("malformed SACK option in options: %v", opts)
				}
				sackOptionLen := int(opts[i+1])
				if i+sackOptionLen > limit || (sackOptionLen-2)%8 != 0 {
					// Malformed SACK block.
					t.Errorf("malformed SACK option length in options: %v", opts)
				}
				numBlocks := sackOptionLen / 8
				for j := 0; j < numBlocks; j++ {
					start := binary.BigEndian.Uint32(opts[i+2+j*8:])
					end := binary.BigEndian.Uint32(opts[i+2+j*8+4:])
					gotSACKBlocks = append(gotSACKBlocks, header.SACKBlock{
						Start: seqnum.Value(start),
						End:   seqnum.Value(end),
					})
				}
				i += sackOptionLen
			default:
				// We don't recognize this option, just skip over it.
				if i+2 > limit {
					break
				}
				l := int(opts[i+1])
				if l < 2 || i+l > limit {
					break
				}
				i += l
			}
		}

		if !reflect.DeepEqual(gotSACKBlocks, sackBlocks) {
			t.Errorf("SACKBlocks are not equal, got: %v, want: %v", gotSACKBlocks, sackBlocks)
		}
	}
}

// Payload creates a checker that checks the payload.
func Payload(want []byte) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		if got := h.Payload(); !reflect.DeepEqual(got, want) {
			t.Errorf("Wrong payload, got %v, want %v", got, want)
		}
	}
}

// ICMPv4 creates a checker that checks that the transport protocol is ICMPv4 and
// potentially additional ICMPv4 header fields.
func ICMPv4(checkers ...TransportChecker) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		last := h[len(h)-1]

		if p := last.TransportProtocol(); p != header.ICMPv4ProtocolNumber {
			t.Fatalf("Bad protocol, got %d, want %d", p, header.ICMPv4ProtocolNumber)
		}

		icmp := header.ICMPv4(last.Payload())
		for _, f := range checkers {
			f(t, icmp)
		}
		if t.Failed() {
			t.FailNow()
		}
	}
}

// ICMPv4Type creates a checker that checks the ICMPv4 Type field.
func ICMPv4Type(want header.ICMPv4Type) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()
		icmpv4, ok := h.(header.ICMPv4)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker got: %+v, want: header.ICMPv4", h)
		}
		if got := icmpv4.Type(); got != want {
			t.Fatalf("unexpected icmp type got: %d, want: %d", got, want)
		}
	}
}

// ICMPv4Code creates a checker that checks the ICMPv4 Code field.
func ICMPv4Code(want byte) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()
		icmpv4, ok := h.(header.ICMPv4)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker got: %+v, want: header.ICMPv4", h)
		}
		if got := icmpv4.Code(); got != want {
			t.Fatalf("unexpected ICMP code got: %d, want: %d", got, want)
		}
	}
}

// ICMPv6 creates a checker that checks that the transport protocol is ICMPv6 and
// potentially additional ICMPv6 header fields.
//
// ICMPv6 will validate the checksum field before calling checkers.
func ICMPv6(checkers ...TransportChecker) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		last := h[len(h)-1]

		if p := last.TransportProtocol(); p != header.ICMPv6ProtocolNumber {
			t.Fatalf("Bad protocol, got %d, want %d", p, header.ICMPv6ProtocolNumber)
		}

		icmp := header.ICMPv6(last.Payload())
		if got, want := icmp.Checksum(), header.ICMPv6Checksum(icmp, last.SourceAddress(), last.DestinationAddress(), buffer.VectorisedView{}); got != want {
			t.Fatalf("Bad ICMPv6 checksum; got %d, want %d", got, want)
		}

		for _, f := range checkers {
			f(t, icmp)
		}
		if t.Failed() {
			t.FailNow()
		}
	}
}

// ICMPv6Type creates a checker that checks the ICMPv6 Type field.
func ICMPv6Type(want header.ICMPv6Type) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()
		icmpv6, ok := h.(header.ICMPv6)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker got: %+v, want: header.ICMPv6", h)
		}
		if got := icmpv6.Type(); got != want {
			t.Fatalf("unexpected icmp type got: %d, want: %d", got, want)
		}
	}
}

// ICMPv6Code creates a checker that checks the ICMPv6 Code field.
func ICMPv6Code(want byte) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()
		icmpv6, ok := h.(header.ICMPv6)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker got: %+v, want: header.ICMPv6", h)
		}
		if got := icmpv6.Code(); got != want {
			t.Fatalf("unexpected ICMP code got: %d, want: %d", got, want)
		}
	}
}

// NDP creates a checker that checks that the packet contains a valid NDP
// message for type of ty, with potentially additional checks specified by
// checkers.
//
// checkers may assume that a valid ICMPv6 is passed to it containing a valid
// NDP message as far as the size of the message (minSize) is concerned. The
// values within the message are up to checkers to validate.
func NDP(msgType header.ICMPv6Type, minSize int, checkers ...TransportChecker) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		// Check normal ICMPv6 first.
		ICMPv6(
			ICMPv6Type(msgType),
			ICMPv6Code(0))(t, h)

		last := h[len(h)-1]

		icmp := header.ICMPv6(last.Payload())
		if got := len(icmp.NDPPayload()); got < minSize {
			t.Fatalf("ICMPv6 NDP (type = %d) payload size of %d is less than the minimum size of %d", msgType, got, minSize)
		}

		for _, f := range checkers {
			f(t, icmp)
		}
		if t.Failed() {
			t.FailNow()
		}
	}
}

// NDPNS creates a checker that checks that the packet contains a valid NDP
// Neighbor Solicitation message (as per the raw wire format), with potentially
// additional checks specified by checkers.
//
// checkers may assume that a valid ICMPv6 is passed to it containing a valid
// NDPNS message as far as the size of the messages concerned. The values within
// the message are up to checkers to validate.
func NDPNS(checkers ...TransportChecker) NetworkChecker {
	return NDP(header.ICMPv6NeighborSolicit, header.NDPNSMinimumSize, checkers...)
}

// NDPNSTargetAddress creates a checker that checks the Target Address field of
// a header.NDPNeighborSolicit.
//
// The returned TransportChecker assumes that a valid ICMPv6 is passed to it
// containing a valid NDPNS message as far as the size is concerned.
func NDPNSTargetAddress(want tcpip.Address) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmp := h.(header.ICMPv6)
		ns := header.NDPNeighborSolicit(icmp.NDPPayload())

		if got := ns.TargetAddress(); got != want {
			t.Fatalf("got %T.TargetAddress = %s, want = %s", ns, got, want)
		}
	}
}
