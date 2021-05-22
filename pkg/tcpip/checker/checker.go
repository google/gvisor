// Copyright 2021 The gVisor Authors.
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
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// NetworkChecker is a function to check a property of a network packet.
type NetworkChecker func(*testing.T, []header.Network)

// TransportChecker is a function to check a property of a transport packet.
type TransportChecker func(*testing.T, header.Transport)

// ControlMessagesChecker is a function to check a property of ancillary data.
type ControlMessagesChecker func(*testing.T, tcpip.ControlMessages)

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

	if !ipv4.IsChecksumValid() {
		t.Errorf("Bad checksum, got = %d", ipv4.Checksum())
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
		t.Helper()

		var v uint8
		switch ip := h[0].(type) {
		case header.IPv4:
			v = ip.TTL()
		case header.IPv6:
			v = ip.HopLimit()
		case *ipv6HeaderWithExtHdr:
			v = ip.HopLimit()
		default:
			t.Fatalf("unrecognized header type %T for TTL evaluation", ip)
		}
		if v != ttl {
			t.Fatalf("Bad TTL, got = %d, want = %d", v, ttl)
		}
	}
}

// IPFullLength creates a checker for the full IP packet length. The
// expected size is checked against both the Total Length in the
// header and the number of bytes received.
func IPFullLength(packetLength uint16) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		var v uint16
		var l uint16
		switch ip := h[0].(type) {
		case header.IPv4:
			v = ip.TotalLength()
			l = uint16(len(ip))
		case header.IPv6:
			v = ip.PayloadLength() + header.IPv6FixedHeaderSize
			l = uint16(len(ip))
		default:
			t.Fatalf("unexpected network header passed to checker, got = %T, want = header.IPv4 or header.IPv6", ip)
		}
		if l != packetLength {
			t.Errorf("bad packet length, got = %d, want = %d", l, packetLength)
		}
		if v != packetLength {
			t.Errorf("unexpected packet length in header, got = %d, want = %d", v, packetLength)
		}
	}
}

// IPv4HeaderLength creates a checker that checks the IPv4 Header length.
func IPv4HeaderLength(headerLength int) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		switch ip := h[0].(type) {
		case header.IPv4:
			if hl := ip.HeaderLength(); hl != uint8(headerLength) {
				t.Errorf("Bad header length, got = %d, want = %d", hl, headerLength)
			}
		default:
			t.Fatalf("unexpected network header passed to checker, got = %T, want = header.IPv4", ip)
		}
	}
}

// PayloadLen creates a checker that checks the payload length.
func PayloadLen(payloadLength int) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		if l := len(h[0].Payload()); l != payloadLength {
			t.Errorf("Bad payload length, got = %d, want = %d", l, payloadLength)
		}
	}
}

// IPPayload creates a checker that checks the payload.
func IPPayload(payload []byte) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		got := h[0].Payload()

		// cmp.Diff does not consider nil slices equal to empty slices, but we do.
		if len(got) == 0 && len(payload) == 0 {
			return
		}

		if diff := cmp.Diff(payload, got); diff != "" {
			t.Errorf("payload mismatch (-want +got):\n%s", diff)
		}
	}
}

// IPv4Options returns a checker that checks the options in an IPv4 packet.
func IPv4Options(want header.IPv4Options) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		ip, ok := h[0].(header.IPv4)
		if !ok {
			t.Fatalf("unexpected network header passed to checker, got = %T, want = header.IPv4", h[0])
		}
		options := ip.Options()
		// cmp.Diff does not consider nil slices equal to empty slices, but we do.
		if len(want) == 0 && len(options) == 0 {
			return
		}
		if diff := cmp.Diff(want, options); diff != "" {
			t.Errorf("options mismatch (-want +got):\n%s", diff)
		}
	}
}

// IPv4RouterAlert returns a checker that checks that the RouterAlert option is
// set in an IPv4 packet.
func IPv4RouterAlert() NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()
		ip, ok := h[0].(header.IPv4)
		if !ok {
			t.Fatalf("unexpected network header passed to checker, got = %T, want = header.IPv4", h[0])
		}
		iterator := ip.Options().MakeIterator()
		for {
			opt, done, err := iterator.Next()
			if err != nil {
				t.Fatalf("error acquiring next IPv4 option at offset %d", err.Pointer)
			}
			if done {
				break
			}
			if opt.Type() != header.IPv4OptionRouterAlertType {
				continue
			}
			want := [header.IPv4OptionRouterAlertLength]byte{
				byte(header.IPv4OptionRouterAlertType),
				header.IPv4OptionRouterAlertLength,
				header.IPv4OptionRouterAlertValue,
				header.IPv4OptionRouterAlertValue,
			}
			if diff := cmp.Diff(want[:], opt.Contents()); diff != "" {
				t.Errorf("router alert option mismatch (-want +got):\n%s", diff)
			}
			return
		}
		t.Errorf("failed to find router alert option in %v", ip.Options())
	}
}

// FragmentOffset creates a checker that checks the FragmentOffset field.
func FragmentOffset(offset uint16) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		// We only do this for IPv4 for now.
		switch ip := h[0].(type) {
		case header.IPv4:
			if v := ip.FragmentOffset(); v != offset {
				t.Errorf("Bad fragment offset, got = %d, want = %d", v, offset)
			}
		}
	}
}

// FragmentFlags creates a checker that checks the fragment flags field.
func FragmentFlags(flags uint8) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		// We only do this for IPv4 for now.
		switch ip := h[0].(type) {
		case header.IPv4:
			if v := ip.Flags(); v != flags {
				t.Errorf("Bad fragment offset, got = %d, want = %d", v, flags)
			}
		}
	}
}

// ReceiveTClass creates a checker that checks the TCLASS field in
// ControlMessages.
func ReceiveTClass(want uint32) ControlMessagesChecker {
	return func(t *testing.T, cm tcpip.ControlMessages) {
		t.Helper()
		if !cm.HasTClass {
			t.Errorf("got cm.HasTClass = %t, want = true", cm.HasTClass)
		} else if got := cm.TClass; got != want {
			t.Errorf("got cm.TClass = %d, want %d", got, want)
		}
	}
}

// ReceiveTOS creates a checker that checks the TOS field in ControlMessages.
func ReceiveTOS(want uint8) ControlMessagesChecker {
	return func(t *testing.T, cm tcpip.ControlMessages) {
		t.Helper()
		if !cm.HasTOS {
			t.Errorf("got cm.HasTOS = %t, want = true", cm.HasTOS)
		} else if got := cm.TOS; got != want {
			t.Errorf("got cm.TOS = %d, want %d", got, want)
		}
	}
}

// ReceiveIPPacketInfo creates a checker that checks the PacketInfo field in
// ControlMessages.
func ReceiveIPPacketInfo(want tcpip.IPPacketInfo) ControlMessagesChecker {
	return func(t *testing.T, cm tcpip.ControlMessages) {
		t.Helper()
		if !cm.HasIPPacketInfo {
			t.Errorf("got cm.HasIPPacketInfo = %t, want = true", cm.HasIPPacketInfo)
		} else if diff := cmp.Diff(want, cm.PacketInfo); diff != "" {
			t.Errorf("IPPacketInfo mismatch (-want +got):\n%s", diff)
		}
	}
}

// ReceiveOriginalDstAddr creates a checker that checks the OriginalDstAddress
// field in ControlMessages.
func ReceiveOriginalDstAddr(want tcpip.FullAddress) ControlMessagesChecker {
	return func(t *testing.T, cm tcpip.ControlMessages) {
		t.Helper()
		if !cm.HasOriginalDstAddress {
			t.Errorf("got cm.HasOriginalDstAddress = %t, want = true", cm.HasOriginalDstAddress)
		} else if diff := cmp.Diff(want, cm.OriginalDstAddress); diff != "" {
			t.Errorf("OriginalDstAddress mismatch (-want +got):\n%s", diff)
		}
	}
}

// TOS creates a checker that checks the TOS field.
func TOS(tos uint8, label uint32) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		if v, l := h[0].TOS(); v != tos || l != label {
			t.Errorf("Bad TOS, got = (%d, %d), want = (%d,%d)", v, l, tos, label)
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
			t.Errorf("Bad protocol, got = %d, want = %d", p, header.UDPProtocolNumber)
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
			t.Errorf("Bad protocol, got = %d, want = %d", p, header.TCPProtocolNumber)
		}

		tcp := header.TCP(last.Payload())
		payload := tcp.Payload()
		payloadChecksum := header.Checksum(payload, 0)
		if !tcp.IsChecksumValid(first.SourceAddress(), first.DestinationAddress(), payloadChecksum, uint16(len(payload))) {
			t.Errorf("Bad checksum, got = %d", tcp.Checksum())
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
			t.Errorf("Bad protocol, got = %d, want = %d", p, header.UDPProtocolNumber)
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
			t.Errorf("Bad source port, got = %d, want = %d", p, port)
		}
	}
}

// DstPort creates a checker that checks the destination port.
func DstPort(port uint16) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		if p := h.DestinationPort(); p != port {
			t.Errorf("Bad destination port, got = %d, want = %d", p, port)
		}
	}
}

// NoChecksum creates a checker that checks if the checksum is zero.
func NoChecksum(noChecksum bool) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		udp, ok := h.(header.UDP)
		if !ok {
			t.Fatalf("UDP header not found in h: %T", h)
		}

		if b := udp.Checksum() == 0; b != noChecksum {
			t.Errorf("bad checksum state, got %t, want %t", b, noChecksum)
		}
	}
}

// TCPSeqNum creates a checker that checks the sequence number.
func TCPSeqNum(seq uint32) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		tcp, ok := h.(header.TCP)
		if !ok {
			t.Fatalf("TCP header not found in h: %T", h)
		}

		if s := tcp.SequenceNumber(); s != seq {
			t.Errorf("Bad sequence number, got = %d, want = %d", s, seq)
		}
	}
}

// TCPAckNum creates a checker that checks the ack number.
func TCPAckNum(seq uint32) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		tcp, ok := h.(header.TCP)
		if !ok {
			t.Fatalf("TCP header not found in h: %T", h)
		}

		if s := tcp.AckNumber(); s != seq {
			t.Errorf("Bad ack number, got = %d, want = %d", s, seq)
		}
	}
}

// TCPWindow creates a checker that checks the tcp window.
func TCPWindow(window uint16) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		tcp, ok := h.(header.TCP)
		if !ok {
			t.Fatalf("TCP header not found in hdr : %T", h)
		}

		if w := tcp.WindowSize(); w != window {
			t.Errorf("Bad window, got %d, want %d", w, window)
		}
	}
}

// TCPWindowGreaterThanEq creates a checker that checks that the TCP window
// is greater than or equal to the provided value.
func TCPWindowGreaterThanEq(window uint16) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		tcp, ok := h.(header.TCP)
		if !ok {
			t.Fatalf("TCP header not found in h: %T", h)
		}

		if w := tcp.WindowSize(); w < window {
			t.Errorf("Bad window, got %d, want > %d", w, window)
		}
	}
}

// TCPWindowLessThanEq creates a checker that checks that the tcp window
// is less than or equal to the provided value.
func TCPWindowLessThanEq(window uint16) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		tcp, ok := h.(header.TCP)
		if !ok {
			t.Fatalf("TCP header not found in h: %T", h)
		}

		if w := tcp.WindowSize(); w > window {
			t.Errorf("Bad window, got %d, want < %d", w, window)
		}
	}
}

// TCPFlags creates a checker that checks the tcp flags.
func TCPFlags(flags header.TCPFlags) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		tcp, ok := h.(header.TCP)
		if !ok {
			t.Fatalf("TCP header not found in h: %T", h)
		}

		if got := tcp.Flags(); got != flags {
			t.Errorf("got tcp.Flags() = %s, want %s", got, flags)
		}
	}
}

// TCPFlagsMatch creates a checker that checks that the tcp flags, masked by the
// given mask, match the supplied flags.
func TCPFlagsMatch(flags, mask header.TCPFlags) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		tcp, ok := h.(header.TCP)
		if !ok {
			t.Fatalf("TCP header not found in h: %T", h)
		}

		if got := tcp.Flags(); (got & mask) != (flags & mask) {
			t.Errorf("got tcp.Flags() = %s, want %s, mask %s", got, flags, mask)
		}
	}
}

// TCPSynOptions creates a checker that checks the presence of TCP options in
// SYN segments.
//
// If wndscale is negative, the window scale option must not be present.
func TCPSynOptions(wantOpts header.TCPSynOptions) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

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
					t.Errorf("Bad MSS, got = %d, want = %d", v, wantOpts.MSS)
				}
				foundMSS = true
				i += 4
			case header.TCPOptionWS:
				if wantOpts.WS < 0 {
					t.Error("WS present when it shouldn't be")
				}
				v := int(opts[i+2])
				if v != wantOpts.WS {
					t.Errorf("Bad WS, got = %d, want = %d", v, wantOpts.WS)
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
			t.Errorf("TS option specified but TSEcr is incorrect, got = %d, want = %d", tsEcr, wantOpts.TSEcr)
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
		t.Helper()

		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}
		opts := tcp.Options()
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
					t.Errorf("TS option found, but bad length specified: got = %d, want = 10", opts[i+1])
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
			t.Errorf("TS Option mismatch, got TS= %t, want TS= %t", foundTS, wantTS)
		}
		if wantTS && wantTSVal != 0 && wantTSVal != tsVal {
			t.Errorf("Timestamp value is incorrect, got = %d, want = %d", tsVal, wantTSVal)
		}
		if wantTS && wantTSEcr != 0 && tsEcr != wantTSEcr {
			t.Errorf("Timestamp Echo Reply is incorrect, got = %d, want = %d", tsEcr, wantTSEcr)
		}
	}
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

		opts := tcp.Options()
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
			t.Errorf("SACKBlocks are not equal, got = %v, want = %v", gotSACKBlocks, sackBlocks)
		}
	}
}

// Payload creates a checker that checks the payload.
func Payload(want []byte) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		if got := h.Payload(); !reflect.DeepEqual(got, want) {
			t.Errorf("Wrong payload, got %v, want %v", got, want)
		}
	}
}

// ICMPv4 creates a checker that checks that the transport protocol is ICMPv4
// and potentially additional ICMPv4 header fields.
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
			t.Fatalf("unexpected transport header passed to checker, got = %T, want = header.ICMPv4", h)
		}
		if got := icmpv4.Type(); got != want {
			t.Fatalf("unexpected icmp type, got = %d, want = %d", got, want)
		}
	}
}

// ICMPv4Code creates a checker that checks the ICMPv4 Code field.
func ICMPv4Code(want header.ICMPv4Code) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmpv4, ok := h.(header.ICMPv4)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker, got = %T, want = header.ICMPv4", h)
		}
		if got := icmpv4.Code(); got != want {
			t.Fatalf("unexpected ICMP code, got = %d, want = %d", got, want)
		}
	}
}

// ICMPv4Ident creates a checker that checks the ICMPv4 echo Ident.
func ICMPv4Ident(want uint16) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmpv4, ok := h.(header.ICMPv4)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker, got = %T, want = header.ICMPv4", h)
		}
		if got := icmpv4.Ident(); got != want {
			t.Fatalf("unexpected ICMP ident, got = %d, want = %d", got, want)
		}
	}
}

// ICMPv4Seq creates a checker that checks the ICMPv4 echo Sequence.
func ICMPv4Seq(want uint16) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmpv4, ok := h.(header.ICMPv4)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker, got = %T, want = header.ICMPv4", h)
		}
		if got := icmpv4.Sequence(); got != want {
			t.Fatalf("unexpected ICMP sequence, got = %d, want = %d", got, want)
		}
	}
}

// ICMPv4Pointer creates a checker that checks the ICMPv4 Param Problem pointer.
func ICMPv4Pointer(want uint8) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmpv4, ok := h.(header.ICMPv4)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker, got = %T, want = header.ICMPv4", h)
		}
		if got := icmpv4.Pointer(); got != want {
			t.Fatalf("unexpected ICMP Param Problem pointer, got = %d, want = %d", got, want)
		}
	}
}

// ICMPv4Checksum creates a checker that checks the ICMPv4 Checksum.
// This assumes that the payload exactly makes up the rest of the slice.
func ICMPv4Checksum() TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmpv4, ok := h.(header.ICMPv4)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker, got = %T, want = header.ICMPv4", h)
		}
		heldChecksum := icmpv4.Checksum()
		icmpv4.SetChecksum(0)
		newChecksum := ^header.Checksum(icmpv4, 0)
		icmpv4.SetChecksum(heldChecksum)
		if heldChecksum != newChecksum {
			t.Errorf("unexpected ICMP checksum, got = %d, want = %d", heldChecksum, newChecksum)
		}
	}
}

// ICMPv4Payload creates a checker that checks the payload in an ICMPv4 packet.
func ICMPv4Payload(want []byte) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmpv4, ok := h.(header.ICMPv4)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker, got = %T, want = header.ICMPv4", h)
		}
		payload := icmpv4.Payload()

		// cmp.Diff does not consider nil slices equal to empty slices, but we do.
		if len(want) == 0 && len(payload) == 0 {
			return
		}

		if diff := cmp.Diff(want, payload); diff != "" {
			t.Errorf("ICMP payload mismatch (-want +got):\n%s", diff)
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
		if got, want := icmp.Checksum(), header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: icmp,
			Src:    last.SourceAddress(),
			Dst:    last.DestinationAddress(),
		}); got != want {
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
			t.Fatalf("unexpected transport header passed to checker, got = %T, want = header.ICMPv6", h)
		}
		if got := icmpv6.Type(); got != want {
			t.Fatalf("unexpected icmp type, got = %d, want = %d", got, want)
		}
	}
}

// ICMPv6Code creates a checker that checks the ICMPv6 Code field.
func ICMPv6Code(want header.ICMPv6Code) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmpv6, ok := h.(header.ICMPv6)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker, got = %T, want = header.ICMPv6", h)
		}
		if got := icmpv6.Code(); got != want {
			t.Fatalf("unexpected ICMP code, got = %d, want = %d", got, want)
		}
	}
}

// ICMPv6TypeSpecific creates a checker that checks the ICMPv6 TypeSpecific
// field.
func ICMPv6TypeSpecific(want uint32) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmpv6, ok := h.(header.ICMPv6)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker, got = %T, want = header.ICMPv6", h)
		}
		if got := icmpv6.TypeSpecific(); got != want {
			t.Fatalf("unexpected ICMP TypeSpecific, got = %d, want = %d", got, want)
		}
	}
}

// ICMPv6Payload creates a checker that checks the payload in an ICMPv6 packet.
func ICMPv6Payload(want []byte) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmpv6, ok := h.(header.ICMPv6)
		if !ok {
			t.Fatalf("unexpected transport header passed to checker, got = %T, want = header.ICMPv6", h)
		}
		payload := icmpv6.Payload()

		// cmp.Diff does not consider nil slices equal to empty slices, but we do.
		if len(want) == 0 && len(payload) == 0 {
			return
		}

		if diff := cmp.Diff(want, payload); diff != "" {
			t.Errorf("ICMP payload mismatch (-want +got):\n%s", diff)
		}
	}
}

// MLD creates a checker that checks that the packet contains a valid MLD
// message for type of mldType, with potentially additional checks specified by
// checkers.
//
// Checkers may assume that a valid ICMPv6 is passed to it containing a valid
// MLD message as far as the size of the message (minSize) is concerned. The
// values within the message are up to checkers to validate.
func MLD(msgType header.ICMPv6Type, minSize int, checkers ...TransportChecker) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		// Check normal ICMPv6 first.
		ICMPv6(
			ICMPv6Type(msgType),
			ICMPv6Code(0))(t, h)

		last := h[len(h)-1]

		icmp := header.ICMPv6(last.Payload())
		if got := len(icmp.MessageBody()); got < minSize {
			t.Fatalf("ICMPv6 MLD (type = %d) payload size of %d is less than the minimum size of %d", msgType, got, minSize)
		}

		for _, f := range checkers {
			f(t, icmp)
		}
		if t.Failed() {
			t.FailNow()
		}
	}
}

// MLDMaxRespDelay creates a checker that checks the Maximum Response Delay
// field of a MLD message.
//
// The returned TransportChecker assumes that a valid ICMPv6 is passed to it
// containing a valid MLD message as far as the size is concerned.
func MLDMaxRespDelay(want time.Duration) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmp := h.(header.ICMPv6)
		ns := header.MLD(icmp.MessageBody())

		if got := ns.MaximumResponseDelay(); got != want {
			t.Errorf("got %T.MaximumResponseDelay() = %s, want = %s", ns, got, want)
		}
	}
}

// MLDMulticastAddress creates a checker that checks the Multicast Address
// field of a MLD message.
//
// The returned TransportChecker assumes that a valid ICMPv6 is passed to it
// containing a valid MLD message as far as the size is concerned.
func MLDMulticastAddress(want tcpip.Address) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmp := h.(header.ICMPv6)
		ns := header.MLD(icmp.MessageBody())

		if got := ns.MulticastAddress(); got != want {
			t.Errorf("got %T.MulticastAddress() = %s, want = %s", ns, got, want)
		}
	}
}

// NDP creates a checker that checks that the packet contains a valid NDP
// message for type of ty, with potentially additional checks specified by
// checkers.
//
// Checkers may assume that a valid ICMPv6 is passed to it containing a valid
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
		if got := len(icmp.MessageBody()); got < minSize {
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
// Checkers may assume that a valid ICMPv6 is passed to it containing a valid
// NDPNS message as far as the size of the message is concerned. The values
// within the message are up to checkers to validate.
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
		ns := header.NDPNeighborSolicit(icmp.MessageBody())

		if got := ns.TargetAddress(); got != want {
			t.Errorf("got %T.TargetAddress() = %s, want = %s", ns, got, want)
		}
	}
}

// NDPNA creates a checker that checks that the packet contains a valid NDP
// Neighbor Advertisement message (as per the raw wire format), with potentially
// additional checks specified by checkers.
//
// Checkers may assume that a valid ICMPv6 is passed to it containing a valid
// NDPNA message as far as the size of the message is concerned. The values
// within the message are up to checkers to validate.
func NDPNA(checkers ...TransportChecker) NetworkChecker {
	return NDP(header.ICMPv6NeighborAdvert, header.NDPNAMinimumSize, checkers...)
}

// NDPNATargetAddress creates a checker that checks the Target Address field of
// a header.NDPNeighborAdvert.
//
// The returned TransportChecker assumes that a valid ICMPv6 is passed to it
// containing a valid NDPNA message as far as the size is concerned.
func NDPNATargetAddress(want tcpip.Address) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmp := h.(header.ICMPv6)
		na := header.NDPNeighborAdvert(icmp.MessageBody())

		if got := na.TargetAddress(); got != want {
			t.Errorf("got %T.TargetAddress() = %s, want = %s", na, got, want)
		}
	}
}

// NDPNASolicitedFlag creates a checker that checks the Solicited field of
// a header.NDPNeighborAdvert.
//
// The returned TransportChecker assumes that a valid ICMPv6 is passed to it
// containing a valid NDPNA message as far as the size is concerned.
func NDPNASolicitedFlag(want bool) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmp := h.(header.ICMPv6)
		na := header.NDPNeighborAdvert(icmp.MessageBody())

		if got := na.SolicitedFlag(); got != want {
			t.Errorf("got %T.SolicitedFlag = %t, want = %t", na, got, want)
		}
	}
}

// ndpOptions checks that optsBuf only contains opts.
func ndpOptions(t *testing.T, optsBuf header.NDPOptions, opts []header.NDPOption) {
	t.Helper()

	it, err := optsBuf.Iter(true)
	if err != nil {
		t.Errorf("optsBuf.Iter(true): %s", err)
		return
	}

	i := 0
	for {
		opt, done, err := it.Next()
		if err != nil {
			// This should never happen as Iter(true) above did not return an error.
			t.Fatalf("unexpected error when iterating over NDP options: %s", err)
		}
		if done {
			break
		}

		if i >= len(opts) {
			t.Errorf("got unexpected option: %s", opt)
			continue
		}

		switch wantOpt := opts[i].(type) {
		case header.NDPSourceLinkLayerAddressOption:
			gotOpt, ok := opt.(header.NDPSourceLinkLayerAddressOption)
			if !ok {
				t.Errorf("got type = %T at index = %d; want = %T", opt, i, wantOpt)
			} else if got, want := gotOpt.EthernetAddress(), wantOpt.EthernetAddress(); got != want {
				t.Errorf("got EthernetAddress() = %s at index %d, want = %s", got, i, want)
			}
		case header.NDPTargetLinkLayerAddressOption:
			gotOpt, ok := opt.(header.NDPTargetLinkLayerAddressOption)
			if !ok {
				t.Errorf("got type = %T at index = %d; want = %T", opt, i, wantOpt)
			} else if got, want := gotOpt.EthernetAddress(), wantOpt.EthernetAddress(); got != want {
				t.Errorf("got EthernetAddress() = %s at index %d, want = %s", got, i, want)
			}
		case header.NDPNonceOption:
			gotOpt, ok := opt.(header.NDPNonceOption)
			if !ok {
				t.Errorf("got type = %T at index = %d; want = %T", opt, i, wantOpt)
			} else if diff := cmp.Diff(wantOpt.Nonce(), gotOpt.Nonce()); diff != "" {
				t.Errorf("nonce mismatch (-want +got):\n%s", diff)
			}
		default:
			t.Fatalf("checker not implemented for expected NDP option: %T", wantOpt)
		}

		i++
	}

	if missing := opts[i:]; len(missing) > 0 {
		t.Errorf("missing options: %s", missing)
	}
}

// NDPNAOptions creates a checker that checks that the packet contains the
// provided NDP options within an NDP Neighbor Solicitation message.
//
// The returned TransportChecker assumes that a valid ICMPv6 is passed to it
// containing a valid NDPNA message as far as the size is concerned.
func NDPNAOptions(opts []header.NDPOption) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmp := h.(header.ICMPv6)
		na := header.NDPNeighborAdvert(icmp.MessageBody())
		ndpOptions(t, na.Options(), opts)
	}
}

// NDPNSOptions creates a checker that checks that the packet contains the
// provided NDP options within an NDP Neighbor Solicitation message.
//
// The returned TransportChecker assumes that a valid ICMPv6 is passed to it
// containing a valid NDPNS message as far as the size is concerned.
func NDPNSOptions(opts []header.NDPOption) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmp := h.(header.ICMPv6)
		ns := header.NDPNeighborSolicit(icmp.MessageBody())
		ndpOptions(t, ns.Options(), opts)
	}
}

// NDPRS creates a checker that checks that the packet contains a valid NDP
// Router Solicitation message (as per the raw wire format).
//
// Checkers may assume that a valid ICMPv6 is passed to it containing a valid
// NDPRS as far as the size of the message is concerned. The values within the
// message are up to checkers to validate.
func NDPRS(checkers ...TransportChecker) NetworkChecker {
	return NDP(header.ICMPv6RouterSolicit, header.NDPRSMinimumSize, checkers...)
}

// NDPRSOptions creates a checker that checks that the packet contains the
// provided NDP options within an NDP Router Solicitation message.
//
// The returned TransportChecker assumes that a valid ICMPv6 is passed to it
// containing a valid NDPRS message as far as the size is concerned.
func NDPRSOptions(opts []header.NDPOption) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		icmp := h.(header.ICMPv6)
		rs := header.NDPRouterSolicit(icmp.MessageBody())
		ndpOptions(t, rs.Options(), opts)
	}
}

// IGMP checks the validity and properties of the given IGMP packet. It is
// expected to be used in conjunction with other IGMP transport checkers for
// specific properties.
func IGMP(checkers ...TransportChecker) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		last := h[len(h)-1]

		if p := last.TransportProtocol(); p != header.IGMPProtocolNumber {
			t.Fatalf("Bad protocol, got %d, want %d", p, header.IGMPProtocolNumber)
		}

		igmp := header.IGMP(last.Payload())
		for _, f := range checkers {
			f(t, igmp)
		}
		if t.Failed() {
			t.FailNow()
		}
	}
}

// IGMPType creates a checker that checks the IGMP Type field.
func IGMPType(want header.IGMPType) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		igmp, ok := h.(header.IGMP)
		if !ok {
			t.Fatalf("got transport header = %T, want = header.IGMP", h)
		}
		if got := igmp.Type(); got != want {
			t.Errorf("got igmp.Type() = %d, want = %d", got, want)
		}
	}
}

// IGMPMaxRespTime creates a checker that checks the IGMP Max Resp Time field.
func IGMPMaxRespTime(want time.Duration) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		igmp, ok := h.(header.IGMP)
		if !ok {
			t.Fatalf("got transport header = %T, want = header.IGMP", h)
		}
		if got := igmp.MaxRespTime(); got != want {
			t.Errorf("got igmp.MaxRespTime() = %s, want = %s", got, want)
		}
	}
}

// IGMPGroupAddress creates a checker that checks the IGMP Group Address field.
func IGMPGroupAddress(want tcpip.Address) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		t.Helper()

		igmp, ok := h.(header.IGMP)
		if !ok {
			t.Fatalf("got transport header = %T, want = header.IGMP", h)
		}
		if got := igmp.GroupAddress(); got != want {
			t.Errorf("got igmp.GroupAddress() = %s, want = %s", got, want)
		}
	}
}

// IPv6ExtHdrChecker is a function to check an extension header.
type IPv6ExtHdrChecker func(*testing.T, header.IPv6PayloadHeader)

// IPv6WithExtHdr is like IPv6 but allows IPv6 packets with extension headers.
func IPv6WithExtHdr(t *testing.T, b []byte, checkers ...NetworkChecker) {
	t.Helper()

	ipv6 := header.IPv6(b)
	if !ipv6.IsValid(len(b)) {
		t.Error("not a valid IPv6 packet")
		return
	}

	payloadIterator := header.MakeIPv6PayloadIterator(
		header.IPv6ExtensionHeaderIdentifier(ipv6.NextHeader()),
		buffer.View(ipv6.Payload()).ToVectorisedView(),
	)

	var rawPayloadHeader header.IPv6RawPayloadHeader
	for {
		h, done, err := payloadIterator.Next()
		if err != nil {
			t.Errorf("payloadIterator.Next(): %s", err)
			return
		}
		if done {
			t.Errorf("got payloadIterator.Next() = (%T, %t, _), want = (_, true, _)", h, done)
			return
		}
		r, ok := h.(header.IPv6RawPayloadHeader)
		if ok {
			rawPayloadHeader = r
			break
		}
	}

	networkHeader := ipv6HeaderWithExtHdr{
		IPv6:      ipv6,
		transport: tcpip.TransportProtocolNumber(rawPayloadHeader.Identifier),
		payload:   rawPayloadHeader.Buf.ToView(),
	}

	for _, checker := range checkers {
		checker(t, []header.Network{&networkHeader})
	}
}

// IPv6ExtHdr checks for the presence of extension headers.
//
// All the extension headers in headers will be checked exhaustively in the
// order provided.
func IPv6ExtHdr(headers ...IPv6ExtHdrChecker) NetworkChecker {
	return func(t *testing.T, h []header.Network) {
		t.Helper()

		extHdrs, ok := h[0].(*ipv6HeaderWithExtHdr)
		if !ok {
			t.Errorf("got network header = %T, want = *ipv6HeaderWithExtHdr", h[0])
			return
		}

		payloadIterator := header.MakeIPv6PayloadIterator(
			header.IPv6ExtensionHeaderIdentifier(extHdrs.IPv6.NextHeader()),
			buffer.View(extHdrs.IPv6.Payload()).ToVectorisedView(),
		)

		for _, check := range headers {
			h, done, err := payloadIterator.Next()
			if err != nil {
				t.Errorf("payloadIterator.Next(): %s", err)
				return
			}
			if done {
				t.Errorf("got payloadIterator.Next() = (%T, %t, _), want = (_, false, _)", h, done)
				return
			}
			check(t, h)
		}
		// Validate we consumed all headers.
		//
		// The next one over should be a raw payload and then iterator should
		// terminate.
		wantDone := false
		for {
			h, done, err := payloadIterator.Next()
			if err != nil {
				t.Errorf("payloadIterator.Next(): %s", err)
				return
			}
			if done != wantDone {
				t.Errorf("got payloadIterator.Next() = (%T, %t, _), want = (_, %t, _)", h, done, wantDone)
				return
			}
			if done {
				break
			}
			if _, ok := h.(header.IPv6RawPayloadHeader); !ok {
				t.Errorf("got payloadIterator.Next() = (%T, _, _), want = (header.IPv6RawPayloadHeader, _, _)", h)
				continue
			}
			wantDone = true
		}
	}
}

var _ header.Network = (*ipv6HeaderWithExtHdr)(nil)

// ipv6HeaderWithExtHdr provides a header.Network implementation that takes
// extension headers into consideration, which is not the case with vanilla
// header.IPv6.
type ipv6HeaderWithExtHdr struct {
	header.IPv6
	transport tcpip.TransportProtocolNumber
	payload   []byte
}

// TransportProtocol implements header.Network.
func (h *ipv6HeaderWithExtHdr) TransportProtocol() tcpip.TransportProtocolNumber {
	return h.transport
}

// Payload implements header.Network.
func (h *ipv6HeaderWithExtHdr) Payload() []byte {
	return h.payload
}

// IPv6ExtHdrOptionChecker is a function to check an extension header option.
type IPv6ExtHdrOptionChecker func(*testing.T, header.IPv6ExtHdrOption)

// IPv6HopByHopExtensionHeader checks the extension header is a Hop by Hop
// extension header and validates the containing options with checkers.
//
// checkers must exhaustively contain all the expected options.
func IPv6HopByHopExtensionHeader(checkers ...IPv6ExtHdrOptionChecker) IPv6ExtHdrChecker {
	return func(t *testing.T, payloadHeader header.IPv6PayloadHeader) {
		t.Helper()

		hbh, ok := payloadHeader.(header.IPv6HopByHopOptionsExtHdr)
		if !ok {
			t.Errorf("unexpected IPv6 payload header, got = %T, want = header.IPv6HopByHopOptionsExtHdr", payloadHeader)
			return
		}
		optionsIterator := hbh.Iter()
		for _, f := range checkers {
			opt, done, err := optionsIterator.Next()
			if err != nil {
				t.Errorf("optionsIterator.Next(): %s", err)
				return
			}
			if done {
				t.Errorf("got optionsIterator.Next() = (%T, %t, _), want = (_, false, _)", opt, done)
			}
			f(t, opt)
		}
		// Validate all options were consumed.
		for {
			opt, done, err := optionsIterator.Next()
			if err != nil {
				t.Errorf("optionsIterator.Next(): %s", err)
				return
			}
			if !done {
				t.Errorf("got optionsIterator.Next() = (%T, %t, _), want = (_, true, _)", opt, done)
			}
			if done {
				break
			}
		}
	}
}

// IPv6RouterAlert validates that an extension header option is the RouterAlert
// option and matches on its value.
func IPv6RouterAlert(want header.IPv6RouterAlertValue) IPv6ExtHdrOptionChecker {
	return func(t *testing.T, opt header.IPv6ExtHdrOption) {
		routerAlert, ok := opt.(*header.IPv6RouterAlertOption)
		if !ok {
			t.Errorf("unexpected extension header option, got = %T, want = header.IPv6RouterAlertOption", opt)
			return
		}
		if routerAlert.Value != want {
			t.Errorf("got routerAlert.Value = %d, want = %d", routerAlert.Value, want)
		}
	}
}

// IPv6UnknownOption validates that an extension header option is the
// unknown header option.
func IPv6UnknownOption() IPv6ExtHdrOptionChecker {
	return func(t *testing.T, opt header.IPv6ExtHdrOption) {
		_, ok := opt.(*header.IPv6UnknownExtHdrOption)
		if !ok {
			t.Errorf("got = %T, want = header.IPv6UnknownExtHdrOption", opt)
		}
	}
}

// IgnoreCmpPath returns a cmp.Option that ignores listed field paths.
func IgnoreCmpPath(paths ...string) cmp.Option {
	ignores := map[string]struct{}{}
	for _, path := range paths {
		ignores[path] = struct{}{}
	}
	return cmp.FilterPath(func(path cmp.Path) bool {
		_, ok := ignores[path.String()]
		return ok
	}, cmp.Ignore())
}
