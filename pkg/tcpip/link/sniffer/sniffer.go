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

// Package sniffer provides the implementation of data-link layer endpoints that
// wrap another endpoint and logs inbound and outbound packets.
//
// Sniffer endpoints can be used in the networking stack by calling New(eID) to
// create a new endpoint, where eID is the ID of the endpoint being wrapped,
// and then passing it as an argument to Stack.CreateNIC().
package sniffer

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// LogPackets is a flag used to enable or disable packet logging via the log
// package. Valid values are 0 or 1.
//
// LogPackets must be accessed atomically.
var LogPackets uint32 = 1

// LogPacketsToPCAP is a flag used to enable or disable logging packets to a
// pcap writer. Valid values are 0 or 1. A writer must have been specified when the
// sniffer was created for this flag to have effect.
//
// LogPacketsToPCAP must be accessed atomically.
var LogPacketsToPCAP uint32 = 1

type endpoint struct {
	nested.Endpoint
	writer     io.Writer
	maxPCAPLen uint32
}

var _ stack.GSOEndpoint = (*endpoint)(nil)
var _ stack.LinkEndpoint = (*endpoint)(nil)
var _ stack.NetworkDispatcher = (*endpoint)(nil)

// New creates a new sniffer link-layer endpoint. It wraps around another
// endpoint and logs packets and they traverse the endpoint.
func New(lower stack.LinkEndpoint) stack.LinkEndpoint {
	sniffer := &endpoint{}
	sniffer.Endpoint.Init(lower, sniffer)
	return sniffer
}

func zoneOffset() (int32, error) {
	loc, err := time.LoadLocation("Local")
	if err != nil {
		return 0, err
	}
	date := time.Date(0, 0, 0, 0, 0, 0, 0, loc)
	_, offset := date.Zone()
	return int32(offset), nil
}

func writePCAPHeader(w io.Writer, maxLen uint32) error {
	offset, err := zoneOffset()
	if err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, pcapHeader{
		// From https://wiki.wireshark.org/Development/LibpcapFileFormat
		MagicNumber: 0xa1b2c3d4,

		VersionMajor: 2,
		VersionMinor: 4,
		Thiszone:     offset,
		Sigfigs:      0,
		Snaplen:      maxLen,
		Network:      101, // LINKTYPE_RAW
	})
}

// NewWithWriter creates a new sniffer link-layer endpoint. It wraps around
// another endpoint and logs packets as they traverse the endpoint.
//
// Packets are logged to writer in the pcap format. A sniffer created with this
// function will not emit packets using the standard log package.
//
// snapLen is the maximum amount of a packet to be saved. Packets with a length
// less than or equal to snapLen will be saved in their entirety. Longer
// packets will be truncated to snapLen.
func NewWithWriter(lower stack.LinkEndpoint, writer io.Writer, snapLen uint32) (stack.LinkEndpoint, error) {
	if err := writePCAPHeader(writer, snapLen); err != nil {
		return nil, err
	}
	sniffer := &endpoint{
		writer:     writer,
		maxPCAPLen: snapLen,
	}
	sniffer.Endpoint.Init(lower, sniffer)
	return sniffer, nil
}

// DeliverNetworkPacket implements the stack.NetworkDispatcher interface. It is
// called by the link-layer endpoint being wrapped when a packet arrives, and
// logs the packet before forwarding to the actual dispatcher.
func (e *endpoint) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.dumpPacket("recv", nil, protocol, pkt)
	e.Endpoint.DeliverNetworkPacket(remote, local, protocol, pkt)
}

func (e *endpoint) dumpPacket(prefix string, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	writer := e.writer
	if writer == nil && atomic.LoadUint32(&LogPackets) == 1 {
		logPacket(prefix, protocol, pkt, gso)
	}
	if writer != nil && atomic.LoadUint32(&LogPacketsToPCAP) == 1 {
		totalLength := pkt.Header.UsedLength() + pkt.Data.Size()
		length := totalLength
		if max := int(e.maxPCAPLen); length > max {
			length = max
		}
		if err := binary.Write(writer, binary.BigEndian, newPCAPPacketHeader(uint32(length), uint32(totalLength))); err != nil {
			panic(err)
		}
		write := func(b []byte) {
			if len(b) > length {
				b = b[:length]
			}
			for len(b) != 0 {
				n, err := writer.Write(b)
				if err != nil {
					panic(err)
				}
				b = b[n:]
				length -= n
			}
		}
		write(pkt.Header.View())
		for _, view := range pkt.Data.Views() {
			if length == 0 {
				break
			}
			write(view)
		}
	}
}

// WritePacket implements the stack.LinkEndpoint interface. It is called by
// higher-level protocols to write packets; it just logs the packet and
// forwards the request to the lower endpoint.
func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	e.dumpPacket("send", gso, protocol, pkt)
	return e.Endpoint.WritePacket(r, gso, protocol, pkt)
}

// WritePackets implements the stack.LinkEndpoint interface. It is called by
// higher-level protocols to write packets; it just logs the packet and
// forwards the request to the lower endpoint.
func (e *endpoint) WritePackets(r *stack.Route, gso *stack.GSO, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		e.dumpPacket("send", gso, protocol, pkt)
	}
	return e.Endpoint.WritePackets(r, gso, pkts, protocol)
}

// WriteRawPacket implements stack.LinkEndpoint.WriteRawPacket.
func (e *endpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {
	e.dumpPacket("send", nil, 0, &stack.PacketBuffer{
		Data: vv,
	})
	return e.Endpoint.WriteRawPacket(vv)
}

func logPacket(prefix string, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer, gso *stack.GSO) {
	// Figure out the network layer info.
	var transProto uint8
	src := tcpip.Address("unknown")
	dst := tcpip.Address("unknown")
	id := 0
	size := uint16(0)
	var fragmentOffset uint16
	var moreFragments bool

	// Create a clone of pkt, including any headers if present. Avoid allocating
	// backing memory for the clone.
	views := [8]buffer.View{}
	vv := buffer.NewVectorisedView(0, views[:0])
	vv.AppendView(pkt.Header.View())
	vv.Append(pkt.Data)

	switch protocol {
	case header.IPv4ProtocolNumber:
		hdr, ok := vv.PullUp(header.IPv4MinimumSize)
		if !ok {
			return
		}
		ipv4 := header.IPv4(hdr)
		fragmentOffset = ipv4.FragmentOffset()
		moreFragments = ipv4.Flags()&header.IPv4FlagMoreFragments == header.IPv4FlagMoreFragments
		src = ipv4.SourceAddress()
		dst = ipv4.DestinationAddress()
		transProto = ipv4.Protocol()
		size = ipv4.TotalLength() - uint16(ipv4.HeaderLength())
		vv.TrimFront(int(ipv4.HeaderLength()))
		id = int(ipv4.ID())

	case header.IPv6ProtocolNumber:
		hdr, ok := vv.PullUp(header.IPv6MinimumSize)
		if !ok {
			return
		}
		ipv6 := header.IPv6(hdr)
		src = ipv6.SourceAddress()
		dst = ipv6.DestinationAddress()
		transProto = ipv6.NextHeader()
		size = ipv6.PayloadLength()
		vv.TrimFront(header.IPv6MinimumSize)

	case header.ARPProtocolNumber:
		hdr, ok := vv.PullUp(header.ARPSize)
		if !ok {
			return
		}
		vv.TrimFront(header.ARPSize)
		arp := header.ARP(hdr)
		log.Infof(
			"%s arp %s (%s) -> %s (%s) valid:%t",
			prefix,
			tcpip.Address(arp.ProtocolAddressSender()), tcpip.LinkAddress(arp.HardwareAddressSender()),
			tcpip.Address(arp.ProtocolAddressTarget()), tcpip.LinkAddress(arp.HardwareAddressTarget()),
			arp.IsValid(),
		)
		return
	default:
		log.Infof("%s unknown network protocol", prefix)
		return
	}

	// Figure out the transport layer info.
	transName := "unknown"
	srcPort := uint16(0)
	dstPort := uint16(0)
	details := ""
	switch tcpip.TransportProtocolNumber(transProto) {
	case header.ICMPv4ProtocolNumber:
		transName = "icmp"
		hdr, ok := vv.PullUp(header.ICMPv4MinimumSize)
		if !ok {
			break
		}
		icmp := header.ICMPv4(hdr)
		icmpType := "unknown"
		if fragmentOffset == 0 {
			switch icmp.Type() {
			case header.ICMPv4EchoReply:
				icmpType = "echo reply"
			case header.ICMPv4DstUnreachable:
				icmpType = "destination unreachable"
			case header.ICMPv4SrcQuench:
				icmpType = "source quench"
			case header.ICMPv4Redirect:
				icmpType = "redirect"
			case header.ICMPv4Echo:
				icmpType = "echo"
			case header.ICMPv4TimeExceeded:
				icmpType = "time exceeded"
			case header.ICMPv4ParamProblem:
				icmpType = "param problem"
			case header.ICMPv4Timestamp:
				icmpType = "timestamp"
			case header.ICMPv4TimestampReply:
				icmpType = "timestamp reply"
			case header.ICMPv4InfoRequest:
				icmpType = "info request"
			case header.ICMPv4InfoReply:
				icmpType = "info reply"
			}
		}
		log.Infof("%s %s %s -> %s %s len:%d id:%04x code:%d", prefix, transName, src, dst, icmpType, size, id, icmp.Code())
		return

	case header.ICMPv6ProtocolNumber:
		transName = "icmp"
		hdr, ok := vv.PullUp(header.ICMPv6MinimumSize)
		if !ok {
			break
		}
		icmp := header.ICMPv6(hdr)
		icmpType := "unknown"
		switch icmp.Type() {
		case header.ICMPv6DstUnreachable:
			icmpType = "destination unreachable"
		case header.ICMPv6PacketTooBig:
			icmpType = "packet too big"
		case header.ICMPv6TimeExceeded:
			icmpType = "time exceeded"
		case header.ICMPv6ParamProblem:
			icmpType = "param problem"
		case header.ICMPv6EchoRequest:
			icmpType = "echo request"
		case header.ICMPv6EchoReply:
			icmpType = "echo reply"
		case header.ICMPv6RouterSolicit:
			icmpType = "router solicit"
		case header.ICMPv6RouterAdvert:
			icmpType = "router advert"
		case header.ICMPv6NeighborSolicit:
			icmpType = "neighbor solicit"
		case header.ICMPv6NeighborAdvert:
			icmpType = "neighbor advert"
		case header.ICMPv6RedirectMsg:
			icmpType = "redirect message"
		}
		log.Infof("%s %s %s -> %s %s len:%d id:%04x code:%d", prefix, transName, src, dst, icmpType, size, id, icmp.Code())
		return

	case header.UDPProtocolNumber:
		transName = "udp"
		hdr, ok := vv.PullUp(header.UDPMinimumSize)
		if !ok {
			break
		}
		udp := header.UDP(hdr)
		if fragmentOffset == 0 {
			srcPort = udp.SourcePort()
			dstPort = udp.DestinationPort()
			details = fmt.Sprintf("xsum: 0x%x", udp.Checksum())
			size -= header.UDPMinimumSize
		}

	case header.TCPProtocolNumber:
		transName = "tcp"
		hdr, ok := vv.PullUp(header.TCPMinimumSize)
		if !ok {
			break
		}
		tcp := header.TCP(hdr)
		if fragmentOffset == 0 {
			offset := int(tcp.DataOffset())
			if offset < header.TCPMinimumSize {
				details += fmt.Sprintf("invalid packet: tcp data offset too small %d", offset)
				break
			}
			if offset > vv.Size() && !moreFragments {
				details += fmt.Sprintf("invalid packet: tcp data offset %d larger than packet buffer length %d", offset, vv.Size())
				break
			}

			srcPort = tcp.SourcePort()
			dstPort = tcp.DestinationPort()
			size -= uint16(offset)

			// Initialize the TCP flags.
			flags := tcp.Flags()
			flagsStr := []byte("FSRPAU")
			for i := range flagsStr {
				if flags&(1<<uint(i)) == 0 {
					flagsStr[i] = ' '
				}
			}
			details = fmt.Sprintf("flags:0x%02x (%s) seqnum: %d ack: %d win: %d xsum:0x%x", flags, string(flagsStr), tcp.SequenceNumber(), tcp.AckNumber(), tcp.WindowSize(), tcp.Checksum())
			if flags&header.TCPFlagSyn != 0 {
				details += fmt.Sprintf(" options: %+v", header.ParseSynOptions(tcp.Options(), flags&header.TCPFlagAck != 0))
			} else {
				details += fmt.Sprintf(" options: %+v", tcp.ParsedOptions())
			}
		}

	default:
		log.Infof("%s %s -> %s unknown transport protocol: %d", prefix, src, dst, transProto)
		return
	}

	if gso != nil {
		details += fmt.Sprintf(" gso: %+v", gso)
	}

	log.Infof("%s %s %s:%d -> %s:%d len:%d id:%04x %s", prefix, transName, src, srcPort, dst, dstPort, size, id, details)
}
