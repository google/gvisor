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
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// LogPackets is a flag used to enable or disable packet logging via the log
// package. Valid values are 0 or 1.
var LogPackets atomicbitops.Uint32 = atomicbitops.FromUint32(1)

// LogPacketsToPCAP is a flag used to enable or disable logging packets to a
// pcap writer. Valid values are 0 or 1. A writer must have been specified when the
// sniffer was created for this flag to have effect.
var LogPacketsToPCAP atomicbitops.Uint32 = atomicbitops.FromUint32(1)

type endpoint struct {
	nested.Endpoint
	writer     io.Writer
	maxPCAPLen uint32
	logPrefix  string
}

var _ stack.GSOEndpoint = (*endpoint)(nil)
var _ stack.LinkEndpoint = (*endpoint)(nil)
var _ stack.NetworkDispatcher = (*endpoint)(nil)

// A Direction indicates whether the packing is being sent or received.
type Direction int

const (
	// DirectionSend indicates a sent packet.
	DirectionSend = iota
	// DirectionRecv indicates a received packet.
	DirectionRecv
)

// New creates a new sniffer link-layer endpoint. It wraps around another
// endpoint and logs packets and they traverse the endpoint.
func New(lower stack.LinkEndpoint) stack.LinkEndpoint {
	return NewWithPrefix(lower, "")
}

// NewWithPrefix creates a new sniffer link-layer endpoint. It wraps around
// another endpoint and logs packets prefixed with logPrefix as they traverse
// the endpoint.
//
// logPrefix is prepended to the log line without any separators.
// E.g. logPrefix = "NIC:en0/" will produce log lines like
// "NIC:en0/send udp [...]".
func NewWithPrefix(lower stack.LinkEndpoint, logPrefix string) stack.LinkEndpoint {
	sniffer := &endpoint{logPrefix: logPrefix}
	sniffer.Endpoint.Init(lower, sniffer)
	return sniffer
}

func zoneOffset() (int32, error) {
	date := time.Date(0, 0, 0, 0, 0, 0, 0, time.Local)
	_, offset := date.Zone()
	return int32(offset), nil
}

func writePCAPHeader(w io.Writer, maxLen uint32) error {
	offset, err := zoneOffset()
	if err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, pcapHeader{
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
// Each packet is written to writer in the pcap format in a single Write call
// without synchronization. A sniffer created with this function will not emit
// packets using the standard log package.
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
func (e *endpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBufferPtr) {
	e.dumpPacket(DirectionRecv, protocol, pkt)
	e.Endpoint.DeliverNetworkPacket(protocol, pkt)
}

func (e *endpoint) dumpPacket(dir Direction, protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBufferPtr) {
	writer := e.writer
	if writer == nil && LogPackets.Load() == 1 {
		LogPacket(e.logPrefix, dir, protocol, pkt)
	}
	if writer != nil && LogPacketsToPCAP.Load() == 1 {
		packet := pcapPacket{
			timestamp:     time.Now(),
			packet:        pkt,
			maxCaptureLen: int(e.maxPCAPLen),
		}
		b, err := packet.MarshalBinary()
		if err != nil {
			panic(err)
		}
		if _, err := writer.Write(b); err != nil {
			panic(err)
		}
	}
}

// WritePackets implements the stack.LinkEndpoint interface. It is called by
// higher-level protocols to write packets; it just logs the packet and
// forwards the request to the lower endpoint.
func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for _, pkt := range pkts.AsSlice() {
		e.dumpPacket(DirectionSend, pkt.NetworkProtocolNumber, pkt)
	}
	return e.Endpoint.WritePackets(pkts)
}

// LogPacket logs a packet to stdout.
func LogPacket(prefix string, dir Direction, protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBufferPtr) {
	// Figure out the network layer info.
	var transProto uint8
	src := tcpip.Address("unknown")
	dst := tcpip.Address("unknown")
	var size uint16
	var id uint32
	var fragmentOffset uint16
	var moreFragments bool

	var directionPrefix string
	switch dir {
	case DirectionSend:
		directionPrefix = "send"
	case DirectionRecv:
		directionPrefix = "recv"
	default:
		panic(fmt.Sprintf("unrecognized direction: %d", dir))
	}

	pkt = trimmedClone(pkt)
	defer pkt.DecRef()
	switch protocol {
	case header.IPv4ProtocolNumber:
		if ok := parse.IPv4(pkt); !ok {
			return
		}

		ipv4 := header.IPv4(pkt.NetworkHeader().Slice())
		fragmentOffset = ipv4.FragmentOffset()
		moreFragments = ipv4.Flags()&header.IPv4FlagMoreFragments == header.IPv4FlagMoreFragments
		src = ipv4.SourceAddress()
		dst = ipv4.DestinationAddress()
		transProto = ipv4.Protocol()
		size = ipv4.TotalLength() - uint16(ipv4.HeaderLength())
		id = uint32(ipv4.ID())

	case header.IPv6ProtocolNumber:
		proto, fragID, fragOffset, fragMore, ok := parse.IPv6(pkt)
		if !ok {
			return
		}

		ipv6 := header.IPv6(pkt.NetworkHeader().Slice())
		src = ipv6.SourceAddress()
		dst = ipv6.DestinationAddress()
		transProto = uint8(proto)
		size = ipv6.PayloadLength()
		id = fragID
		moreFragments = fragMore
		fragmentOffset = fragOffset

	case header.ARPProtocolNumber:
		if !parse.ARP(pkt) {
			return
		}

		arp := header.ARP(pkt.NetworkHeader().Slice())
		log.Infof(
			"%s%s arp %s (%s) -> %s (%s) valid:%t",
			prefix,
			directionPrefix,
			tcpip.Address(arp.ProtocolAddressSender()), tcpip.LinkAddress(arp.HardwareAddressSender()),
			tcpip.Address(arp.ProtocolAddressTarget()), tcpip.LinkAddress(arp.HardwareAddressTarget()),
			arp.IsValid(),
		)
		return
	default:
		log.Infof("%s%s unknown network protocol: %d", prefix, directionPrefix, protocol)
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
		hdr, ok := pkt.Data().PullUp(header.ICMPv4MinimumSize)
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
		log.Infof("%s%s %s %s -> %s %s len:%d id:%04x code:%d", prefix, directionPrefix, transName, src, dst, icmpType, size, id, icmp.Code())
		return

	case header.ICMPv6ProtocolNumber:
		transName = "icmp"
		hdr, ok := pkt.Data().PullUp(header.ICMPv6MinimumSize)
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
		log.Infof("%s%s %s %s -> %s %s len:%d id:%04x code:%d", prefix, directionPrefix, transName, src, dst, icmpType, size, id, icmp.Code())
		return

	case header.UDPProtocolNumber:
		transName = "udp"
		if ok := parse.UDP(pkt); !ok {
			break
		}

		udp := header.UDP(pkt.TransportHeader().Slice())
		if fragmentOffset == 0 {
			srcPort = udp.SourcePort()
			dstPort = udp.DestinationPort()
			details = fmt.Sprintf("xsum: 0x%x", udp.Checksum())
			size -= header.UDPMinimumSize
		}

	case header.TCPProtocolNumber:
		transName = "tcp"
		if ok := parse.TCP(pkt); !ok {
			break
		}

		tcp := header.TCP(pkt.TransportHeader().Slice())
		if fragmentOffset == 0 {
			offset := int(tcp.DataOffset())
			if offset < header.TCPMinimumSize {
				details += fmt.Sprintf("invalid packet: tcp data offset too small %d", offset)
				break
			}
			if size := pkt.Data().Size() + len(tcp); offset > size && !moreFragments {
				details += fmt.Sprintf("invalid packet: tcp data offset %d larger than tcp packet length %d", offset, size)
				break
			}

			srcPort = tcp.SourcePort()
			dstPort = tcp.DestinationPort()
			size -= uint16(offset)

			// Initialize the TCP flags.
			flags := tcp.Flags()
			details = fmt.Sprintf("flags: %s seqnum: %d ack: %d win: %d xsum:0x%x", flags, tcp.SequenceNumber(), tcp.AckNumber(), tcp.WindowSize(), tcp.Checksum())
			if flags&header.TCPFlagSyn != 0 {
				details += fmt.Sprintf(" options: %+v", header.ParseSynOptions(tcp.Options(), flags&header.TCPFlagAck != 0))
			} else {
				details += fmt.Sprintf(" options: %+v", tcp.ParsedOptions())
			}
		}

	default:
		log.Infof("%s%s %s -> %s unknown transport protocol: %d", prefix, directionPrefix, src, dst, transProto)
		return
	}

	if pkt.GSOOptions.Type != stack.GSONone {
		details += fmt.Sprintf(" gso: %#v", pkt.GSOOptions)
	}

	log.Infof("%s%s %s %s:%d -> %s:%d len:%d id:%04x %s", prefix, directionPrefix, transName, src, srcPort, dst, dstPort, size, id, details)
}

// trimmedClone clones the packet buffer to not modify the original. It trims
// anything before the network header.
func trimmedClone(pkt stack.PacketBufferPtr) stack.PacketBufferPtr {
	// We don't clone the original packet buffer so that the new packet buffer
	// does not have any of its headers set.
	//
	// We trim the link headers from the cloned buffer as the sniffer doesn't
	// handle link headers.
	buf := pkt.ToBuffer()
	buf.TrimFront(int64(len(pkt.VirtioNetHeader().Slice())))
	buf.TrimFront(int64(len(pkt.LinkHeader().Slice())))
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buf})
}
