// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv4

import (
	"context"
	"encoding/binary"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// PingProtocolName is a pseudo transport protocol used to handle ping replies.
// Use it when constructing a stack that intends to use ipv4.Ping.
const PingProtocolName = "icmpv4ping"

// pingProtocolNumber is a fake transport protocol used to
// deliver incoming ICMP echo replies. The ICMP identifier
// number is used as a port number for multiplexing.
const pingProtocolNumber tcpip.TransportProtocolNumber = 256 + 11

// handleControl handles the case when an ICMP packet contains the headers of
// the original packet that caused the ICMP one to be sent. This information is
// used to find out which transport endpoint must be notified about the ICMP
// packet.
func (e *endpoint) handleControl(typ stack.ControlType, extra uint32, vv *buffer.VectorisedView) {
	h := header.IPv4(vv.First())

	// We don't use IsValid() here because ICMP only requires that the IP
	// header plus 8 bytes of the transport header be included. So it's
	// likely that it is truncated, which would cause IsValid to return
	// false.
	//
	// Drop packet if it doesn't have the basic IPv4 header or if the
	// original source address doesn't match the endpoint's address.
	if len(h) < header.IPv4MinimumSize || h.SourceAddress() != e.id.LocalAddress {
		return
	}

	hlen := int(h.HeaderLength())
	if vv.Size() < hlen || h.FragmentOffset() != 0 {
		// We won't be able to handle this if it doesn't contain the
		// full IPv4 header, or if it's a fragment not at offset 0
		// (because it won't have the transport header).
		return
	}

	// Skip the ip header, then deliver control message.
	vv.TrimFront(hlen)
	p := h.TransportProtocol()
	e.dispatcher.DeliverTransportControlPacket(e.id.LocalAddress, h.DestinationAddress(), ProtocolNumber, p, typ, extra, vv)
}

func (e *endpoint) handleICMP(r *stack.Route, vv *buffer.VectorisedView) {
	v := vv.First()
	if len(v) < header.ICMPv4MinimumSize {
		return
	}
	h := header.ICMPv4(v)

	switch h.Type() {
	case header.ICMPv4Echo:
		if len(v) < header.ICMPv4EchoMinimumSize {
			return
		}
		vv.TrimFront(header.ICMPv4MinimumSize)
		req := echoRequest{r: r.Clone(), v: vv.ToView()}
		select {
		case e.echoRequests <- req:
		default:
			req.r.Release()
		}

	case header.ICMPv4EchoReply:
		e.dispatcher.DeliverTransportPacket(r, pingProtocolNumber, vv)

	case header.ICMPv4DstUnreachable:
		if len(v) < header.ICMPv4DstUnreachableMinimumSize {
			return
		}
		vv.TrimFront(header.ICMPv4DstUnreachableMinimumSize)
		switch h.Code() {
		case header.ICMPv4PortUnreachable:
			e.handleControl(stack.ControlPortUnreachable, 0, vv)

		case header.ICMPv4FragmentationNeeded:
			mtu := uint32(binary.BigEndian.Uint16(v[header.ICMPv4DstUnreachableMinimumSize-2:]))
			e.handleControl(stack.ControlPacketTooBig, calculateMTU(mtu), vv)
		}
	}
	// TODO: Handle other ICMP types.
}

type echoRequest struct {
	r stack.Route
	v buffer.View
}

func (e *endpoint) echoReplier() {
	for req := range e.echoRequests {
		sendICMPv4(&req.r, header.ICMPv4EchoReply, 0, req.v)
		req.r.Release()
	}
}

func sendICMPv4(r *stack.Route, typ header.ICMPv4Type, code byte, data buffer.View) *tcpip.Error {
	hdr := buffer.NewPrependable(header.ICMPv4MinimumSize + int(r.MaxHeaderLength()))

	icmpv4 := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
	icmpv4.SetType(typ)
	icmpv4.SetCode(code)
	icmpv4.SetChecksum(^header.Checksum(icmpv4, header.Checksum(data, 0)))

	return r.WritePacket(&hdr, data, header.ICMPv4ProtocolNumber)
}

// A Pinger can send echo requests to an address.
type Pinger struct {
	Stack     *stack.Stack
	NICID     tcpip.NICID
	Addr      tcpip.Address
	LocalAddr tcpip.Address // optional
	Wait      time.Duration // if zero, defaults to 1 second
	Count     uint16        // if zero, defaults to MaxUint16
}

// Ping sends echo requests to an ICMPv4 endpoint.
// Responses are streamed to the channel ch.
func (p *Pinger) Ping(ctx context.Context, ch chan<- PingReply) *tcpip.Error {
	count := p.Count
	if count == 0 {
		count = 1<<16 - 1
	}
	wait := p.Wait
	if wait == 0 {
		wait = 1 * time.Second
	}

	r, err := p.Stack.FindRoute(p.NICID, p.LocalAddr, p.Addr, ProtocolNumber)
	if err != nil {
		return err
	}

	netProtos := []tcpip.NetworkProtocolNumber{ProtocolNumber}
	ep := &pingEndpoint{
		stack: p.Stack,
		pktCh: make(chan buffer.View, 1),
	}
	id := stack.TransportEndpointID{
		LocalAddress:  r.LocalAddress,
		RemoteAddress: p.Addr,
	}

	_, err = p.Stack.PickEphemeralPort(func(port uint16) (bool, *tcpip.Error) {
		id.LocalPort = port
		err := p.Stack.RegisterTransportEndpoint(p.NICID, netProtos, pingProtocolNumber, id, ep)
		switch err {
		case nil:
			return true, nil
		case tcpip.ErrPortInUse:
			return false, nil
		default:
			return false, err
		}
	})
	if err != nil {
		return err
	}
	defer p.Stack.UnregisterTransportEndpoint(p.NICID, netProtos, pingProtocolNumber, id)

	v := buffer.NewView(4)
	binary.BigEndian.PutUint16(v[0:], id.LocalPort)

	start := time.Now()

	done := make(chan struct{})
	go func(count int) {
	loop:
		for ; count > 0; count-- {
			select {
			case v := <-ep.pktCh:
				seq := binary.BigEndian.Uint16(v[header.ICMPv4MinimumSize+2:])
				ch <- PingReply{
					Duration:  time.Since(start) - time.Duration(seq)*wait,
					SeqNumber: seq,
				}
			case <-ctx.Done():
				break loop
			}
		}
		close(done)
	}(int(count))
	defer func() { <-done }()

	t := time.NewTicker(wait)
	defer t.Stop()
	for seq := uint16(0); seq < count; seq++ {
		select {
		case <-t.C:
		case <-ctx.Done():
			return nil
		}
		binary.BigEndian.PutUint16(v[2:], seq)
		sent := time.Now()
		if err := sendICMPv4(&r, header.ICMPv4Echo, 0, v); err != nil {
			ch <- PingReply{
				Error:     err,
				Duration:  time.Since(sent),
				SeqNumber: seq,
			}
		}
	}
	return nil
}

// PingReply summarizes an ICMP echo reply.
type PingReply struct {
	Error     *tcpip.Error // reports any errors sending a ping request
	Duration  time.Duration
	SeqNumber uint16
}

type pingProtocol struct{}

func (*pingProtocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return nil, tcpip.ErrNotSupported // endpoints are created directly
}

func (*pingProtocol) Number() tcpip.TransportProtocolNumber { return pingProtocolNumber }

func (*pingProtocol) MinimumPacketSize() int { return header.ICMPv4EchoMinimumSize }

func (*pingProtocol) ParsePorts(v buffer.View) (src, dst uint16, err *tcpip.Error) {
	ident := binary.BigEndian.Uint16(v[4:])
	return 0, ident, nil
}

func (*pingProtocol) HandleUnknownDestinationPacket(*stack.Route, stack.TransportEndpointID, *buffer.VectorisedView) bool {
	return true
}

// SetOption implements TransportProtocol.SetOption.
func (p *pingProtocol) SetOption(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// Option implements TransportProtocol.Option.
func (p *pingProtocol) Option(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

func init() {
	stack.RegisterTransportProtocolFactory(PingProtocolName, func() stack.TransportProtocol {
		return &pingProtocol{}
	})
}

type pingEndpoint struct {
	stack *stack.Stack
	pktCh chan buffer.View
}

func (e *pingEndpoint) Close() {
	close(e.pktCh)
}

func (e *pingEndpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, vv *buffer.VectorisedView) {
	select {
	case e.pktCh <- vv.ToView():
	default:
	}
}

// HandleControlPacket implements stack.TransportEndpoint.HandleControlPacket.
func (e *pingEndpoint) HandleControlPacket(id stack.TransportEndpointID, typ stack.ControlType, extra uint32, vv *buffer.VectorisedView) {
}
