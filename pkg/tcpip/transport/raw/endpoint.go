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

// Package raw provides the implementation of raw sockets (see raw(7)). Raw
// sockets allow applications to:
//
//   * manually write and inspect transport layer headers and payloads
//   * receive all traffic of a given transport protocol (e.g. ICMP or UDP)
//   * optionally write and inspect network layer headers of packets
//
// Raw sockets don't have any notion of ports, and incoming packets are
// demultiplexed solely by protocol number. Thus, a raw UDP endpoint will
// receive every UDP packet received by netstack. bind(2) and connect(2) can be
// used to filter incoming packets by source and destination.
package raw

import (
	"io"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// +stateify savable
type rawPacket struct {
	rawPacketEntry
	// data holds the actual packet data, including any headers and
	// payload.
	data       buffer.VectorisedView `state:".(buffer.VectorisedView)"`
	receivedAt time.Time             `state:".(int64)"`
	// senderAddr is the network address of the sender.
	senderAddr tcpip.FullAddress
}

// endpoint is the raw socket implementation of tcpip.Endpoint. It is legal to
// have goroutines make concurrent calls into the endpoint.
//
// Lock order:
//   endpoint.mu
//     endpoint.rcvMu
//
// +stateify savable
type endpoint struct {
	stack.TransportEndpointInfo
	tcpip.DefaultSocketOptionsHandler

	// The following fields are initialized at creation time and are
	// immutable.
	stack       *stack.Stack `state:"manual"`
	waiterQueue *waiter.Queue
	associated  bool

	// The following fields are used to manage the receive queue and are
	// protected by rcvMu.
	rcvMu      sync.Mutex `state:"nosave"`
	rcvList    rawPacketList
	rcvBufSize int
	rcvClosed  bool

	// The following fields are protected by mu.
	mu        sync.RWMutex `state:"nosave"`
	closed    bool
	connected bool
	bound     bool
	// route is the route to a remote network endpoint. It is set via
	// Connect(), and is valid only when conneted is true.
	route *stack.Route                 `state:"manual"`
	stats tcpip.TransportEndpointStats `state:"nosave"`
	// owner is used to get uid and gid of the packet.
	owner tcpip.PacketOwner

	// ops is used to get socket level options.
	ops tcpip.SocketOptions

	// frozen indicates if the packets should be delivered to the endpoint
	// during restore.
	frozen bool
}

// NewEndpoint returns a raw  endpoint for the given protocols.
func NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return newEndpoint(stack, netProto, transProto, waiterQueue, true /* associated */)
}

func newEndpoint(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue, associated bool) (tcpip.Endpoint, tcpip.Error) {
	if netProto != header.IPv4ProtocolNumber && netProto != header.IPv6ProtocolNumber {
		return nil, &tcpip.ErrUnknownProtocol{}
	}

	e := &endpoint{
		stack: s,
		TransportEndpointInfo: stack.TransportEndpointInfo{
			NetProto:   netProto,
			TransProto: transProto,
		},
		waiterQueue: waiterQueue,
		associated:  associated,
	}
	e.ops.InitHandler(e, e.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	e.ops.SetHeaderIncluded(!associated)
	e.ops.SetSendBufferSize(32*1024, false /* notify */)
	e.ops.SetReceiveBufferSize(32*1024, false /* notify */)

	// Override with stack defaults.
	var ss tcpip.SendBufferSizeOption
	if err := s.Option(&ss); err == nil {
		e.ops.SetSendBufferSize(int64(ss.Default), false /* notify */)
	}

	var rs tcpip.ReceiveBufferSizeOption
	if err := s.Option(&rs); err == nil {
		e.ops.SetReceiveBufferSize(int64(rs.Default), false /* notify */)
	}

	// Unassociated endpoints are write-only and users call Write() with IP
	// headers included. Because they're write-only, We don't need to
	// register with the stack.
	if !associated {
		e.ops.SetReceiveBufferSize(0, false /* notify */)
		e.waiterQueue = nil
		return e, nil
	}

	if err := e.stack.RegisterRawTransportEndpoint(e.NetProto, e.TransProto, e); err != nil {
		return nil, err
	}

	return e, nil
}

// Abort implements stack.TransportEndpoint.Abort.
func (e *endpoint) Abort() {
	e.Close()
}

// Close implements tcpip.Endpoint.Close.
func (e *endpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed || !e.associated {
		return
	}

	e.stack.UnregisterRawTransportEndpoint(e.NetProto, e.TransProto, e)

	e.rcvMu.Lock()
	defer e.rcvMu.Unlock()

	// Clear the receive list.
	e.rcvClosed = true
	e.rcvBufSize = 0
	for !e.rcvList.Empty() {
		e.rcvList.Remove(e.rcvList.Front())
	}

	e.connected = false

	if e.route != nil {
		e.route.Release()
		e.route = nil
	}

	e.closed = true

	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (*endpoint) ModerateRecvBuf(int) {}

func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.owner = owner
}

// Read implements tcpip.Endpoint.Read.
func (e *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	e.rcvMu.Lock()

	// If there's no data to read, return that read would block or that the
	// endpoint is closed.
	if e.rcvList.Empty() {
		var err tcpip.Error = &tcpip.ErrWouldBlock{}
		if e.rcvClosed {
			e.stats.ReadErrors.ReadClosed.Increment()
			err = &tcpip.ErrClosedForReceive{}
		}
		e.rcvMu.Unlock()
		return tcpip.ReadResult{}, err
	}

	pkt := e.rcvList.Front()
	if !opts.Peek {
		e.rcvList.Remove(pkt)
		e.rcvBufSize -= pkt.data.Size()
	}

	e.rcvMu.Unlock()

	res := tcpip.ReadResult{
		Total: pkt.data.Size(),
		ControlMessages: tcpip.ControlMessages{
			HasTimestamp: true,
			Timestamp:    pkt.receivedAt.UnixNano(),
		},
	}
	if opts.NeedRemoteAddr {
		res.RemoteAddr = pkt.senderAddr
	}

	n, err := pkt.data.ReadTo(dst, opts.Peek)
	if n == 0 && err != nil {
		return res, &tcpip.ErrBadBuffer{}
	}
	res.Count = n
	return res, nil
}

// Write implements tcpip.Endpoint.Write.
func (e *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	// We can create, but not write to, unassociated IPv6 endpoints.
	if !e.associated && e.TransportEndpointInfo.NetProto == header.IPv6ProtocolNumber {
		return 0, &tcpip.ErrInvalidOptionValue{}
	}

	if opts.To != nil {
		// Raw sockets do not support sending to a IPv4 address on a IPv6 endpoint.
		if e.TransportEndpointInfo.NetProto == header.IPv6ProtocolNumber && len(opts.To.Addr) != header.IPv6AddressSize {
			return 0, &tcpip.ErrInvalidOptionValue{}
		}
	}

	n, err := e.write(p, opts)
	switch err.(type) {
	case nil:
		e.stats.PacketsSent.Increment()
	case *tcpip.ErrMessageTooLong, *tcpip.ErrInvalidOptionValue:
		e.stats.WriteErrors.InvalidArgs.Increment()
	case *tcpip.ErrClosedForSend:
		e.stats.WriteErrors.WriteClosed.Increment()
	case *tcpip.ErrInvalidEndpointState:
		e.stats.WriteErrors.InvalidEndpointState.Increment()
	case *tcpip.ErrNoRoute, *tcpip.ErrBroadcastDisabled, *tcpip.ErrNetworkUnreachable:
		// Errors indicating any problem with IP routing of the packet.
		e.stats.SendErrors.NoRoute.Increment()
	default:
		// For all other errors when writing to the network layer.
		e.stats.SendErrors.SendToNetworkFailed.Increment()
	}
	return n, err
}

func (e *endpoint) write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	// MSG_MORE is unimplemented. This also means that MSG_EOR is a no-op.
	if opts.More {
		return 0, &tcpip.ErrInvalidOptionValue{}
	}
	payloadBytes, route, owner, err := func() ([]byte, *stack.Route, tcpip.PacketOwner, tcpip.Error) {
		e.mu.RLock()
		defer e.mu.RUnlock()

		if e.closed {
			return nil, nil, nil, &tcpip.ErrInvalidEndpointState{}
		}

		payloadBytes := make([]byte, p.Len())
		if _, err := io.ReadFull(p, payloadBytes); err != nil {
			return nil, nil, nil, &tcpip.ErrBadBuffer{}
		}

		// Did the user caller provide a destination? If not, use the connected
		// destination.
		if opts.To == nil {
			// If the user doesn't specify a destination, they should have
			// connected to another address.
			if !e.connected {
				return nil, nil, nil, &tcpip.ErrDestinationRequired{}
			}

			e.route.Acquire()

			return payloadBytes, e.route, e.owner, nil
		}

		// The caller provided a destination. Reject destination address if it
		// goes through a different NIC than the endpoint was bound to.
		nic := opts.To.NIC
		if e.bound && nic != 0 && nic != e.BindNICID {
			return nil, nil, nil, &tcpip.ErrNoRoute{}
		}

		// Find the route to the destination. If BindAddress is 0,
		// FindRoute will choose an appropriate source address.
		route, err := e.stack.FindRoute(nic, e.BindAddr, opts.To.Addr, e.NetProto, false)
		if err != nil {
			return nil, nil, nil, err
		}

		return payloadBytes, route, e.owner, nil
	}()
	if err != nil {
		return 0, err
	}
	defer route.Release()

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()),
		Data:               buffer.View(payloadBytes).ToVectorisedView(),
	})
	pkt.Owner = owner

	if e.ops.GetHeaderIncluded() {
		if err := route.WriteHeaderIncludedPacket(pkt); err != nil {
			return 0, err
		}
		return int64(len(payloadBytes)), nil
	}

	if err := route.WritePacket(stack.NetworkHeaderParams{
		Protocol: e.TransProto,
		TTL:      route.DefaultTTL(),
		TOS:      stack.DefaultTOS,
	}, pkt); err != nil {
		return 0, err
	}
	return int64(len(payloadBytes)), nil
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (*endpoint) Disconnect() tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Connect implements tcpip.Endpoint.Connect.
func (e *endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	// Raw sockets do not support connecting to a IPv4 address on a IPv6 endpoint.
	if e.TransportEndpointInfo.NetProto == header.IPv6ProtocolNumber && len(addr.Addr) != header.IPv6AddressSize {
		return &tcpip.ErrAddressFamilyNotSupported{}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return &tcpip.ErrInvalidEndpointState{}
	}

	nic := addr.NIC
	if e.bound {
		if e.BindNICID == 0 {
			// If we're bound, but not to a specific NIC, the NIC
			// in addr will be used. Nothing to do here.
		} else if addr.NIC == 0 {
			// If we're bound to a specific NIC, but addr doesn't
			// specify a NIC, use the bound NIC.
			nic = e.BindNICID
		} else if addr.NIC != e.BindNICID {
			// We're bound and addr specifies a NIC. They must be
			// the same.
			return &tcpip.ErrInvalidEndpointState{}
		}
	}

	// Find a route to the destination.
	route, err := e.stack.FindRoute(nic, "", addr.Addr, e.NetProto, false)
	if err != nil {
		return err
	}

	if e.associated {
		// Re-register the endpoint with the appropriate NIC.
		if err := e.stack.RegisterRawTransportEndpoint(e.NetProto, e.TransProto, e); err != nil {
			route.Release()
			return err
		}
		e.stack.UnregisterRawTransportEndpoint(e.NetProto, e.TransProto, e)
		e.RegisterNICID = nic
	}

	if e.route != nil {
		// If the endpoint was previously connected then release any previous route.
		e.route.Release()
	}
	e.route = route
	e.connected = true

	return nil
}

// Shutdown implements tcpip.Endpoint.Shutdown. It's a noop for raw sockets.
func (e *endpoint) Shutdown(tcpip.ShutdownFlags) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.connected {
		return &tcpip.ErrNotConnected{}
	}
	return nil
}

// Listen implements tcpip.Endpoint.Listen.
func (*endpoint) Listen(int) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Accept implements tcpip.Endpoint.Accept.
func (*endpoint) Accept(*tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrNotSupported{}
}

// Bind implements tcpip.Endpoint.Bind.
func (e *endpoint) Bind(addr tcpip.FullAddress) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If a local address was specified, verify that it's valid.
	if len(addr.Addr) != 0 && e.stack.CheckLocalAddress(e.RegisterNICID, e.NetProto, addr.Addr) == 0 {
		return &tcpip.ErrBadLocalAddress{}
	}

	if e.associated {
		// Re-register the endpoint with the appropriate NIC.
		if err := e.stack.RegisterRawTransportEndpoint(e.NetProto, e.TransProto, e); err != nil {
			return err
		}
		e.stack.UnregisterRawTransportEndpoint(e.NetProto, e.TransProto, e)
		e.RegisterNICID = addr.NIC
		e.BindNICID = addr.NIC
	}

	e.BindAddr = addr.Addr
	e.bound = true

	return nil
}

// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	addr := e.BindAddr
	if e.connected {
		addr = e.route.LocalAddress()
	}

	return tcpip.FullAddress{
		NIC:  e.RegisterNICID,
		Addr: addr,
		// Linux returns the protocol in the port field.
		Port: uint16(e.TransProto),
	}, nil
}

// GetRemoteAddress implements tcpip.Endpoint.GetRemoteAddress.
func (*endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	// Even a connected socket doesn't return a remote address.
	return tcpip.FullAddress{}, &tcpip.ErrNotConnected{}
}

// Readiness implements tcpip.Endpoint.Readiness.
func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	// The endpoint is always writable.
	result := waiter.WritableEvents & mask

	// Determine whether the endpoint is readable.
	if (mask & waiter.ReadableEvents) != 0 {
		e.rcvMu.Lock()
		if !e.rcvList.Empty() || e.rcvClosed {
			result |= waiter.ReadableEvents
		}
		e.rcvMu.Unlock()
	}

	return result
}

// SetSockOpt implements tcpip.Endpoint.SetSockOpt.
func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	switch opt.(type) {
	case *tcpip.SocketDetachFilterOption:
		return nil

	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

func (*endpoint) SetSockOptInt(tcpip.SockOptInt, int) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (*endpoint) GetSockOpt(tcpip.GettableSocketOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (e *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
	case tcpip.ReceiveQueueSizeOption:
		v := 0
		e.rcvMu.Lock()
		if !e.rcvList.Empty() {
			p := e.rcvList.Front()
			v = p.data.Size()
		}
		e.rcvMu.Unlock()
		return v, nil

	default:
		return -1, &tcpip.ErrUnknownProtocolOption{}
	}
}

// HandlePacket implements stack.RawTransportEndpoint.HandlePacket.
func (e *endpoint) HandlePacket(pkt *stack.PacketBuffer) {
	e.mu.RLock()
	e.rcvMu.Lock()

	// Drop the packet if our buffer is currently full or if this is an unassociated
	// endpoint (i.e endpoint created  w/ IPPROTO_RAW). Such endpoints are send only
	// See: https://man7.org/linux/man-pages/man7/raw.7.html
	//
	//    An IPPROTO_RAW socket is send only.  If you really want to receive
	//    all IP packets, use a packet(7) socket with the ETH_P_IP protocol.
	//    Note that packet sockets don't reassemble IP fragments, unlike raw
	//    sockets.
	if e.rcvClosed || !e.associated {
		e.rcvMu.Unlock()
		e.mu.RUnlock()
		e.stack.Stats().DroppedPackets.Increment()
		e.stats.ReceiveErrors.ClosedReceiver.Increment()
		return
	}

	rcvBufSize := e.ops.GetReceiveBufferSize()
	if e.frozen || e.rcvBufSize >= int(rcvBufSize) {
		e.rcvMu.Unlock()
		e.mu.RUnlock()
		e.stack.Stats().DroppedPackets.Increment()
		e.stats.ReceiveErrors.ReceiveBufferOverflow.Increment()
		return
	}

	remoteAddr := pkt.Network().SourceAddress()

	if e.bound {
		// If bound to a NIC, only accept data for that NIC.
		if e.BindNICID != 0 && e.BindNICID != pkt.NICID {
			e.rcvMu.Unlock()
			e.mu.RUnlock()
			return
		}
		// If bound to an address, only accept data for that address.
		if e.BindAddr != "" && e.BindAddr != remoteAddr {
			e.rcvMu.Unlock()
			e.mu.RUnlock()
			return
		}
	}

	// If connected, only accept packets from the remote address we
	// connected to.
	if e.connected && e.route.RemoteAddress() != remoteAddr {
		e.rcvMu.Unlock()
		e.mu.RUnlock()
		return
	}

	wasEmpty := e.rcvBufSize == 0

	// Push new packet into receive list and increment the buffer size.
	packet := &rawPacket{
		senderAddr: tcpip.FullAddress{
			NIC:  pkt.NICID,
			Addr: remoteAddr,
		},
	}

	// Raw IPv4 endpoints return the IP header, but IPv6 endpoints do not.
	// We copy headers' underlying bytes because pkt.*Header may point to
	// the middle of a slice, and another struct may point to the "outer"
	// slice. Save/restore doesn't support overlapping slices and will fail.
	var combinedVV buffer.VectorisedView
	if e.TransportEndpointInfo.NetProto == header.IPv4ProtocolNumber {
		network, transport := pkt.NetworkHeader().View(), pkt.TransportHeader().View()
		headers := make(buffer.View, 0, len(network)+len(transport))
		headers = append(headers, network...)
		headers = append(headers, transport...)
		combinedVV = headers.ToVectorisedView()
	} else {
		combinedVV = append(buffer.View(nil), pkt.TransportHeader().View()...).ToVectorisedView()
	}
	combinedVV.Append(pkt.Data().ExtractVV())
	packet.data = combinedVV
	packet.receivedAt = e.stack.Clock().Now()

	e.rcvList.PushBack(packet)
	e.rcvBufSize += packet.data.Size()
	e.rcvMu.Unlock()
	e.mu.RUnlock()
	e.stats.PacketsReceived.Increment()
	// Notify waiters that there's data to be read.
	if wasEmpty {
		e.waiterQueue.Notify(waiter.ReadableEvents)
	}
}

// State implements socket.Socket.State.
func (e *endpoint) State() uint32 {
	return 0
}

// Info returns a copy of the endpoint info.
func (e *endpoint) Info() tcpip.EndpointInfo {
	e.mu.RLock()
	// Make a copy of the endpoint info.
	ret := e.TransportEndpointInfo
	e.mu.RUnlock()
	return &ret
}

// Stats returns a pointer to the endpoint stats.
func (e *endpoint) Stats() tcpip.EndpointStats {
	return &e.stats
}

// Wait implements stack.TransportEndpoint.Wait.
func (*endpoint) Wait() {}

// LastError implements tcpip.Endpoint.LastError.
func (*endpoint) LastError() tcpip.Error {
	return nil
}

// SocketOptions implements tcpip.Endpoint.SocketOptions.
func (e *endpoint) SocketOptions() *tcpip.SocketOptions {
	return &e.ops
}

// freeze prevents any more packets from being delivered to the endpoint.
func (e *endpoint) freeze() {
	e.mu.Lock()
	e.frozen = true
	e.mu.Unlock()
}

// thaw unfreezes a previously frozen endpoint using endpoint.freeze() allows
// new packets to be delivered again.
func (e *endpoint) thaw() {
	e.mu.Lock()
	e.frozen = false
	e.mu.Unlock()
}
