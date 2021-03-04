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

package icmp

import (
	"io"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// +stateify savable
type icmpPacket struct {
	icmpPacketEntry
	senderAddress tcpip.FullAddress
	data          buffer.VectorisedView `state:".(buffer.VectorisedView)"`
	timestamp     int64
}

type endpointState int

const (
	stateInitial endpointState = iota
	stateBound
	stateConnected
	stateClosed
)

// endpoint represents an ICMP endpoint. This struct serves as the interface
// between users of the endpoint and the protocol implementation; it is legal to
// have concurrent goroutines make calls into the endpoint, they are properly
// synchronized.
//
// +stateify savable
type endpoint struct {
	stack.TransportEndpointInfo
	tcpip.DefaultSocketOptionsHandler

	// The following fields are initialized at creation time and are
	// immutable.
	stack       *stack.Stack `state:"manual"`
	waiterQueue *waiter.Queue
	uniqueID    uint64

	// The following fields are used to manage the receive queue, and are
	// protected by rcvMu.
	rcvMu         sync.Mutex `state:"nosave"`
	rcvReady      bool
	rcvList       icmpPacketList
	rcvBufSizeMax int `state:".(int)"`
	rcvBufSize    int
	rcvClosed     bool

	// The following fields are protected by the mu mutex.
	mu sync.RWMutex `state:"nosave"`
	// shutdownFlags represent the current shutdown state of the endpoint.
	shutdownFlags tcpip.ShutdownFlags
	state         endpointState
	route         *stack.Route `state:"manual"`
	ttl           uint8
	stats         tcpip.TransportEndpointStats `state:"nosave"`

	// owner is used to get uid and gid of the packet.
	owner tcpip.PacketOwner

	// ops is used to get socket level options.
	ops tcpip.SocketOptions
}

func newEndpoint(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	ep := &endpoint{
		stack: s,
		TransportEndpointInfo: stack.TransportEndpointInfo{
			NetProto:   netProto,
			TransProto: transProto,
		},
		waiterQueue:   waiterQueue,
		rcvBufSizeMax: 32 * 1024,
		state:         stateInitial,
		uniqueID:      s.UniqueID(),
	}
	ep.ops.InitHandler(ep, ep.stack, tcpip.GetStackSendBufferLimits)
	ep.ops.SetSendBufferSize(32*1024, false /* notify */)

	// Override with stack defaults.
	var ss tcpip.SendBufferSizeOption
	if err := s.Option(&ss); err == nil {
		ep.ops.SetSendBufferSize(int64(ss.Default), false /* notify */)
	}
	return ep, nil
}

// UniqueID implements stack.TransportEndpoint.UniqueID.
func (e *endpoint) UniqueID() uint64 {
	return e.uniqueID
}

// Abort implements stack.TransportEndpoint.Abort.
func (e *endpoint) Abort() {
	e.Close()
}

// Close puts the endpoint in a closed state and frees all resources
// associated with it.
func (e *endpoint) Close() {
	e.mu.Lock()
	e.shutdownFlags = tcpip.ShutdownRead | tcpip.ShutdownWrite
	switch e.state {
	case stateBound, stateConnected:
		e.stack.UnregisterTransportEndpoint([]tcpip.NetworkProtocolNumber{e.NetProto}, e.TransProto, e.ID, e, ports.Flags{}, 0 /* bindToDevice */)
	}

	// Close the receive list and drain it.
	e.rcvMu.Lock()
	e.rcvClosed = true
	e.rcvBufSize = 0
	for !e.rcvList.Empty() {
		p := e.rcvList.Front()
		e.rcvList.Remove(p)
	}
	e.rcvMu.Unlock()

	if e.route != nil {
		e.route.Release()
		e.route = nil
	}

	// Update the state.
	e.state = stateClosed

	e.mu.Unlock()

	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.EventIn | waiter.EventOut)
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (e *endpoint) ModerateRecvBuf(copied int) {}

// SetOwner implements tcpip.Endpoint.SetOwner.
func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.owner = owner
}

// Read implements tcpip.Endpoint.Read.
func (e *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	e.rcvMu.Lock()

	if e.rcvList.Empty() {
		var err tcpip.Error = &tcpip.ErrWouldBlock{}
		if e.rcvClosed {
			e.stats.ReadErrors.ReadClosed.Increment()
			err = &tcpip.ErrClosedForReceive{}
		}
		e.rcvMu.Unlock()
		return tcpip.ReadResult{}, err
	}

	p := e.rcvList.Front()
	if !opts.Peek {
		e.rcvList.Remove(p)
		e.rcvBufSize -= p.data.Size()
	}

	e.rcvMu.Unlock()

	res := tcpip.ReadResult{
		Total: p.data.Size(),
		ControlMessages: tcpip.ControlMessages{
			HasTimestamp: true,
			Timestamp:    p.timestamp,
		},
	}
	if opts.NeedRemoteAddr {
		res.RemoteAddr = p.senderAddress
	}

	n, err := p.data.ReadTo(dst, opts.Peek)
	if n == 0 && err != nil {
		return res, &tcpip.ErrBadBuffer{}
	}
	res.Count = n
	return res, nil
}

// prepareForWrite prepares the endpoint for sending data. In particular, it
// binds it if it's still in the initial state. To do so, it must first
// reacquire the mutex in exclusive mode.
//
// Returns true for retry if preparation should be retried.
func (e *endpoint) prepareForWrite(to *tcpip.FullAddress) (retry bool, err tcpip.Error) {
	switch e.state {
	case stateInitial:
	case stateConnected:
		return false, nil

	case stateBound:
		if to == nil {
			return false, &tcpip.ErrDestinationRequired{}
		}
		return false, nil
	default:
		return false, &tcpip.ErrInvalidEndpointState{}
	}

	e.mu.RUnlock()
	defer e.mu.RLock()

	e.mu.Lock()
	defer e.mu.Unlock()

	// The state changed when we released the shared locked and re-acquired
	// it in exclusive mode. Try again.
	if e.state != stateInitial {
		return true, nil
	}

	// The state is still 'initial', so try to bind the endpoint.
	if err := e.bindLocked(tcpip.FullAddress{}); err != nil {
		return false, err
	}

	return true, nil
}

// Write writes data to the endpoint's peer. This method does not block
// if the data cannot be written.
func (e *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
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
	// MSG_MORE is unimplemented. (This also means that MSG_EOR is a no-op.)
	if opts.More {
		return 0, &tcpip.ErrInvalidOptionValue{}
	}

	to := opts.To

	e.mu.RLock()
	defer e.mu.RUnlock()

	// If we've shutdown with SHUT_WR we are in an invalid state for sending.
	if e.shutdownFlags&tcpip.ShutdownWrite != 0 {
		return 0, &tcpip.ErrClosedForSend{}
	}

	// Prepare for write.
	for {
		retry, err := e.prepareForWrite(to)
		if err != nil {
			return 0, err
		}

		if !retry {
			break
		}
	}

	route := e.route
	if to != nil {
		// Reject destination address if it goes through a different
		// NIC than the endpoint was bound to.
		nicID := to.NIC
		if e.BindNICID != 0 {
			if nicID != 0 && nicID != e.BindNICID {
				return 0, &tcpip.ErrNoRoute{}
			}

			nicID = e.BindNICID
		}

		dst, netProto, err := e.checkV4MappedLocked(*to)
		if err != nil {
			return 0, err
		}

		// Find the endpoint.
		r, err := e.stack.FindRoute(nicID, e.BindAddr, dst.Addr, netProto, false /* multicastLoop */)
		if err != nil {
			return 0, err
		}
		defer r.Release()

		route = r
	}

	v := make([]byte, p.Len())
	if _, err := io.ReadFull(p, v); err != nil {
		return 0, &tcpip.ErrBadBuffer{}
	}

	var err tcpip.Error
	switch e.NetProto {
	case header.IPv4ProtocolNumber:
		err = send4(route, e.ID.LocalPort, v, e.ttl, e.owner)

	case header.IPv6ProtocolNumber:
		err = send6(route, e.ID.LocalPort, v, e.ttl)
	}

	if err != nil {
		return 0, err
	}

	return int64(len(v)), nil
}

// SetSockOpt sets a socket option.
func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	return nil
}

// SetSockOptInt sets a socket option. Currently not supported.
func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	switch opt {
	case tcpip.TTLOption:
		e.mu.Lock()
		e.ttl = uint8(v)
		e.mu.Unlock()

	}
	return nil
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

	case tcpip.ReceiveBufferSizeOption:
		e.rcvMu.Lock()
		v := e.rcvBufSizeMax
		e.rcvMu.Unlock()
		return v, nil

	case tcpip.TTLOption:
		e.rcvMu.Lock()
		v := int(e.ttl)
		e.rcvMu.Unlock()
		return v, nil

	default:
		return -1, &tcpip.ErrUnknownProtocolOption{}
	}
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *endpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func send4(r *stack.Route, ident uint16, data buffer.View, ttl uint8, owner tcpip.PacketOwner) tcpip.Error {
	if len(data) < header.ICMPv4MinimumSize {
		return &tcpip.ErrInvalidEndpointState{}
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.ICMPv4MinimumSize + int(r.MaxHeaderLength()),
	})
	pkt.Owner = owner

	icmpv4 := header.ICMPv4(pkt.TransportHeader().Push(header.ICMPv4MinimumSize))
	pkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber
	copy(icmpv4, data)
	// Set the ident to the user-specified port. Sequence number should
	// already be set by the user.
	icmpv4.SetIdent(ident)
	data = data[header.ICMPv4MinimumSize:]

	// Linux performs these basic checks.
	if icmpv4.Type() != header.ICMPv4Echo || icmpv4.Code() != 0 {
		return &tcpip.ErrInvalidEndpointState{}
	}

	icmpv4.SetChecksum(0)
	icmpv4.SetChecksum(^header.Checksum(icmpv4, header.Checksum(data, 0)))

	pkt.Data().AppendView(data)

	if ttl == 0 {
		ttl = r.DefaultTTL()
	}
	return r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: header.ICMPv4ProtocolNumber, TTL: ttl, TOS: stack.DefaultTOS}, pkt)
}

func send6(r *stack.Route, ident uint16, data buffer.View, ttl uint8) tcpip.Error {
	if len(data) < header.ICMPv6EchoMinimumSize {
		return &tcpip.ErrInvalidEndpointState{}
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.ICMPv6MinimumSize + int(r.MaxHeaderLength()),
	})

	icmpv6 := header.ICMPv6(pkt.TransportHeader().Push(header.ICMPv6MinimumSize))
	pkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
	copy(icmpv6, data)
	// Set the ident. Sequence number is provided by the user.
	icmpv6.SetIdent(ident)
	data = data[header.ICMPv6MinimumSize:]

	if icmpv6.Type() != header.ICMPv6EchoRequest || icmpv6.Code() != 0 {
		return &tcpip.ErrInvalidEndpointState{}
	}

	pkt.Data().AppendView(data)
	dataRange := pkt.Data().AsRange()
	icmpv6.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpv6,
		Src:         r.LocalAddress,
		Dst:         r.RemoteAddress,
		PayloadCsum: dataRange.Checksum(),
		PayloadLen:  dataRange.Size(),
	}))

	if ttl == 0 {
		ttl = r.DefaultTTL()
	}
	return r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: ttl, TOS: stack.DefaultTOS}, pkt)
}

// checkV4MappedLocked determines the effective network protocol and converts
// addr to its canonical form.
func (e *endpoint) checkV4MappedLocked(addr tcpip.FullAddress) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, tcpip.Error) {
	unwrapped, netProto, err := e.TransportEndpointInfo.AddrNetProtoLocked(addr, false /* v6only */)
	if err != nil {
		return tcpip.FullAddress{}, 0, err
	}
	return unwrapped, netProto, nil
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (*endpoint) Disconnect() tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Connect connects the endpoint to its peer. Specifying a NIC is optional.
func (e *endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	nicID := addr.NIC
	localPort := uint16(0)
	switch e.state {
	case stateInitial:
	case stateBound, stateConnected:
		localPort = e.ID.LocalPort
		if e.BindNICID == 0 {
			break
		}

		if nicID != 0 && nicID != e.BindNICID {
			return &tcpip.ErrInvalidEndpointState{}
		}

		nicID = e.BindNICID
	default:
		return &tcpip.ErrInvalidEndpointState{}
	}

	addr, netProto, err := e.checkV4MappedLocked(addr)
	if err != nil {
		return err
	}

	// Find a route to the desired destination.
	r, err := e.stack.FindRoute(nicID, e.BindAddr, addr.Addr, netProto, false /* multicastLoop */)
	if err != nil {
		return err
	}

	id := stack.TransportEndpointID{
		LocalAddress:  r.LocalAddress,
		LocalPort:     localPort,
		RemoteAddress: r.RemoteAddress,
	}

	// Even if we're connected, this endpoint can still be used to send
	// packets on a different network protocol, so we register both even if
	// v6only is set to false and this is an ipv6 endpoint.
	netProtos := []tcpip.NetworkProtocolNumber{netProto}

	id, err = e.registerWithStack(nicID, netProtos, id)
	if err != nil {
		r.Release()
		return err
	}

	e.ID = id
	e.route = r
	e.RegisterNICID = nicID

	e.state = stateConnected

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

// ConnectEndpoint is not supported.
func (*endpoint) ConnectEndpoint(tcpip.Endpoint) tcpip.Error {
	return &tcpip.ErrInvalidEndpointState{}
}

// Shutdown closes the read and/or write end of the endpoint connection
// to its peer.
func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.shutdownFlags |= flags

	if e.state != stateConnected {
		return &tcpip.ErrNotConnected{}
	}

	if flags&tcpip.ShutdownRead != 0 {
		e.rcvMu.Lock()
		wasClosed := e.rcvClosed
		e.rcvClosed = true
		e.rcvMu.Unlock()

		if !wasClosed {
			e.waiterQueue.Notify(waiter.EventIn)
		}
	}

	return nil
}

// Listen is not supported by UDP, it just fails.
func (*endpoint) Listen(int) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Accept is not supported by UDP, it just fails.
func (*endpoint) Accept(*tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrNotSupported{}
}

func (e *endpoint) registerWithStack(nicID tcpip.NICID, netProtos []tcpip.NetworkProtocolNumber, id stack.TransportEndpointID) (stack.TransportEndpointID, tcpip.Error) {
	if id.LocalPort != 0 {
		// The endpoint already has a local port, just attempt to
		// register it.
		err := e.stack.RegisterTransportEndpoint(netProtos, e.TransProto, id, e, ports.Flags{}, 0 /* bindToDevice */)
		return id, err
	}

	// We need to find a port for the endpoint.
	_, err := e.stack.PickEphemeralPort(func(p uint16) (bool, tcpip.Error) {
		id.LocalPort = p
		err := e.stack.RegisterTransportEndpoint(netProtos, e.TransProto, id, e, ports.Flags{}, 0 /* bindtodevice */)
		switch err.(type) {
		case nil:
			return true, nil
		case *tcpip.ErrPortInUse:
			return false, nil
		default:
			return false, err
		}
	})

	return id, err
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress) tcpip.Error {
	// Don't allow binding once endpoint is not in the initial state
	// anymore.
	if e.state != stateInitial {
		return &tcpip.ErrInvalidEndpointState{}
	}

	addr, netProto, err := e.checkV4MappedLocked(addr)
	if err != nil {
		return err
	}

	// Expand netProtos to include v4 and v6 if the caller is binding to a
	// wildcard (empty) address, and this is an IPv6 endpoint with v6only
	// set to false.
	netProtos := []tcpip.NetworkProtocolNumber{netProto}

	if len(addr.Addr) != 0 {
		// A local address was specified, verify that it's valid.
		if e.stack.CheckLocalAddress(addr.NIC, netProto, addr.Addr) == 0 {
			return &tcpip.ErrBadLocalAddress{}
		}
	}

	id := stack.TransportEndpointID{
		LocalPort:    addr.Port,
		LocalAddress: addr.Addr,
	}
	id, err = e.registerWithStack(addr.NIC, netProtos, id)
	if err != nil {
		return err
	}

	e.ID = id
	e.RegisterNICID = addr.NIC

	// Mark endpoint as bound.
	e.state = stateBound

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

// Bind binds the endpoint to a specific local address and port.
// Specifying a NIC is optional.
func (e *endpoint) Bind(addr tcpip.FullAddress) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	err := e.bindLocked(addr)
	if err != nil {
		return err
	}

	e.BindNICID = addr.NIC
	e.BindAddr = addr.Addr

	return nil
}

// GetLocalAddress returns the address to which the endpoint is bound.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return tcpip.FullAddress{
		NIC:  e.RegisterNICID,
		Addr: e.ID.LocalAddress,
		Port: e.ID.LocalPort,
	}, nil
}

// GetRemoteAddress returns the address to which the endpoint is connected.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.state != stateConnected {
		return tcpip.FullAddress{}, &tcpip.ErrNotConnected{}
	}

	return tcpip.FullAddress{
		NIC:  e.RegisterNICID,
		Addr: e.ID.RemoteAddress,
		Port: e.ID.RemotePort,
	}, nil
}

// Readiness returns the current readiness of the endpoint. For example, if
// waiter.EventIn is set, the endpoint is immediately readable.
func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	// The endpoint is always writable.
	result := waiter.EventOut & mask

	// Determine if the endpoint is readable if requested.
	if (mask & waiter.EventIn) != 0 {
		e.rcvMu.Lock()
		if !e.rcvList.Empty() || e.rcvClosed {
			result |= waiter.EventIn
		}
		e.rcvMu.Unlock()
	}

	return result
}

// HandlePacket is called by the stack when new packets arrive to this transport
// endpoint.
func (e *endpoint) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	// Only accept echo replies.
	switch e.NetProto {
	case header.IPv4ProtocolNumber:
		h := header.ICMPv4(pkt.TransportHeader().View())
		// TODO(b/129292233): Determine if len(h) check is still needed after early
		// parsing.
		if len(h) < header.ICMPv4MinimumSize || h.Type() != header.ICMPv4EchoReply {
			e.stack.Stats().DroppedPackets.Increment()
			e.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
			return
		}
	case header.IPv6ProtocolNumber:
		h := header.ICMPv6(pkt.TransportHeader().View())
		// TODO(b/129292233): Determine if len(h) check is still needed after early
		// parsing.
		if len(h) < header.ICMPv6MinimumSize || h.Type() != header.ICMPv6EchoReply {
			e.stack.Stats().DroppedPackets.Increment()
			e.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
			return
		}
	}

	e.rcvMu.Lock()

	// Drop the packet if our buffer is currently full.
	if !e.rcvReady || e.rcvClosed {
		e.rcvMu.Unlock()
		e.stack.Stats().DroppedPackets.Increment()
		e.stats.ReceiveErrors.ClosedReceiver.Increment()
		return
	}

	if e.rcvBufSize >= e.rcvBufSizeMax {
		e.rcvMu.Unlock()
		e.stack.Stats().DroppedPackets.Increment()
		e.stats.ReceiveErrors.ReceiveBufferOverflow.Increment()
		return
	}

	wasEmpty := e.rcvBufSize == 0

	// Push new packet into receive list and increment the buffer size.
	packet := &icmpPacket{
		senderAddress: tcpip.FullAddress{
			NIC:  pkt.NICID,
			Addr: id.RemoteAddress,
		},
	}

	// ICMP socket's data includes ICMP header.
	packet.data = pkt.TransportHeader().View().ToVectorisedView()
	packet.data.Append(pkt.Data().ExtractVV())

	e.rcvList.PushBack(packet)
	e.rcvBufSize += packet.data.Size()

	packet.timestamp = e.stack.Clock().NowNanoseconds()

	e.rcvMu.Unlock()
	e.stats.PacketsReceived.Increment()
	// Notify any waiters that there's data to be read now.
	if wasEmpty {
		e.waiterQueue.Notify(waiter.EventIn)
	}
}

// HandleError implements stack.TransportEndpoint.
func (*endpoint) HandleError(stack.TransportError, *stack.PacketBuffer) {}

// State implements tcpip.Endpoint.State. The ICMP endpoint currently doesn't
// expose internal socket state.
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
