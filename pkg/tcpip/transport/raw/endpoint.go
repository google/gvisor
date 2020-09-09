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
	"fmt"

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
	data buffer.VectorisedView `state:".(buffer.VectorisedView)"`
	// timestampNS is the unix time at which the packet was received.
	timestampNS int64
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
	// The following fields are initialized at creation time and are
	// immutable.
	stack       *stack.Stack `state:"manual"`
	waiterQueue *waiter.Queue
	associated  bool
	hdrIncluded bool

	// The following fields are used to manage the receive queue and are
	// protected by rcvMu.
	rcvMu         sync.Mutex `state:"nosave"`
	rcvList       rawPacketList
	rcvBufSize    int
	rcvBufSizeMax int `state:".(int)"`
	rcvClosed     bool

	// The following fields are protected by mu.
	mu            sync.RWMutex `state:"nosave"`
	sndBufSize    int
	sndBufSizeMax int
	closed        bool
	connected     bool
	bound         bool
	// route is the route to a remote network endpoint. It is set via
	// Connect(), and is valid only when conneted is true.
	route stack.Route                  `state:"manual"`
	stats tcpip.TransportEndpointStats `state:"nosave"`

	// owner is used to get uid and gid of the packet.
	owner tcpip.PacketOwner
}

// NewEndpoint returns a raw  endpoint for the given protocols.
func NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return newEndpoint(stack, netProto, transProto, waiterQueue, true /* associated */)
}

func newEndpoint(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue, associated bool) (tcpip.Endpoint, *tcpip.Error) {
	if netProto != header.IPv4ProtocolNumber && netProto != header.IPv6ProtocolNumber {
		return nil, tcpip.ErrUnknownProtocol
	}

	e := &endpoint{
		stack: s,
		TransportEndpointInfo: stack.TransportEndpointInfo{
			NetProto:   netProto,
			TransProto: transProto,
		},
		waiterQueue:   waiterQueue,
		rcvBufSizeMax: 32 * 1024,
		sndBufSizeMax: 32 * 1024,
		associated:    associated,
		hdrIncluded:   !associated,
	}

	// Override with stack defaults.
	var ss stack.SendBufferSizeOption
	if err := s.Option(&ss); err == nil {
		e.sndBufSizeMax = ss.Default
	}

	var rs stack.ReceiveBufferSizeOption
	if err := s.Option(&rs); err == nil {
		e.rcvBufSizeMax = rs.Default
	}

	// Unassociated endpoints are write-only and users call Write() with IP
	// headers included. Because they're write-only, We don't need to
	// register with the stack.
	if !associated {
		e.rcvBufSizeMax = 0
		e.waiterQueue = nil
		return e, nil
	}

	if err := e.stack.RegisterRawTransportEndpoint(e.RegisterNICID, e.NetProto, e.TransProto, e); err != nil {
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

	e.stack.UnregisterRawTransportEndpoint(e.RegisterNICID, e.NetProto, e.TransProto, e)

	e.rcvMu.Lock()
	defer e.rcvMu.Unlock()

	// Clear the receive list.
	e.rcvClosed = true
	e.rcvBufSize = 0
	for !e.rcvList.Empty() {
		e.rcvList.Remove(e.rcvList.Front())
	}

	if e.connected {
		e.route.Release()
		e.connected = false
	}

	e.closed = true

	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.EventIn | waiter.EventOut)
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (e *endpoint) ModerateRecvBuf(copied int) {}

func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.owner = owner
}

// Read implements tcpip.Endpoint.Read.
func (e *endpoint) Read(addr *tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, *tcpip.Error) {
	e.rcvMu.Lock()

	// If there's no data to read, return that read would block or that the
	// endpoint is closed.
	if e.rcvList.Empty() {
		err := tcpip.ErrWouldBlock
		if e.rcvClosed {
			e.stats.ReadErrors.ReadClosed.Increment()
			err = tcpip.ErrClosedForReceive
		}
		e.rcvMu.Unlock()
		return buffer.View{}, tcpip.ControlMessages{}, err
	}

	pkt := e.rcvList.Front()
	e.rcvList.Remove(pkt)
	e.rcvBufSize -= pkt.data.Size()

	e.rcvMu.Unlock()

	if addr != nil {
		*addr = pkt.senderAddr
	}

	return pkt.data.ToView(), tcpip.ControlMessages{HasTimestamp: true, Timestamp: pkt.timestampNS}, nil
}

// Write implements tcpip.Endpoint.Write.
func (e *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, <-chan struct{}, *tcpip.Error) {
	// We can create, but not write to, unassociated IPv6 endpoints.
	if !e.associated && e.TransportEndpointInfo.NetProto == header.IPv6ProtocolNumber {
		return 0, nil, tcpip.ErrInvalidOptionValue
	}

	n, ch, err := e.write(p, opts)
	switch err {
	case nil:
		e.stats.PacketsSent.Increment()
	case tcpip.ErrMessageTooLong, tcpip.ErrInvalidOptionValue:
		e.stats.WriteErrors.InvalidArgs.Increment()
	case tcpip.ErrClosedForSend:
		e.stats.WriteErrors.WriteClosed.Increment()
	case tcpip.ErrInvalidEndpointState:
		e.stats.WriteErrors.InvalidEndpointState.Increment()
	case tcpip.ErrNoLinkAddress:
		e.stats.SendErrors.NoLinkAddr.Increment()
	case tcpip.ErrNoRoute, tcpip.ErrBroadcastDisabled, tcpip.ErrNetworkUnreachable:
		// Errors indicating any problem with IP routing of the packet.
		e.stats.SendErrors.NoRoute.Increment()
	default:
		// For all other errors when writing to the network layer.
		e.stats.SendErrors.SendToNetworkFailed.Increment()
	}
	return n, ch, err
}

func (e *endpoint) write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, <-chan struct{}, *tcpip.Error) {
	// MSG_MORE is unimplemented. This also means that MSG_EOR is a no-op.
	if opts.More {
		return 0, nil, tcpip.ErrInvalidOptionValue
	}

	e.mu.RLock()

	if e.closed {
		e.mu.RUnlock()
		return 0, nil, tcpip.ErrInvalidEndpointState
	}

	payloadBytes, err := p.FullPayload()
	if err != nil {
		e.mu.RUnlock()
		return 0, nil, err
	}

	// If this is an unassociated socket and callee provided a nonzero
	// destination address, route using that address.
	if e.hdrIncluded {
		ip := header.IPv4(payloadBytes)
		if !ip.IsValid(len(payloadBytes)) {
			e.mu.RUnlock()
			return 0, nil, tcpip.ErrInvalidOptionValue
		}
		dstAddr := ip.DestinationAddress()
		// Update dstAddr with the address in the IP header, unless
		// opts.To is set (e.g. if sendto specifies a specific
		// address).
		if dstAddr != tcpip.Address([]byte{0, 0, 0, 0}) && opts.To == nil {
			opts.To = &tcpip.FullAddress{
				NIC:  0,       // NIC is unset.
				Addr: dstAddr, // The address from the payload.
				Port: 0,       // There are no ports here.
			}
		}
	}

	// Did the user caller provide a destination? If not, use the connected
	// destination.
	if opts.To == nil {
		// If the user doesn't specify a destination, they should have
		// connected to another address.
		if !e.connected {
			e.mu.RUnlock()
			return 0, nil, tcpip.ErrDestinationRequired
		}

		if e.route.IsResolutionRequired() {
			savedRoute := &e.route
			// Promote lock to exclusive if using a shared route,
			// given that it may need to change in finishWrite.
			e.mu.RUnlock()
			e.mu.Lock()

			// Make sure that the route didn't change during the
			// time we didn't hold the lock.
			if !e.connected || savedRoute != &e.route {
				e.mu.Unlock()
				return 0, nil, tcpip.ErrInvalidEndpointState
			}

			n, ch, err := e.finishWrite(payloadBytes, savedRoute)
			e.mu.Unlock()
			return n, ch, err
		}

		n, ch, err := e.finishWrite(payloadBytes, &e.route)
		e.mu.RUnlock()
		return n, ch, err
	}

	// The caller provided a destination. Reject destination address if it
	// goes through a different NIC than the endpoint was bound to.
	nic := opts.To.NIC
	if e.bound && nic != 0 && nic != e.BindNICID {
		e.mu.RUnlock()
		return 0, nil, tcpip.ErrNoRoute
	}

	// Find the route to the destination. If BindAddress is 0,
	// FindRoute will choose an appropriate source address.
	route, err := e.stack.FindRoute(nic, e.BindAddr, opts.To.Addr, e.NetProto, false)
	if err != nil {
		e.mu.RUnlock()
		return 0, nil, err
	}

	n, ch, err := e.finishWrite(payloadBytes, &route)
	route.Release()
	e.mu.RUnlock()
	return n, ch, err
}

// finishWrite writes the payload to a route. It resolves the route if
// necessary. It's really just a helper to make defer unnecessary in Write.
func (e *endpoint) finishWrite(payloadBytes []byte, route *stack.Route) (int64, <-chan struct{}, *tcpip.Error) {
	// We may need to resolve the route (match a link layer address to the
	// network address). If that requires blocking (e.g. to use ARP),
	// return a channel on which the caller can wait.
	if route.IsResolutionRequired() {
		if ch, err := route.Resolve(nil); err != nil {
			if err == tcpip.ErrWouldBlock {
				return 0, ch, tcpip.ErrNoLinkAddress
			}
			return 0, nil, err
		}
	}

	if e.hdrIncluded {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: buffer.View(payloadBytes).ToVectorisedView(),
		})
		if err := route.WriteHeaderIncludedPacket(pkt); err != nil {
			return 0, nil, err
		}
	} else {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(route.MaxHeaderLength()),
			Data:               buffer.View(payloadBytes).ToVectorisedView(),
		})
		pkt.Owner = e.owner
		if err := route.WritePacket(nil /* gso */, stack.NetworkHeaderParams{
			Protocol: e.TransProto,
			TTL:      route.DefaultTTL(),
			TOS:      stack.DefaultTOS,
		}, pkt); err != nil {
			return 0, nil, err
		}
	}

	return int64(len(payloadBytes)), nil, nil
}

// Peek implements tcpip.Endpoint.Peek.
func (e *endpoint) Peek([][]byte) (int64, tcpip.ControlMessages, *tcpip.Error) {
	return 0, tcpip.ControlMessages{}, nil
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (*endpoint) Disconnect() *tcpip.Error {
	return tcpip.ErrNotSupported
}

// Connect implements tcpip.Endpoint.Connect.
func (e *endpoint) Connect(addr tcpip.FullAddress) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return tcpip.ErrInvalidEndpointState
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
			return tcpip.ErrInvalidEndpointState
		}
	}

	// Find a route to the destination.
	route, err := e.stack.FindRoute(nic, tcpip.Address(""), addr.Addr, e.NetProto, false)
	if err != nil {
		return err
	}
	defer route.Release()

	if e.associated {
		// Re-register the endpoint with the appropriate NIC.
		if err := e.stack.RegisterRawTransportEndpoint(addr.NIC, e.NetProto, e.TransProto, e); err != nil {
			return err
		}
		e.stack.UnregisterRawTransportEndpoint(e.RegisterNICID, e.NetProto, e.TransProto, e)
		e.RegisterNICID = nic
	}

	// Save the route we've connected via.
	e.route = route.Clone()
	e.connected = true

	return nil
}

// Shutdown implements tcpip.Endpoint.Shutdown. It's a noop for raw sockets.
func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.connected {
		return tcpip.ErrNotConnected
	}
	return nil
}

// Listen implements tcpip.Endpoint.Listen.
func (e *endpoint) Listen(backlog int) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// Accept implements tcpip.Endpoint.Accept.
func (e *endpoint) Accept() (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	return nil, nil, tcpip.ErrNotSupported
}

// Bind implements tcpip.Endpoint.Bind.
func (e *endpoint) Bind(addr tcpip.FullAddress) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If a local address was specified, verify that it's valid.
	if len(addr.Addr) != 0 && e.stack.CheckLocalAddress(addr.NIC, e.NetProto, addr.Addr) == 0 {
		return tcpip.ErrBadLocalAddress
	}

	if e.associated {
		// Re-register the endpoint with the appropriate NIC.
		if err := e.stack.RegisterRawTransportEndpoint(addr.NIC, e.NetProto, e.TransProto, e); err != nil {
			return err
		}
		e.stack.UnregisterRawTransportEndpoint(e.RegisterNICID, e.NetProto, e.TransProto, e)
		e.RegisterNICID = addr.NIC
		e.BindNICID = addr.NIC
	}

	e.BindAddr = addr.Addr
	e.bound = true

	return nil
}

// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	return tcpip.FullAddress{}, tcpip.ErrNotSupported
}

// GetRemoteAddress implements tcpip.Endpoint.GetRemoteAddress.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	// Even a connected socket doesn't return a remote address.
	return tcpip.FullAddress{}, tcpip.ErrNotConnected
}

// Readiness implements tcpip.Endpoint.Readiness.
func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	// The endpoint is always writable.
	result := waiter.EventOut & mask

	// Determine whether the endpoint is readable.
	if (mask & waiter.EventIn) != 0 {
		e.rcvMu.Lock()
		if !e.rcvList.Empty() || e.rcvClosed {
			result |= waiter.EventIn
		}
		e.rcvMu.Unlock()
	}

	return result
}

// SetSockOpt implements tcpip.Endpoint.SetSockOpt.
func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) *tcpip.Error {
	switch opt.(type) {
	case *tcpip.SocketDetachFilterOption:
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// SetSockOptBool implements tcpip.Endpoint.SetSockOptBool.
func (e *endpoint) SetSockOptBool(opt tcpip.SockOptBool, v bool) *tcpip.Error {
	switch opt {
	case tcpip.IPHdrIncludedOption:
		e.mu.Lock()
		e.hdrIncluded = v
		e.mu.Unlock()
		return nil
	}
	return tcpip.ErrUnknownProtocolOption
}

// SetSockOptInt implements tcpip.Endpoint.SetSockOptInt.
func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) *tcpip.Error {
	switch opt {
	case tcpip.SendBufferSizeOption:
		// Make sure the send buffer size is within the min and max
		// allowed.
		var ss stack.SendBufferSizeOption
		if err := e.stack.Option(&ss); err != nil {
			panic(fmt.Sprintf("s.Option(%#v) = %s", ss, err))
		}
		if v > ss.Max {
			v = ss.Max
		}
		if v < ss.Min {
			v = ss.Min
		}
		e.mu.Lock()
		e.sndBufSizeMax = v
		e.mu.Unlock()
		return nil

	case tcpip.ReceiveBufferSizeOption:
		// Make sure the receive buffer size is within the min and max
		// allowed.
		var rs stack.ReceiveBufferSizeOption
		if err := e.stack.Option(&rs); err != nil {
			panic(fmt.Sprintf("s.Option(%#v) = %s", rs, err))
		}
		if v > rs.Max {
			v = rs.Max
		}
		if v < rs.Min {
			v = rs.Min
		}
		e.rcvMu.Lock()
		e.rcvBufSizeMax = v
		e.rcvMu.Unlock()
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (*endpoint) GetSockOpt(tcpip.GettableSocketOption) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// GetSockOptBool implements tcpip.Endpoint.GetSockOptBool.
func (e *endpoint) GetSockOptBool(opt tcpip.SockOptBool) (bool, *tcpip.Error) {
	switch opt {
	case tcpip.KeepaliveEnabledOption:
		return false, nil

	case tcpip.IPHdrIncludedOption:
		e.mu.Lock()
		v := e.hdrIncluded
		e.mu.Unlock()
		return v, nil

	default:
		return false, tcpip.ErrUnknownProtocolOption
	}
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (e *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, *tcpip.Error) {
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

	case tcpip.SendBufferSizeOption:
		e.mu.Lock()
		v := e.sndBufSizeMax
		e.mu.Unlock()
		return v, nil

	case tcpip.ReceiveBufferSizeOption:
		e.rcvMu.Lock()
		v := e.rcvBufSizeMax
		e.rcvMu.Unlock()
		return v, nil

	default:
		return -1, tcpip.ErrUnknownProtocolOption
	}
}

// HandlePacket implements stack.RawTransportEndpoint.HandlePacket.
func (e *endpoint) HandlePacket(route *stack.Route, pkt *stack.PacketBuffer) {
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

	if e.bound {
		// If bound to a NIC, only accept data for that NIC.
		if e.BindNICID != 0 && e.BindNICID != route.NICID() {
			e.rcvMu.Unlock()
			return
		}
		// If bound to an address, only accept data for that address.
		if e.BindAddr != "" && e.BindAddr != route.RemoteAddress {
			e.rcvMu.Unlock()
			return
		}
	}

	// If connected, only accept packets from the remote address we
	// connected to.
	if e.connected && e.route.RemoteAddress != route.RemoteAddress {
		e.rcvMu.Unlock()
		return
	}

	wasEmpty := e.rcvBufSize == 0

	// Push new packet into receive list and increment the buffer size.
	packet := &rawPacket{
		senderAddr: tcpip.FullAddress{
			NIC:  route.NICID(),
			Addr: route.RemoteAddress,
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
	combinedVV.Append(pkt.Data)
	packet.data = combinedVV
	packet.timestampNS = e.stack.Clock().NowNanoseconds()

	e.rcvList.PushBack(packet)
	e.rcvBufSize += packet.data.Size()
	e.rcvMu.Unlock()
	e.stats.PacketsReceived.Increment()
	// Notify waiters that there's data to be read.
	if wasEmpty {
		e.waiterQueue.Notify(waiter.EventIn)
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

func (*endpoint) LastError() *tcpip.Error {
	return nil
}
