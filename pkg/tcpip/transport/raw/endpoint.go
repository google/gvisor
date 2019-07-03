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
//   * optionally write and inspect network layer and link layer headers for
//     packets
//
// Raw sockets don't have any notion of ports, and incoming packets are
// demultiplexed solely by protocol number. Thus, a raw UDP endpoint will
// receive every UDP packet received by netstack. bind(2) and connect(2) can be
// used to filter incoming packets by source and destination.
package raw

import (
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// +stateify savable
type packet struct {
	packetEntry
	// data holds the actual packet data, including any headers and
	// payload.
	data buffer.VectorisedView `state:".(buffer.VectorisedView)"`
	// views is pre-allocated space to back data. As long as the packet is
	// made up of fewer than 8 buffer.Views, no extra allocation is
	// necessary to store packet data.
	views [8]buffer.View `state:"nosave"`
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
	// The following fields are initialized at creation time and are
	// immutable.
	stack       *stack.Stack `state:"manual"`
	netProto    tcpip.NetworkProtocolNumber
	transProto  tcpip.TransportProtocolNumber
	waiterQueue *waiter.Queue

	// The following fields are used to manage the receive queue and are
	// protected by rcvMu.
	rcvMu         sync.Mutex `state:"nosave"`
	rcvList       packetList
	rcvBufSizeMax int `state:".(int)"`
	rcvBufSize    int
	rcvClosed     bool

	// The following fields are protected by mu.
	mu         sync.RWMutex `state:"nosave"`
	sndBufSize int
	closed     bool
	connected  bool
	bound      bool
	// registeredNIC is the NIC to which th endpoint is explicitly
	// registered. Is set when Connect or Bind are used to specify a NIC.
	registeredNIC tcpip.NICID
	// boundNIC and boundAddr are set on calls to Bind(). When callers
	// attempt actions that would invalidate the binding data (e.g. sending
	// data via a NIC other than boundNIC), the endpoint will return an
	// error.
	boundNIC  tcpip.NICID
	boundAddr tcpip.Address
	// route is the route to a remote network endpoint. It is set via
	// Connect(), and is valid only when conneted is true.
	route stack.Route `state:"manual"`
}

// NewEndpoint returns a raw  endpoint for the given protocols.
// TODO(b/129292371): IP_HDRINCL, IPPROTO_RAW, and AF_PACKET.
func NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	if netProto != header.IPv4ProtocolNumber {
		return nil, tcpip.ErrUnknownProtocol
	}

	ep := &endpoint{
		stack:         stack,
		netProto:      netProto,
		transProto:    transProto,
		waiterQueue:   waiterQueue,
		rcvBufSizeMax: 32 * 1024,
		sndBufSize:    32 * 1024,
	}

	if err := ep.stack.RegisterRawTransportEndpoint(ep.registeredNIC, ep.netProto, ep.transProto, ep); err != nil {
		return nil, err
	}

	return ep, nil
}

// Close implements tcpip.Endpoint.Close.
func (ep *endpoint) Close() {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if ep.closed {
		return
	}

	ep.stack.UnregisterRawTransportEndpoint(ep.registeredNIC, ep.netProto, ep.transProto, ep)

	ep.rcvMu.Lock()
	defer ep.rcvMu.Unlock()

	// Clear the receive list.
	ep.rcvClosed = true
	ep.rcvBufSize = 0
	for !ep.rcvList.Empty() {
		ep.rcvList.Remove(ep.rcvList.Front())
	}

	if ep.connected {
		ep.route.Release()
	}

	ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.EventIn | waiter.EventOut)
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (ep *endpoint) ModerateRecvBuf(copied int) {}

// Read implements tcpip.Endpoint.Read.
func (ep *endpoint) Read(addr *tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, *tcpip.Error) {
	ep.rcvMu.Lock()

	// If there's no data to read, return that read would block or that the
	// endpoint is closed.
	if ep.rcvList.Empty() {
		err := tcpip.ErrWouldBlock
		if ep.rcvClosed {
			err = tcpip.ErrClosedForReceive
		}
		ep.rcvMu.Unlock()
		return buffer.View{}, tcpip.ControlMessages{}, err
	}

	packet := ep.rcvList.Front()
	ep.rcvList.Remove(packet)
	ep.rcvBufSize -= packet.data.Size()

	ep.rcvMu.Unlock()

	if addr != nil {
		*addr = packet.senderAddr
	}

	return packet.data.ToView(), tcpip.ControlMessages{HasTimestamp: true, Timestamp: packet.timestampNS}, nil
}

// Write implements tcpip.Endpoint.Write.
func (ep *endpoint) Write(payload tcpip.Payload, opts tcpip.WriteOptions) (uintptr, <-chan struct{}, *tcpip.Error) {
	// MSG_MORE is unimplemented. This also means that MSG_EOR is a no-op.
	if opts.More {
		return 0, nil, tcpip.ErrInvalidOptionValue
	}

	ep.mu.RLock()

	if ep.closed {
		ep.mu.RUnlock()
		return 0, nil, tcpip.ErrInvalidEndpointState
	}

	// Did the user caller provide a destination? If not, use the connected
	// destination.
	if opts.To == nil {
		// If the user doesn't specify a destination, they should have
		// connected to another address.
		if !ep.connected {
			ep.mu.RUnlock()
			return 0, nil, tcpip.ErrDestinationRequired
		}

		if ep.route.IsResolutionRequired() {
			savedRoute := &ep.route
			// Promote lock to exclusive if using a shared route,
			// given that it may need to change in finishWrite.
			ep.mu.RUnlock()
			ep.mu.Lock()

			// Make sure that the route didn't change during the
			// time we didn't hold the lock.
			if !ep.connected || savedRoute != &ep.route {
				ep.mu.Unlock()
				return 0, nil, tcpip.ErrInvalidEndpointState
			}

			n, ch, err := ep.finishWrite(payload, savedRoute)
			ep.mu.Unlock()
			return n, ch, err
		}

		n, ch, err := ep.finishWrite(payload, &ep.route)
		ep.mu.RUnlock()
		return n, ch, err
	}

	// The caller provided a destination. Reject destination address if it
	// goes through a different NIC than the endpoint was bound to.
	nic := opts.To.NIC
	if ep.bound && nic != 0 && nic != ep.boundNIC {
		ep.mu.RUnlock()
		return 0, nil, tcpip.ErrNoRoute
	}

	// We don't support IPv6 yet, so this has to be an IPv4 address.
	if len(opts.To.Addr) != header.IPv4AddressSize {
		ep.mu.RUnlock()
		return 0, nil, tcpip.ErrInvalidEndpointState
	}

	// Find the route to the destination. If boundAddress is 0,
	// FindRoute will choose an appropriate source address.
	route, err := ep.stack.FindRoute(nic, ep.boundAddr, opts.To.Addr, ep.netProto, false)
	if err != nil {
		ep.mu.RUnlock()
		return 0, nil, err
	}

	n, ch, err := ep.finishWrite(payload, &route)
	route.Release()
	ep.mu.RUnlock()
	return n, ch, err
}

// finishWrite writes the payload to a route. It resolves the route if
// necessary. It's really just a helper to make defer unnecessary in Write.
func (ep *endpoint) finishWrite(payload tcpip.Payload, route *stack.Route) (uintptr, <-chan struct{}, *tcpip.Error) {
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

	payloadBytes, err := payload.Get(payload.Size())
	if err != nil {
		return 0, nil, err
	}

	switch ep.netProto {
	case header.IPv4ProtocolNumber:
		hdr := buffer.NewPrependable(len(payloadBytes) + int(route.MaxHeaderLength()))
		if err := route.WritePacket(nil /* gso */, hdr, buffer.View(payloadBytes).ToVectorisedView(), ep.transProto, route.DefaultTTL()); err != nil {
			return 0, nil, err
		}

	default:
		return 0, nil, tcpip.ErrUnknownProtocol
	}

	return uintptr(len(payloadBytes)), nil, nil
}

// Peek implements tcpip.Endpoint.Peek.
func (ep *endpoint) Peek([][]byte) (uintptr, tcpip.ControlMessages, *tcpip.Error) {
	return 0, tcpip.ControlMessages{}, nil
}

// Connect implements tcpip.Endpoint.Connect.
func (ep *endpoint) Connect(addr tcpip.FullAddress) *tcpip.Error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if addr.Addr == "" {
		// AF_UNSPEC isn't supported.
		return tcpip.ErrAddressFamilyNotSupported
	}

	if ep.closed {
		return tcpip.ErrInvalidEndpointState
	}

	// We don't support IPv6 yet.
	if len(addr.Addr) != header.IPv4AddressSize {
		return tcpip.ErrInvalidEndpointState
	}

	nic := addr.NIC
	if ep.bound {
		if ep.boundNIC == 0 {
			// If we're bound, but not to a specific NIC, the NIC
			// in addr will be used. Nothing to do here.
		} else if addr.NIC == 0 {
			// If we're bound to a specific NIC, but addr doesn't
			// specify a NIC, use the bound NIC.
			nic = ep.boundNIC
		} else if addr.NIC != ep.boundNIC {
			// We're bound and addr specifies a NIC. They must be
			// the same.
			return tcpip.ErrInvalidEndpointState
		}
	}

	// Find a route to the destination.
	route, err := ep.stack.FindRoute(nic, tcpip.Address(""), addr.Addr, ep.netProto, false)
	if err != nil {
		return err
	}
	defer route.Release()

	// Re-register the endpoint with the appropriate NIC.
	if err := ep.stack.RegisterRawTransportEndpoint(addr.NIC, ep.netProto, ep.transProto, ep); err != nil {
		return err
	}
	ep.stack.UnregisterRawTransportEndpoint(ep.registeredNIC, ep.netProto, ep.transProto, ep)

	// Save the route and NIC we've connected via.
	ep.route = route.Clone()
	ep.registeredNIC = nic
	ep.connected = true

	return nil
}

// Shutdown implements tcpip.Endpoint.Shutdown. It's a noop for raw sockets.
func (ep *endpoint) Shutdown(flags tcpip.ShutdownFlags) *tcpip.Error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if !ep.connected {
		return tcpip.ErrNotConnected
	}
	return nil
}

// Listen implements tcpip.Endpoint.Listen.
func (ep *endpoint) Listen(backlog int) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// Accept implements tcpip.Endpoint.Accept.
func (ep *endpoint) Accept() (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	return nil, nil, tcpip.ErrNotSupported
}

// Bind implements tcpip.Endpoint.Bind.
func (ep *endpoint) Bind(addr tcpip.FullAddress) *tcpip.Error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	// Callers must provide an IPv4 address or no network address (for
	// binding to a NIC, but not an address).
	if len(addr.Addr) != 0 && len(addr.Addr) != 4 {
		return tcpip.ErrInvalidEndpointState
	}

	// If a local address was specified, verify that it's valid.
	if len(addr.Addr) == header.IPv4AddressSize && ep.stack.CheckLocalAddress(addr.NIC, ep.netProto, addr.Addr) == 0 {
		return tcpip.ErrBadLocalAddress
	}

	// Re-register the endpoint with the appropriate NIC.
	if err := ep.stack.RegisterRawTransportEndpoint(addr.NIC, ep.netProto, ep.transProto, ep); err != nil {
		return err
	}
	ep.stack.UnregisterRawTransportEndpoint(ep.registeredNIC, ep.netProto, ep.transProto, ep)

	ep.registeredNIC = addr.NIC
	ep.boundNIC = addr.NIC
	ep.boundAddr = addr.Addr
	ep.bound = true

	return nil
}

// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress.
func (ep *endpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	return tcpip.FullAddress{}, tcpip.ErrNotSupported
}

// GetRemoteAddress implements tcpip.Endpoint.GetRemoteAddress.
func (ep *endpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	// Even a connected socket doesn't return a remote address.
	return tcpip.FullAddress{}, tcpip.ErrNotConnected
}

// Readiness implements tcpip.Endpoint.Readiness.
func (ep *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	// The endpoint is always writable.
	result := waiter.EventOut & mask

	// Determine whether the endpoint is readable.
	if (mask & waiter.EventIn) != 0 {
		ep.rcvMu.Lock()
		if !ep.rcvList.Empty() || ep.rcvClosed {
			result |= waiter.EventIn
		}
		ep.rcvMu.Unlock()
	}

	return result
}

// SetSockOpt implements tcpip.Endpoint.SetSockOpt.
func (ep *endpoint) SetSockOpt(opt interface{}) *tcpip.Error {
	return nil
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (ep *endpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	switch o := opt.(type) {
	case tcpip.ErrorOption:
		return nil

	case *tcpip.SendBufferSizeOption:
		ep.mu.Lock()
		*o = tcpip.SendBufferSizeOption(ep.sndBufSize)
		ep.mu.Unlock()
		return nil

	case *tcpip.ReceiveBufferSizeOption:
		ep.rcvMu.Lock()
		*o = tcpip.ReceiveBufferSizeOption(ep.rcvBufSizeMax)
		ep.rcvMu.Unlock()
		return nil

	case *tcpip.ReceiveQueueSizeOption:
		ep.rcvMu.Lock()
		if ep.rcvList.Empty() {
			*o = 0
		} else {
			p := ep.rcvList.Front()
			*o = tcpip.ReceiveQueueSizeOption(p.data.Size())
		}
		ep.rcvMu.Unlock()
		return nil

	case *tcpip.KeepaliveEnabledOption:
		*o = 0
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// HandlePacket implements stack.RawTransportEndpoint.HandlePacket.
func (ep *endpoint) HandlePacket(route *stack.Route, netHeader buffer.View, vv buffer.VectorisedView) {
	ep.rcvMu.Lock()

	// Drop the packet if our buffer is currently full.
	if ep.rcvClosed || ep.rcvBufSize >= ep.rcvBufSizeMax {
		ep.stack.Stats().DroppedPackets.Increment()
		ep.rcvMu.Unlock()
		return
	}

	if ep.bound {
		// If bound to a NIC, only accept data for that NIC.
		if ep.boundNIC != 0 && ep.boundNIC != route.NICID() {
			ep.rcvMu.Unlock()
			return
		}
		// If bound to an address, only accept data for that address.
		if ep.boundAddr != "" && ep.boundAddr != route.RemoteAddress {
			ep.rcvMu.Unlock()
			return
		}
	}

	// If connected, only accept packets from the remote address we
	// connected to.
	if ep.connected && ep.route.RemoteAddress != route.RemoteAddress {
		ep.rcvMu.Unlock()
		return
	}

	wasEmpty := ep.rcvBufSize == 0

	// Push new packet into receive list and increment the buffer size.
	packet := &packet{
		senderAddr: tcpip.FullAddress{
			NIC:  route.NICID(),
			Addr: route.RemoteAddress,
		},
	}

	combinedVV := netHeader.ToVectorisedView()
	combinedVV.Append(vv)
	packet.data = combinedVV.Clone(packet.views[:])
	packet.timestampNS = ep.stack.NowNanoseconds()

	ep.rcvList.PushBack(packet)
	ep.rcvBufSize += packet.data.Size()

	ep.rcvMu.Unlock()

	// Notify waiters that there's data to be read.
	if wasEmpty {
		ep.waiterQueue.Notify(waiter.EventIn)
	}
}

// State implements socket.Socket.State.
func (ep *endpoint) State() uint32 {
	return 0
}
