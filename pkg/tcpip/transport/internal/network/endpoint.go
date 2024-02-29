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

// Package network provides facilities to support tcpip.Endpoints that operate
// at the network layer or above.
package network

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Endpoint is a datagram-based endpoint. It only supports sending datagrams to
// a peer.
//
// +stateify savable
type Endpoint struct {
	// The following fields must only be set once then never changed.
	stack       *stack.Stack `state:"manual"`
	ops         *tcpip.SocketOptions
	netProto    tcpip.NetworkProtocolNumber
	transProto  tcpip.TransportProtocolNumber
	waiterQueue *waiter.Queue

	mu sync.RWMutex `state:"nosave"`
	// +checklocks:mu
	wasBound bool
	// owner is the owner of transmitted packets.
	//
	// +checklocks:mu
	owner tcpip.PacketOwner
	// +checklocks:mu
	writeShutdown bool
	// +checklocks:mu
	effectiveNetProto tcpip.NetworkProtocolNumber
	// +checklocks:mu
	connectedRoute *stack.Route `state:"manual"`
	// +checklocks:mu
	multicastMemberships map[multicastMembership]struct{}
	// +checklocks:mu
	ipv4TTL uint8
	// +checklocks:mu
	ipv6HopLimit int16
	// TODO(https://gvisor.dev/issue/6389): Use different fields for IPv4/IPv6.
	// +checklocks:mu
	multicastTTL uint8
	// TODO(https://gvisor.dev/issue/6389): Use different fields for IPv4/IPv6.
	// +checklocks:mu
	multicastAddr tcpip.Address
	// TODO(https://gvisor.dev/issue/6389): Use different fields for IPv4/IPv6.
	// +checklocks:mu
	multicastNICID tcpip.NICID
	// +checklocks:mu
	ipv4TOS uint8
	// +checklocks:mu
	ipv6TClass uint8

	// Lock ordering: mu > infoMu.
	infoMu sync.RWMutex `state:"nosave"`
	// info has a dedicated mutex so that we can avoid lock ordering violations
	// when reading the endpoint's info. If we used mu, we need to guarantee
	// that any lock taken while mu is held is not held when calling Info()
	// which is not true as of writing (we hold mu while registering transport
	// endpoints (taking the transport demuxer lock but we also hold the demuxer
	// lock when delivering packets/errors to endpoints).
	//
	// Writes must be performed through setInfo.
	//
	// +checklocks:infoMu
	info stack.TransportEndpointInfo

	// state holds a transport.DatagramBasedEndpointState.
	//
	// state must be accessed with atomics so that we can avoid lock ordering
	// violations when reading the state. If we used mu, we need to guarantee
	// that any lock taken while mu is held is not held when calling State()
	// which is not true as of writing (we hold mu while registering transport
	// endpoints (taking the transport demuxer lock but we also hold the demuxer
	// lock when delivering packets/errors to endpoints).
	//
	// Writes must be performed through setEndpointState.
	state atomicbitops.Uint32

	// Callers should not attempt to obtain sendBufferSizeInUseMu while holding
	// another lock on Endpoint.
	sendBufferSizeInUseMu sync.RWMutex `state:"nosave"`
	// sendBufferSizeInUse keeps track of the bytes in use by in-flight packets.
	//
	// +checklocks:sendBufferSizeInUseMu
	sendBufferSizeInUse int64 `state:"nosave"`
}

// +stateify savable
type multicastMembership struct {
	nicID         tcpip.NICID
	multicastAddr tcpip.Address
}

// Init initializes the endpoint.
func (e *Endpoint) Init(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ops *tcpip.SocketOptions, waiterQueue *waiter.Queue) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.multicastMemberships != nil {
		panic(fmt.Sprintf("endpoint is already initialized; got e.multicastMemberships = %#v, want = nil", e.multicastMemberships))
	}

	switch netProto {
	case header.IPv4ProtocolNumber, header.IPv6ProtocolNumber:
	default:
		panic(fmt.Sprintf("invalid protocol number = %d", netProto))
	}

	e.stack = s
	e.ops = ops
	e.netProto = netProto
	e.transProto = transProto
	e.waiterQueue = waiterQueue
	e.infoMu.Lock()
	e.info = stack.TransportEndpointInfo{
		NetProto:   netProto,
		TransProto: transProto,
	}
	e.infoMu.Unlock()
	e.effectiveNetProto = netProto
	e.ipv4TTL = tcpip.UseDefaultIPv4TTL
	e.ipv6HopLimit = tcpip.UseDefaultIPv6HopLimit

	// Linux defaults to TTL=1.
	e.multicastTTL = 1
	e.multicastMemberships = make(map[multicastMembership]struct{})
	e.setEndpointState(transport.DatagramEndpointStateInitial)
}

// NetProto returns the network protocol the endpoint was initialized with.
func (e *Endpoint) NetProto() tcpip.NetworkProtocolNumber {
	return e.netProto
}

// setEndpointState sets the state of the endpoint.
//
// e.mu must be held to synchronize changes to state with the rest of the
// endpoint.
//
// +checklocks:e.mu
func (e *Endpoint) setEndpointState(state transport.DatagramEndpointState) {
	e.state.Store(uint32(state))
}

// State returns the state of the endpoint.
func (e *Endpoint) State() transport.DatagramEndpointState {
	return transport.DatagramEndpointState(e.state.Load())
}

// Close cleans the endpoint's resources and leaves the endpoint in a closed
// state.
func (e *Endpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.State() == transport.DatagramEndpointStateClosed {
		return
	}

	for mem := range e.multicastMemberships {
		e.stack.LeaveGroup(e.netProto, mem.nicID, mem.multicastAddr)
	}
	e.multicastMemberships = nil

	if e.connectedRoute != nil {
		e.connectedRoute.Release()
		e.connectedRoute = nil
	}

	e.setEndpointState(transport.DatagramEndpointStateClosed)
}

// SetOwner sets the owner of transmitted packets.
func (e *Endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.owner = owner
}

// +checklocksread:e.mu
func (e *Endpoint) calculateTTL(route *stack.Route) uint8 {
	remoteAddress := route.RemoteAddress()
	if header.IsV4MulticastAddress(remoteAddress) || header.IsV6MulticastAddress(remoteAddress) {
		return e.multicastTTL
	}

	switch netProto := route.NetProto(); netProto {
	case header.IPv4ProtocolNumber:
		if e.ipv4TTL == 0 {
			return route.DefaultTTL()
		}
		return e.ipv4TTL
	case header.IPv6ProtocolNumber:
		if e.ipv6HopLimit == -1 {
			return route.DefaultTTL()
		}
		return uint8(e.ipv6HopLimit)
	default:
		panic(fmt.Sprintf("invalid protocol number = %d", netProto))
	}
}

// WriteContext holds the context for a write.
type WriteContext struct {
	e     *Endpoint
	route *stack.Route
	ttl   uint8
	tos   uint8
}

func (c *WriteContext) MTU() uint32 {
	return c.route.MTU()
}

// Release releases held resources.
func (c *WriteContext) Release() {
	c.route.Release()
	*c = WriteContext{}
}

// WritePacketInfo is the properties of a packet that may be written.
type WritePacketInfo struct {
	NetProto                    tcpip.NetworkProtocolNumber
	LocalAddress, RemoteAddress tcpip.Address
	MaxHeaderLength             uint16
	RequiresTXTransportChecksum bool
}

// PacketInfo returns the properties of a packet that will be written.
func (c *WriteContext) PacketInfo() WritePacketInfo {
	return WritePacketInfo{
		NetProto:                    c.route.NetProto(),
		LocalAddress:                c.route.LocalAddress(),
		RemoteAddress:               c.route.RemoteAddress(),
		MaxHeaderLength:             c.route.MaxHeaderLength(),
		RequiresTXTransportChecksum: c.route.RequiresTXTransportChecksum(),
	}
}

// TryNewPacketBuffer returns a new packet buffer iff the endpoint's send buffer
// is not full.
//
// If this method returns nil, the caller should wait for the endpoint to become
// writable.
func (c *WriteContext) TryNewPacketBuffer(reserveHdrBytes int, data buffer.Buffer) *stack.PacketBuffer {
	e := c.e

	e.sendBufferSizeInUseMu.Lock()
	defer e.sendBufferSizeInUseMu.Unlock()

	if !e.hasSendSpaceRLocked() {
		return nil
	}

	// Note that we allow oversubscription - if there is any space at all in the
	// send buffer, we accept the full packet which may be larger than the space
	// available. This is because if the endpoint reports that it is writable,
	// a write operation should succeed.
	//
	// This matches Linux behaviour:
	// https://github.com/torvalds/linux/blob/38d741cb70b/include/net/sock.h#L2519
	// https://github.com/torvalds/linux/blob/38d741cb70b/net/core/sock.c#L2588
	pktSize := int64(reserveHdrBytes) + int64(data.Size())
	e.sendBufferSizeInUse += pktSize

	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: reserveHdrBytes,
		Payload:            data,
		OnRelease: func() {
			e.sendBufferSizeInUseMu.Lock()
			if got := e.sendBufferSizeInUse; got < pktSize {
				e.sendBufferSizeInUseMu.Unlock()
				panic(fmt.Sprintf("e.sendBufferSizeInUse=(%d) < pktSize(=%d)", got, pktSize))
			}
			e.sendBufferSizeInUse -= pktSize
			signal := e.hasSendSpaceRLocked()
			e.sendBufferSizeInUseMu.Unlock()

			// Let waiters know if we now have space in the send buffer.
			if signal {
				e.waiterQueue.Notify(waiter.WritableEvents)
			}
		},
	})
}

// WritePacket attempts to write the packet.
func (c *WriteContext) WritePacket(pkt *stack.PacketBuffer, headerIncluded bool) tcpip.Error {
	c.e.mu.RLock()
	pkt.Owner = c.e.owner
	c.e.mu.RUnlock()

	if headerIncluded {
		return c.route.WriteHeaderIncludedPacket(pkt)
	}

	err := c.route.WritePacket(stack.NetworkHeaderParams{
		Protocol: c.e.transProto,
		TTL:      c.ttl,
		TOS:      c.tos,
	}, pkt)

	if _, ok := err.(*tcpip.ErrNoBufferSpace); ok {
		var recvErr bool
		switch netProto := c.route.NetProto(); netProto {
		case header.IPv4ProtocolNumber:
			recvErr = c.e.ops.GetIPv4RecvError()
		case header.IPv6ProtocolNumber:
			recvErr = c.e.ops.GetIPv6RecvError()
		default:
			panic(fmt.Sprintf("unhandled network protocol number = %d", netProto))
		}

		// Linux only returns ENOBUFS to the caller if IP{,V6}_RECVERR is set.
		//
		// https://github.com/torvalds/linux/blob/3e71713c9e75c/net/ipv4/udp.c#L969
		// https://github.com/torvalds/linux/blob/3e71713c9e75c/net/ipv6/udp.c#L1260
		if !recvErr {
			err = nil
		}
	}

	return err
}

// MaybeSignalWritable signals waiters with writable events if the send buffer
// has space.
func (e *Endpoint) MaybeSignalWritable() {
	e.sendBufferSizeInUseMu.RLock()
	signal := e.hasSendSpaceRLocked()
	e.sendBufferSizeInUseMu.RUnlock()

	if signal {
		e.waiterQueue.Notify(waiter.WritableEvents)
	}
}

// HasSendSpace returns whether or not the send buffer has space.
func (e *Endpoint) HasSendSpace() bool {
	e.sendBufferSizeInUseMu.RLock()
	defer e.sendBufferSizeInUseMu.RUnlock()
	return e.hasSendSpaceRLocked()
}

// +checklocksread:e.sendBufferSizeInUseMu
func (e *Endpoint) hasSendSpaceRLocked() bool {
	return e.ops.GetSendBufferSize() > e.sendBufferSizeInUse
}

// AcquireContextForWrite acquires a WriteContext.
func (e *Endpoint) AcquireContextForWrite(opts tcpip.WriteOptions) (WriteContext, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// MSG_MORE is unimplemented. This also means that MSG_EOR is a no-op.
	if opts.More {
		return WriteContext{}, &tcpip.ErrInvalidOptionValue{}
	}

	if e.State() == transport.DatagramEndpointStateClosed {
		return WriteContext{}, &tcpip.ErrInvalidEndpointState{}
	}

	if e.writeShutdown {
		return WriteContext{}, &tcpip.ErrClosedForSend{}
	}

	ipv6PktInfoValid := e.effectiveNetProto == header.IPv6ProtocolNumber && opts.ControlMessages.HasIPv6PacketInfo

	route := e.connectedRoute
	to := opts.To
	info := e.Info()
	switch {
	case to == nil:
		// If the user doesn't specify a destination, they should have
		// connected to another address.
		if e.State() != transport.DatagramEndpointStateConnected {
			return WriteContext{}, &tcpip.ErrDestinationRequired{}
		}

		if !ipv6PktInfoValid {
			route.Acquire()
			break
		}

		// We are connected and the caller did not specify the destination but
		// we have an IPv6 packet info structure which may change our local
		// interface/address used to send the packet so we need to construct
		// a new route instead of using the connected route.
		//
		// Construct a destination matching the remote the endpoint is connected
		// to.
		to = &tcpip.FullAddress{
			// RegisterNICID is set when the endpoint is connected. It is usually
			// only set for link-local addresses or multicast addresses if the
			// multicast interface was specified (see e.multicastNICID,
			// e.connectRouteRLocked and e.ConnectAndThen).
			NIC:  info.RegisterNICID,
			Addr: info.ID.RemoteAddress,
		}
		fallthrough
	default:
		// Reject destination address if it goes through a different
		// NIC than the endpoint was bound to.
		nicID := to.NIC
		if nicID == 0 {
			nicID = tcpip.NICID(e.ops.GetBindToDevice())
		}

		var localAddr tcpip.Address
		if ipv6PktInfoValid {
			// Uphold strong-host semantics since (as of writing) the stack follows
			// the strong host model.

			pktInfoNICID := opts.ControlMessages.IPv6PacketInfo.NIC
			pktInfoAddr := opts.ControlMessages.IPv6PacketInfo.Addr

			if pktInfoNICID != 0 {
				// If we are bound to an interface or specified the destination
				// interface (usually when using link-local addresses), make sure the
				// interface matches the specified local interface.
				if nicID != 0 && nicID != pktInfoNICID {
					return WriteContext{}, &tcpip.ErrHostUnreachable{}
				}

				// If a local address is not specified, then we need to make sure the
				// bound address belongs to the specified local interface.
				if pktInfoAddr.BitLen() == 0 {
					// If the bound interface is different from the specified local
					// interface, the bound address obviously does not belong to the
					// specified local interface.
					//
					// The bound interface is usually only set for link-local addresses.
					if info.BindNICID != 0 && info.BindNICID != pktInfoNICID {
						return WriteContext{}, &tcpip.ErrHostUnreachable{}
					}
					if info.ID.LocalAddress.BitLen() != 0 && e.stack.CheckLocalAddress(pktInfoNICID, header.IPv6ProtocolNumber, info.ID.LocalAddress) == 0 {
						return WriteContext{}, &tcpip.ErrBadLocalAddress{}
					}
				}

				nicID = pktInfoNICID
			}

			if pktInfoAddr.BitLen() != 0 {
				// The local address must belong to the stack. If an outgoing interface
				// is specified as a result of binding the endpoint to a device, or
				// specifying the outgoing interface in the destination address/pkt info
				// structure, the address must belong to that interface.
				if e.stack.CheckLocalAddress(nicID, header.IPv6ProtocolNumber, pktInfoAddr) == 0 {
					return WriteContext{}, &tcpip.ErrBadLocalAddress{}
				}

				localAddr = pktInfoAddr
			}
		} else {
			if info.BindNICID != 0 {
				if nicID != 0 && nicID != info.BindNICID {
					return WriteContext{}, &tcpip.ErrHostUnreachable{}
				}

				nicID = info.BindNICID
			}
			if nicID == 0 {
				nicID = info.RegisterNICID
			}
		}

		dst, netProto, err := e.checkV4Mapped(*to)
		if err != nil {
			return WriteContext{}, err
		}

		route, _, err = e.connectRouteRLocked(nicID, localAddr, dst, netProto)
		if err != nil {
			return WriteContext{}, err
		}
	}

	if !e.ops.GetBroadcast() && route.IsOutboundBroadcast() {
		route.Release()
		return WriteContext{}, &tcpip.ErrBroadcastDisabled{}
	}

	var tos uint8
	var ttl uint8
	switch netProto := route.NetProto(); netProto {
	case header.IPv4ProtocolNumber:
		tos = e.ipv4TOS
		if opts.ControlMessages.HasTTL {
			ttl = opts.ControlMessages.TTL
		} else {
			ttl = e.calculateTTL(route)
		}
	case header.IPv6ProtocolNumber:
		tos = e.ipv6TClass
		if opts.ControlMessages.HasHopLimit {
			ttl = opts.ControlMessages.HopLimit
		} else {
			ttl = e.calculateTTL(route)
		}
	default:
		panic(fmt.Sprintf("invalid protocol number = %d", netProto))
	}

	return WriteContext{
		e:     e,
		route: route,
		ttl:   ttl,
		tos:   tos,
	}, nil
}

// Disconnect disconnects the endpoint from its peer.
func (e *Endpoint) Disconnect() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.State() != transport.DatagramEndpointStateConnected {
		return
	}

	info := e.Info()
	// Exclude ephemerally bound endpoints.
	if e.wasBound {
		info.ID = stack.TransportEndpointID{
			LocalAddress: info.BindAddr,
		}
		e.setEndpointState(transport.DatagramEndpointStateBound)
	} else {
		info.ID = stack.TransportEndpointID{}
		e.setEndpointState(transport.DatagramEndpointStateInitial)
	}
	e.setInfo(info)

	e.connectedRoute.Release()
	e.connectedRoute = nil
}

// connectRouteRLocked establishes a route to the specified interface or the
// configured multicast interface if no interface is specified and the
// specified address is a multicast address.
//
// +checklocksread:e.mu
func (e *Endpoint) connectRouteRLocked(nicID tcpip.NICID, localAddr tcpip.Address, addr tcpip.FullAddress, netProto tcpip.NetworkProtocolNumber) (*stack.Route, tcpip.NICID, tcpip.Error) {
	if localAddr.BitLen() == 0 {
		localAddr = e.Info().ID.LocalAddress
		if e.isBroadcastOrMulticast(nicID, netProto, localAddr) {
			// A packet can only originate from a unicast address (i.e., an interface).
			localAddr = tcpip.Address{}
		}

		if header.IsV4MulticastAddress(addr.Addr) || header.IsV6MulticastAddress(addr.Addr) {
			if nicID == 0 {
				nicID = e.multicastNICID
			}
			if localAddr == (tcpip.Address{}) && nicID == 0 {
				localAddr = e.multicastAddr
			}
		}
	}

	// Find a route to the desired destination.
	r, err := e.stack.FindRoute(nicID, localAddr, addr.Addr, netProto, e.ops.GetMulticastLoop())
	if err != nil {
		return nil, 0, err
	}
	return r, nicID, nil
}

// Connect connects the endpoint to the address.
func (e *Endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	return e.ConnectAndThen(addr, func(_ tcpip.NetworkProtocolNumber, _, _ stack.TransportEndpointID) tcpip.Error {
		return nil
	})
}

// ConnectAndThen connects the endpoint to the address and then calls the
// provided function.
//
// If the function returns an error, the endpoint's state does not change. The
// function will be called with the network protocol used to connect to the peer
// and the source and destination addresses that will be used to send traffic to
// the peer.
func (e *Endpoint) ConnectAndThen(addr tcpip.FullAddress, f func(netProto tcpip.NetworkProtocolNumber, previousID, nextID stack.TransportEndpointID) tcpip.Error) tcpip.Error {
	addr.Port = 0

	e.mu.Lock()
	defer e.mu.Unlock()

	info := e.Info()
	nicID := addr.NIC
	switch e.State() {
	case transport.DatagramEndpointStateInitial:
	case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
		if info.BindNICID == 0 {
			break
		}

		if nicID != 0 && nicID != info.BindNICID {
			return &tcpip.ErrInvalidEndpointState{}
		}

		nicID = info.BindNICID
	default:
		return &tcpip.ErrInvalidEndpointState{}
	}

	addr, netProto, err := e.checkV4Mapped(addr)
	if err != nil {
		return err
	}

	r, nicID, err := e.connectRouteRLocked(nicID, tcpip.Address{}, addr, netProto)
	if err != nil {
		return err
	}

	id := stack.TransportEndpointID{
		LocalAddress:  info.ID.LocalAddress,
		RemoteAddress: r.RemoteAddress(),
	}
	if e.State() == transport.DatagramEndpointStateInitial {
		id.LocalAddress = r.LocalAddress()
	}

	if err := f(r.NetProto(), info.ID, id); err != nil {
		r.Release()
		return err
	}

	if e.connectedRoute != nil {
		// If the endpoint was previously connected then release any previous route.
		e.connectedRoute.Release()
	}
	e.connectedRoute = r
	info.ID = id
	info.RegisterNICID = nicID
	e.setInfo(info)
	e.effectiveNetProto = netProto
	e.setEndpointState(transport.DatagramEndpointStateConnected)
	return nil
}

// Shutdown shutsdown the endpoint.
func (e *Endpoint) Shutdown() tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch state := e.State(); state {
	case transport.DatagramEndpointStateInitial, transport.DatagramEndpointStateClosed:
		return &tcpip.ErrNotConnected{}
	case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
		e.writeShutdown = true
		return nil
	default:
		panic(fmt.Sprintf("unhandled state = %s", state))
	}
}

// checkV4MappedRLocked determines the effective network protocol and converts
// addr to its canonical form.
func (e *Endpoint) checkV4Mapped(addr tcpip.FullAddress) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, tcpip.Error) {
	info := e.Info()
	unwrapped, netProto, err := info.AddrNetProtoLocked(addr, e.ops.GetV6Only())
	if err != nil {
		return tcpip.FullAddress{}, 0, err
	}
	return unwrapped, netProto, nil
}

func (e *Endpoint) isBroadcastOrMulticast(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	return addr == header.IPv4Broadcast || header.IsV4MulticastAddress(addr) || header.IsV6MulticastAddress(addr) || e.stack.IsSubnetBroadcast(nicID, netProto, addr)
}

// Bind binds the endpoint to the address.
func (e *Endpoint) Bind(addr tcpip.FullAddress) tcpip.Error {
	return e.BindAndThen(addr, func(tcpip.NetworkProtocolNumber, tcpip.Address) tcpip.Error {
		return nil
	})
}

// BindAndThen binds the endpoint to the address and then calls the provided
// function.
//
// If the function returns an error, the endpoint's state does not change. The
// function will be called with the bound network protocol and address.
func (e *Endpoint) BindAndThen(addr tcpip.FullAddress, f func(tcpip.NetworkProtocolNumber, tcpip.Address) tcpip.Error) tcpip.Error {
	addr.Port = 0

	e.mu.Lock()
	defer e.mu.Unlock()

	// Don't allow binding once endpoint is not in the initial state
	// anymore.
	if e.State() != transport.DatagramEndpointStateInitial {
		return &tcpip.ErrInvalidEndpointState{}
	}

	addr, netProto, err := e.checkV4Mapped(addr)
	if err != nil {
		return err
	}

	nicID := addr.NIC
	if addr.Addr.BitLen() != 0 && !e.isBroadcastOrMulticast(addr.NIC, netProto, addr.Addr) {
		nicID = e.stack.CheckLocalAddress(nicID, netProto, addr.Addr)
		if nicID == 0 {
			return &tcpip.ErrBadLocalAddress{}
		}
	}

	if err := f(netProto, addr.Addr); err != nil {
		return err
	}

	e.wasBound = true

	info := e.Info()
	info.ID = stack.TransportEndpointID{
		LocalAddress: addr.Addr,
	}
	info.BindNICID = addr.NIC
	info.RegisterNICID = nicID
	info.BindAddr = addr.Addr
	e.setInfo(info)
	e.effectiveNetProto = netProto
	e.setEndpointState(transport.DatagramEndpointStateBound)
	return nil
}

// WasBound returns true iff the endpoint was ever bound.
func (e *Endpoint) WasBound() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.wasBound
}

// GetLocalAddress returns the address that the endpoint is bound to.
func (e *Endpoint) GetLocalAddress() tcpip.FullAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()

	info := e.Info()
	addr := info.BindAddr
	if e.State() == transport.DatagramEndpointStateConnected {
		addr = e.connectedRoute.LocalAddress()
	}

	return tcpip.FullAddress{
		NIC:  info.RegisterNICID,
		Addr: addr,
	}
}

// GetRemoteAddress returns the address that the endpoint is connected to.
func (e *Endpoint) GetRemoteAddress() (tcpip.FullAddress, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.State() != transport.DatagramEndpointStateConnected {
		return tcpip.FullAddress{}, false
	}

	return tcpip.FullAddress{
		Addr: e.connectedRoute.RemoteAddress(),
		NIC:  e.Info().RegisterNICID,
	}, true
}

// SetSockOptInt sets the socket option.
func (e *Endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	switch opt {
	case tcpip.MTUDiscoverOption:
		// Return not supported if the value is not disabling path
		// MTU discovery.
		if v != tcpip.PMTUDiscoveryDont {
			return &tcpip.ErrNotSupported{}
		}

	case tcpip.MulticastTTLOption:
		e.mu.Lock()
		e.multicastTTL = uint8(v)
		e.mu.Unlock()

	case tcpip.IPv4TTLOption:
		e.mu.Lock()
		e.ipv4TTL = uint8(v)
		e.mu.Unlock()

	case tcpip.IPv6HopLimitOption:
		e.mu.Lock()
		e.ipv6HopLimit = int16(v)
		e.mu.Unlock()

	case tcpip.IPv4TOSOption:
		e.mu.Lock()
		e.ipv4TOS = uint8(v)
		e.mu.Unlock()

	case tcpip.IPv6TrafficClassOption:
		e.mu.Lock()
		e.ipv6TClass = uint8(v)
		e.mu.Unlock()
	}

	return nil
}

// GetSockOptInt returns the socket option.
func (e *Endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
	case tcpip.MTUDiscoverOption:
		// The only supported setting is path MTU discovery disabled.
		return tcpip.PMTUDiscoveryDont, nil

	case tcpip.MulticastTTLOption:
		e.mu.Lock()
		v := int(e.multicastTTL)
		e.mu.Unlock()
		return v, nil

	case tcpip.IPv4TTLOption:
		e.mu.Lock()
		v := int(e.ipv4TTL)
		e.mu.Unlock()
		return v, nil

	case tcpip.IPv6HopLimitOption:
		e.mu.Lock()
		v := int(e.ipv6HopLimit)
		e.mu.Unlock()
		return v, nil

	case tcpip.IPv4TOSOption:
		e.mu.RLock()
		v := int(e.ipv4TOS)
		e.mu.RUnlock()
		return v, nil

	case tcpip.IPv6TrafficClassOption:
		e.mu.RLock()
		v := int(e.ipv6TClass)
		e.mu.RUnlock()
		return v, nil

	default:
		return -1, &tcpip.ErrUnknownProtocolOption{}
	}
}

// SetSockOpt sets the socket option.
func (e *Endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	switch v := opt.(type) {
	case *tcpip.MulticastInterfaceOption:
		e.mu.Lock()
		defer e.mu.Unlock()

		fa := tcpip.FullAddress{Addr: v.InterfaceAddr}
		fa, netProto, err := e.checkV4Mapped(fa)
		if err != nil {
			return err
		}
		nic := v.NIC
		addr := fa.Addr

		if nic == 0 && addr == (tcpip.Address{}) {
			e.multicastAddr = tcpip.Address{}
			e.multicastNICID = 0
			break
		}

		if nic != 0 {
			if !e.stack.CheckNIC(nic) {
				return &tcpip.ErrBadLocalAddress{}
			}
		} else {
			nic = e.stack.CheckLocalAddress(0, netProto, addr)
			if nic == 0 {
				return &tcpip.ErrBadLocalAddress{}
			}
		}

		if info := e.Info(); info.BindNICID != 0 && info.BindNICID != nic {
			return &tcpip.ErrInvalidEndpointState{}
		}

		e.multicastNICID = nic
		e.multicastAddr = addr

	case *tcpip.AddMembershipOption:
		if !(header.IsV4MulticastAddress(v.MulticastAddr) && e.netProto == header.IPv4ProtocolNumber) && !(header.IsV6MulticastAddress(v.MulticastAddr) && e.netProto == header.IPv6ProtocolNumber) {
			return &tcpip.ErrInvalidOptionValue{}
		}

		nicID := v.NIC

		if v.InterfaceAddr.Unspecified() {
			if nicID == 0 {
				if r, err := e.stack.FindRoute(0, tcpip.Address{}, v.MulticastAddr, e.netProto, false /* multicastLoop */); err == nil {
					nicID = r.NICID()
					r.Release()
				}
			}
		} else {
			nicID = e.stack.CheckLocalAddress(nicID, e.netProto, v.InterfaceAddr)
		}
		if nicID == 0 {
			return &tcpip.ErrUnknownDevice{}
		}

		memToInsert := multicastMembership{nicID: nicID, multicastAddr: v.MulticastAddr}

		e.mu.Lock()
		defer e.mu.Unlock()

		if _, ok := e.multicastMemberships[memToInsert]; ok {
			return &tcpip.ErrPortInUse{}
		}

		if err := e.stack.JoinGroup(e.netProto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		e.multicastMemberships[memToInsert] = struct{}{}

	case *tcpip.RemoveMembershipOption:
		if !(header.IsV4MulticastAddress(v.MulticastAddr) && e.netProto == header.IPv4ProtocolNumber) && !(header.IsV6MulticastAddress(v.MulticastAddr) && e.netProto == header.IPv6ProtocolNumber) {
			return &tcpip.ErrInvalidOptionValue{}
		}

		nicID := v.NIC
		if v.InterfaceAddr.Unspecified() {
			if nicID == 0 {
				if r, err := e.stack.FindRoute(0, tcpip.Address{}, v.MulticastAddr, e.netProto, false /* multicastLoop */); err == nil {
					nicID = r.NICID()
					r.Release()
				}
			}
		} else {
			nicID = e.stack.CheckLocalAddress(nicID, e.netProto, v.InterfaceAddr)
		}
		if nicID == 0 {
			return &tcpip.ErrUnknownDevice{}
		}

		memToRemove := multicastMembership{nicID: nicID, multicastAddr: v.MulticastAddr}

		e.mu.Lock()
		defer e.mu.Unlock()

		if _, ok := e.multicastMemberships[memToRemove]; !ok {
			return &tcpip.ErrBadLocalAddress{}
		}

		if err := e.stack.LeaveGroup(e.netProto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		delete(e.multicastMemberships, memToRemove)

	case *tcpip.SocketDetachFilterOption:
		return nil
	}
	return nil
}

// GetSockOpt returns the socket option.
func (e *Endpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	switch o := opt.(type) {
	case *tcpip.MulticastInterfaceOption:
		e.mu.Lock()
		*o = tcpip.MulticastInterfaceOption{
			NIC:           e.multicastNICID,
			InterfaceAddr: e.multicastAddr,
		}
		e.mu.Unlock()

	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
	return nil
}

// Info returns a copy of the endpoint info.
func (e *Endpoint) Info() stack.TransportEndpointInfo {
	e.infoMu.RLock()
	defer e.infoMu.RUnlock()
	return e.info
}

// setInfo sets the endpoint's info.
//
// e.mu must be held to synchronize changes to info with the rest of the
// endpoint.
//
// +checklocks:e.mu
func (e *Endpoint) setInfo(info stack.TransportEndpointInfo) {
	e.infoMu.Lock()
	defer e.infoMu.Unlock()
	e.info = info
}
