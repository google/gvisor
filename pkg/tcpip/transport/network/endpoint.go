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

// Package network supports network transports.
package network

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// EndpointState represents the state of a UDP endpoint.
type EndpointState tcpip.EndpointState

// Endpoint states. Note that are represented in a netstack-specific manner and
// may not be meaningful externally. Specifically, they need to be translated to
// Linux's representation for these states if presented to userspace.
const (
	_ EndpointState = iota
	StateInitial
	StateBound
	StateConnected
	StateClosed
)

// Endpoint is the raw socket implementation of tcpip.Endpoint. It is legal to
// have goroutines make concurrent calls into the endpoint.
//
// Lock order:
//   endpoint.mu
//     endpoint.rcvMu
//
// +stateify savable
type Endpoint struct {
	stack.TransportEndpointInfo

	// The following fields are initialized at creation time and are
	// immutable.
	stack *stack.Stack `state:"manual"`

	// state must be read/set using the EndpointState()/setEndpointState()
	// methods.
	state uint32

	// The following fields are protected by mu.
	mu sync.RWMutex `state:"nosave"`
	// route is the route to a remote network endpoint. It is set via
	// Connect(), and is valid only when conneted is true.
	route          *stack.Route `state:"manual"`
	ttl            uint8
	multicastTTL   uint8
	multicastAddr  tcpip.Address
	multicastNICID tcpip.NICID
	// multicastMemberships that need to be remvoed when the endpoint is
	// closed. Protected by the mu mutex.
	multicastMemberships map[multicastMembership]struct{}

	effectiveNetProto tcpip.NetworkProtocolNumber

	// sendTOS represents IPv4 TOS or IPv6 TrafficClass,
	// applied while sending packets. Defaults to 0 as on Linux.
	sendTOS uint8

	// owner is used to get uid and gid of the packet.
	owner tcpip.PacketOwner

	// ops is used to get socket level options.
	ops *tcpip.SocketOptions
}

// +stateify savable
type multicastMembership struct {
	nicID         tcpip.NICID
	multicastAddr tcpip.Address
}

// Init initializes an endpoint.
func (e *Endpoint) Init(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ops *tcpip.SocketOptions) {
	if netProto != header.IPv4ProtocolNumber && netProto != header.IPv6ProtocolNumber {
		panic("invalid protocols")
	}

	*e = Endpoint{
		stack: s,
		TransportEndpointInfo: stack.TransportEndpointInfo{
			NetProto:   netProto,
			TransProto: transProto,
		},
		state: uint32(StateInitial),
		// RFC 1075 section 5.4 recommends a TTL of 1 for membership
		// requests.
		//
		// RFC 5135 4.2.1 appears to assume that IGMP messages have a
		// TTL of 1.
		//
		// RFC 5135 Appendix A defines TTL=1: A multicast source that
		// wants its traffic to not traverse a router (e.g., leave a
		// home network) may find it useful to send traffic with IP
		// TTL=1.
		//
		// Linux defaults to TTL=1.
		multicastTTL:         1,
		multicastMemberships: make(map[multicastMembership]struct{}),
		ops:                  ops,
	}
}

// setEndpointState updates the state of the endpoint to state atomically. This
// method is unexported as the only place we should update the state is in this
// package but we allow the state to be read freely without holding e.mu.
//
// Precondition: e.mu must be held to call this method.
func (e *Endpoint) setEndpointState(state EndpointState) {
	atomic.StoreUint32(&e.state, uint32(state))
}

// EndpointState returns the current state of the endpoint.
func (e *Endpoint) EndpointState() EndpointState {
	return EndpointState(atomic.LoadUint32(&e.state))
}

// Close implements tcpip.Endpoint.Close.
func (e *Endpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.EndpointState() == StateClosed {
		return
	}

	for mem := range e.multicastMemberships {
		e.stack.LeaveGroup(e.NetProto, mem.nicID, mem.multicastAddr)
	}
	e.multicastMemberships = make(map[multicastMembership]struct{})

	if e.route != nil {
		e.route.Release()
		e.route = nil
	}

	e.setEndpointState(StateClosed)
}

// SetOwner sets the owner of packets.
func (e *Endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.owner = owner
}

type PacketFunc func(netProto tcpip.NetworkProtocolNumber, src, dst tcpip.Address, maxHeaderLength int, requiresTXChecksum bool) (*stack.PacketBuffer, tcpip.Error)

// Write implements tcpip.Endpoint.Write.
func (e *Endpoint) Write(pktf PacketFunc, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	// MSG_MORE is unimplemented. This also means that MSG_EOR is a no-op.
	if opts.More {
		return 0, &tcpip.ErrInvalidOptionValue{}
	}
	route, owner, err, ttl, tos := func() (*stack.Route, tcpip.PacketOwner, tcpip.Error, uint8, uint8) {
		e.mu.RLock()
		defer e.mu.RUnlock()

		if e.EndpointState() == StateClosed {
			return nil, nil, &tcpip.ErrInvalidEndpointState{}, 0, 0
		}

		if opts.To == nil {
			// If the user doesn't specify a destination, they should have
			// connected to another address.
			if e.EndpointState() != StateConnected {
				return nil, nil, &tcpip.ErrDestinationRequired{}, 0, 0
			}

			e.route.Acquire()

			ttl := e.ttl
			if header.IsV4MulticastAddress(e.route.RemoteAddress()) || header.IsV6MulticastAddress(e.route.RemoteAddress()) {
				ttl = e.multicastTTL
			} else if ttl == 0 {
				ttl = e.route.DefaultTTL()
			}
			return e.route, e.owner, nil, ttl, e.sendTOS
		}

		// Reject destination address if it goes through a different
		// NIC than the endpoint was bound to.
		nicID := opts.To.NIC
		if nicID == 0 {
			nicID = tcpip.NICID(e.ops.GetBindToDevice())
		}
		if e.BindNICID != 0 {
			if nicID != 0 && nicID != e.BindNICID {
				return nil, nil, &tcpip.ErrNoRoute{}, 0, 0
			}

			nicID = e.BindNICID
		}

		dst, netProto, err := e.checkV4MappedLocked(*opts.To)
		if err != nil {
			return nil, nil, err, 0, 0
		}

		route, _, err := e.connectRoute(nicID, dst, netProto)
		if err != nil {
			return nil, nil, err, 0, 0
		}

		ttl := e.ttl
		if header.IsV4MulticastAddress(route.RemoteAddress()) || header.IsV6MulticastAddress(route.RemoteAddress()) {
			ttl = e.multicastTTL
		} else if ttl == 0 {
			ttl = route.DefaultTTL()
		}
		return route, e.owner, nil, ttl, e.sendTOS
	}()
	if err != nil {
		return 0, err
	}
	defer route.Release()

	if !e.ops.GetBroadcast() && route.IsOutboundBroadcast() {
		return 0, &tcpip.ErrBroadcastDisabled{}
	}

	pkt, err := pktf(route.NetProto(), route.LocalAddress(), route.RemoteAddress(), int(route.MaxHeaderLength()), route.RequiresTXTransportChecksum())
	if err != nil {
		return 0, err
	}

	if e.ops.GetHeaderIncluded() {
		return 0, route.WriteHeaderIncludedPacket(pkt)
	}

	pkt.Owner = owner
	return 0, route.WritePacket(stack.NetworkHeaderParams{
		Protocol: e.TransProto,
		TTL:      ttl,
		TOS:      tos,
	}, pkt)
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (e *Endpoint) Disconnect() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.EndpointState() != StateConnected {
		return
	}

	// Exclude ephemerally bound endpoints.
	if e.BindNICID != 0 || e.ID.LocalAddress == "" {
		e.ID = stack.TransportEndpointID{
			LocalAddress: e.ID.LocalAddress,
		}
		e.setEndpointState(StateBound)
	} else {
		e.ID = stack.TransportEndpointID{}
		e.setEndpointState(StateInitial)
	}

	e.route.Release()
	e.route = nil
}

// connectRoute establishes a route to the specified interface or the
// configured multicast interface if no interface is specified and the
// specified address is a multicast address.
func (e *Endpoint) connectRoute(nicID tcpip.NICID, addr tcpip.FullAddress, netProto tcpip.NetworkProtocolNumber) (*stack.Route, tcpip.NICID, tcpip.Error) {
	localAddr := e.ID.LocalAddress
	if e.isBroadcastOrMulticast(nicID, netProto, localAddr) {
		// A packet can only originate from a unicast address (i.e., an interface).
		localAddr = ""
	}

	if header.IsV4MulticastAddress(addr.Addr) || header.IsV6MulticastAddress(addr.Addr) {
		if nicID == 0 {
			nicID = e.multicastNICID
		}
		if localAddr == "" && nicID == 0 {
			localAddr = e.multicastAddr
		}
	}

	// Find a route to the desired destination.
	r, err := e.stack.FindRoute(nicID, localAddr, addr.Addr, netProto, e.ops.GetMulticastLoop())
	if err != nil {
		return nil, 0, err
	}
	return r, nicID, nil
}

// Connect implements tcpip.Endpoint.Connect.
func (e *Endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	return e.ConnectWith(addr, func(netProto tcpip.NetworkProtocolNumber, src, dst tcpip.Address) tcpip.Error { return nil })
}

func (e *Endpoint) ConnectWith(addr tcpip.FullAddress, f func(netProto tcpip.NetworkProtocolNumber, src, dst tcpip.Address) tcpip.Error) tcpip.Error {
	addr.Port = 0

	e.mu.Lock()
	defer e.mu.Unlock()

	nicID := addr.NIC
	switch e.EndpointState() {
	case StateInitial:
	case StateBound, StateConnected:
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

	r, nicID, err := e.connectRoute(nicID, addr, netProto)
	if err != nil {
		return err
	}

	if err := f(r.NetProto(), r.LocalAddress(), r.RemoteAddress()); err != nil {
		return err
	}

	id := stack.TransportEndpointID{
		LocalAddress:  e.ID.LocalAddress,
		RemoteAddress: r.RemoteAddress(),
	}
	if e.EndpointState() == StateInitial {
		id.LocalAddress = r.LocalAddress()
	}

	if e.route != nil {
		// If the endpoint was previously connected then release any previous route.
		e.route.Release()
	}
	e.route = r
	e.ID = id
	e.RegisterNICID = nicID
	e.effectiveNetProto = netProto
	e.setEndpointState(StateConnected)
	return nil
}

// Shutdown implements tcpip.Endpoint.Shutdown. It's a noop for raw sockets.
func (e *Endpoint) Shutdown(tcpip.ShutdownFlags) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.EndpointState() != StateConnected {
		return &tcpip.ErrNotConnected{}
	}
	return nil
}

// checkV4MappedLocked determines the effective network protocol and converts
// addr to its canonical form.
func (e *Endpoint) checkV4MappedLocked(addr tcpip.FullAddress) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, tcpip.Error) {
	unwrapped, netProto, err := e.TransportEndpointInfo.AddrNetProtoLocked(addr, e.ops.GetV6Only())
	if err != nil {
		return tcpip.FullAddress{}, 0, err
	}
	return unwrapped, netProto, nil
}

func (e *Endpoint) isBroadcastOrMulticast(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	return addr == header.IPv4Broadcast || header.IsV4MulticastAddress(addr) || header.IsV6MulticastAddress(addr) || e.stack.IsSubnetBroadcast(nicID, netProto, addr)
}

// Bind implements tcpip.Endpoint.Bind.
func (e *Endpoint) Bind(addr tcpip.FullAddress) tcpip.Error {
	addr.Port = 0

	e.mu.Lock()
	defer e.mu.Unlock()

	// Don't allow binding once endpoint is not in the initial state
	// anymore.
	if e.EndpointState() != StateInitial {
		return &tcpip.ErrInvalidEndpointState{}
	}

	addr, netProto, err := e.checkV4MappedLocked(addr)
	if err != nil {
		return err
	}

	nicID := addr.NIC
	if len(addr.Addr) != 0 && !e.isBroadcastOrMulticast(addr.NIC, netProto, addr.Addr) {
		// A local unicast address was specified, verify that it's valid.
		nicID = e.stack.CheckLocalAddress(addr.NIC, netProto, addr.Addr)
		if nicID == 0 {
			return &tcpip.ErrBadLocalAddress{}
		}
	}

	id := stack.TransportEndpointID{
		LocalAddress: addr.Addr,
	}

	e.ID = id
	e.BindNICID = nicID
	e.RegisterNICID = nicID
	e.BindAddr = addr.Addr
	e.effectiveNetProto = netProto
	e.setEndpointState(StateBound)
	return nil
}

// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress.
func (e *Endpoint) GetLocalAddress() tcpip.FullAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()

	addr := e.BindAddr
	if e.EndpointState() == StateConnected {
		addr = e.route.LocalAddress()
	}

	return tcpip.FullAddress{
		NIC:  e.RegisterNICID,
		Addr: addr,
		// Linux returns the protocol in the port field.
		Port: uint16(e.TransProto),
	}
}

// GetRemoteAddress implements tcpip.Endpoint.GetRemoteAddress.
func (e *Endpoint) GetRemoteAddress() (tcpip.FullAddress, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.EndpointState() != StateConnected {
		return tcpip.FullAddress{}, false
	}

	return tcpip.FullAddress{Addr: e.route.RemoteAddress(), NIC: e.RegisterNICID}, true
}

// SetSockOptInt implements tcpip.Endpoint.
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

	case tcpip.TTLOption:
		e.mu.Lock()
		e.ttl = uint8(v)
		e.mu.Unlock()

	case tcpip.IPv4TOSOption:
		e.mu.Lock()
		e.sendTOS = uint8(v)
		e.mu.Unlock()

	case tcpip.IPv6TrafficClassOption:
		e.mu.Lock()
		e.sendTOS = uint8(v)
		e.mu.Unlock()
	}

	return nil
}

// GetSockOptInt implements tcpip.Endpoint.
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

	case tcpip.TTLOption:
		e.mu.Lock()
		v := int(e.ttl)
		e.mu.Unlock()
		return v, nil

	case tcpip.IPv4TOSOption:
		e.mu.RLock()
		v := int(e.sendTOS)
		e.mu.RUnlock()
		return v, nil

	case tcpip.IPv6TrafficClassOption:
		e.mu.RLock()
		v := int(e.sendTOS)
		e.mu.RUnlock()
		return v, nil

	default:
		return -1, &tcpip.ErrUnknownProtocolOption{}
	}
}

// SetSockOpt implements tcpip.Endpoint.
func (e *Endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	switch v := opt.(type) {
	case *tcpip.MulticastInterfaceOption:
		e.mu.Lock()
		defer e.mu.Unlock()

		fa := tcpip.FullAddress{Addr: v.InterfaceAddr}
		fa, netProto, err := e.checkV4MappedLocked(fa)
		if err != nil {
			return err
		}
		nic := v.NIC
		addr := fa.Addr

		if nic == 0 && addr == "" {
			e.multicastAddr = ""
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

		if e.BindNICID != 0 && e.BindNICID != nic {
			return &tcpip.ErrInvalidEndpointState{}
		}

		e.multicastNICID = nic
		e.multicastAddr = addr

	case *tcpip.AddMembershipOption:
		if !header.IsV4MulticastAddress(v.MulticastAddr) && !header.IsV6MulticastAddress(v.MulticastAddr) {
			return &tcpip.ErrInvalidOptionValue{}
		}

		nicID := v.NIC

		if v.InterfaceAddr.Unspecified() {
			if nicID == 0 {
				if r, err := e.stack.FindRoute(0, "", v.MulticastAddr, e.NetProto, false /* multicastLoop */); err == nil {
					nicID = r.NICID()
					r.Release()
				}
			}
		} else {
			nicID = e.stack.CheckLocalAddress(nicID, e.NetProto, v.InterfaceAddr)
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

		if err := e.stack.JoinGroup(e.NetProto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		e.multicastMemberships[memToInsert] = struct{}{}

	case *tcpip.RemoveMembershipOption:
		if !header.IsV4MulticastAddress(v.MulticastAddr) && !header.IsV6MulticastAddress(v.MulticastAddr) {
			return &tcpip.ErrInvalidOptionValue{}
		}

		nicID := v.NIC
		if v.InterfaceAddr.Unspecified() {
			if nicID == 0 {
				if r, err := e.stack.FindRoute(0, "", v.MulticastAddr, e.NetProto, false /* multicastLoop */); err == nil {
					nicID = r.NICID()
					r.Release()
				}
			}
		} else {
			nicID = e.stack.CheckLocalAddress(nicID, e.NetProto, v.InterfaceAddr)
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

		if err := e.stack.LeaveGroup(e.NetProto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		delete(e.multicastMemberships, memToRemove)

	case *tcpip.SocketDetachFilterOption:
		return nil
	}
	return nil
}

// GetSockOpt implements tcpip.Endpoint.
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
