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

package udp

import (
	"math"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// +stateify savable
type udpPacket struct {
	udpPacketEntry
	senderAddress tcpip.FullAddress
	data          buffer.VectorisedView `state:".(buffer.VectorisedView)"`
	timestamp     int64
	// views is used as buffer for data when its length is large
	// enough to store a VectorisedView.
	views [8]buffer.View `state:"nosave"`
}

type endpointState int

const (
	stateInitial endpointState = iota
	stateBound
	stateConnected
	stateClosed
)

// endpoint represents a UDP endpoint. This struct serves as the interface
// between users of the endpoint and the protocol implementation; it is legal to
// have concurrent goroutines make calls into the endpoint, they are properly
// synchronized.
//
// It implements tcpip.Endpoint.
//
// +stateify savable
type endpoint struct {
	// The following fields are initialized at creation time and do not
	// change throughout the lifetime of the endpoint.
	stack       *stack.Stack `state:"manual"`
	netProto    tcpip.NetworkProtocolNumber
	waiterQueue *waiter.Queue

	// The following fields are used to manage the receive queue, and are
	// protected by rcvMu.
	rcvMu         sync.Mutex `state:"nosave"`
	rcvReady      bool
	rcvList       udpPacketList
	rcvBufSizeMax int `state:".(int)"`
	rcvBufSize    int
	rcvClosed     bool

	// The following fields are protected by the mu mutex.
	mu             sync.RWMutex `state:"nosave"`
	sndBufSize     int
	id             stack.TransportEndpointID
	state          endpointState
	bindNICID      tcpip.NICID
	regNICID       tcpip.NICID
	route          stack.Route `state:"manual"`
	dstPort        uint16
	v6only         bool
	multicastTTL   uint8
	multicastAddr  tcpip.Address
	multicastNICID tcpip.NICID
	multicastLoop  bool
	reusePort      bool
	broadcast      bool

	// shutdownFlags represent the current shutdown state of the endpoint.
	shutdownFlags tcpip.ShutdownFlags

	// multicastMemberships that need to be remvoed when the endpoint is
	// closed. Protected by the mu mutex.
	multicastMemberships []multicastMembership

	// effectiveNetProtos contains the network protocols actually in use. In
	// most cases it will only contain "netProto", but in cases like IPv6
	// endpoints with v6only set to false, this could include multiple
	// protocols (e.g., IPv6 and IPv4) or a single different protocol (e.g.,
	// IPv4 when IPv6 endpoint is bound or connected to an IPv4 mapped
	// address).
	effectiveNetProtos []tcpip.NetworkProtocolNumber
}

// +stateify savable
type multicastMembership struct {
	nicID         tcpip.NICID
	multicastAddr tcpip.Address
}

func newEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	return &endpoint{
		stack:       stack,
		netProto:    netProto,
		waiterQueue: waiterQueue,
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
		multicastTTL:  1,
		multicastLoop: true,
		rcvBufSizeMax: 32 * 1024,
		sndBufSize:    32 * 1024,
	}
}

// Close puts the endpoint in a closed state and frees all resources
// associated with it.
func (e *endpoint) Close() {
	e.mu.Lock()
	e.shutdownFlags = tcpip.ShutdownRead | tcpip.ShutdownWrite

	switch e.state {
	case stateBound, stateConnected:
		e.stack.UnregisterTransportEndpoint(e.regNICID, e.effectiveNetProtos, ProtocolNumber, e.id, e)
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.id.LocalAddress, e.id.LocalPort)
	}

	for _, mem := range e.multicastMemberships {
		e.stack.LeaveGroup(e.netProto, mem.nicID, mem.multicastAddr)
	}
	e.multicastMemberships = nil

	// Close the receive list and drain it.
	e.rcvMu.Lock()
	e.rcvClosed = true
	e.rcvBufSize = 0
	for !e.rcvList.Empty() {
		p := e.rcvList.Front()
		e.rcvList.Remove(p)
	}
	e.rcvMu.Unlock()

	e.route.Release()

	// Update the state.
	e.state = stateClosed

	e.mu.Unlock()

	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.EventIn | waiter.EventOut)
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (e *endpoint) ModerateRecvBuf(copied int) {}

// Read reads data from the endpoint. This method does not block if
// there is no data pending.
func (e *endpoint) Read(addr *tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, *tcpip.Error) {
	e.rcvMu.Lock()

	if e.rcvList.Empty() {
		err := tcpip.ErrWouldBlock
		if e.rcvClosed {
			err = tcpip.ErrClosedForReceive
		}
		e.rcvMu.Unlock()
		return buffer.View{}, tcpip.ControlMessages{}, err
	}

	p := e.rcvList.Front()
	e.rcvList.Remove(p)
	e.rcvBufSize -= p.data.Size()

	e.rcvMu.Unlock()

	if addr != nil {
		*addr = p.senderAddress
	}

	return p.data.ToView(), tcpip.ControlMessages{HasTimestamp: true, Timestamp: p.timestamp}, nil
}

// prepareForWrite prepares the endpoint for sending data. In particular, it
// binds it if it's still in the initial state. To do so, it must first
// reacquire the mutex in exclusive mode.
//
// Returns true for retry if preparation should be retried.
func (e *endpoint) prepareForWrite(to *tcpip.FullAddress) (retry bool, err *tcpip.Error) {
	switch e.state {
	case stateInitial:
	case stateConnected:
		return false, nil

	case stateBound:
		if to == nil {
			return false, tcpip.ErrDestinationRequired
		}
		return false, nil
	default:
		return false, tcpip.ErrInvalidEndpointState
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

// connectRoute establishes a route to the specified interface or the
// configured multicast interface if no interface is specified and the
// specified address is a multicast address.
func (e *endpoint) connectRoute(nicid tcpip.NICID, addr tcpip.FullAddress) (stack.Route, tcpip.NICID, tcpip.NetworkProtocolNumber, *tcpip.Error) {
	netProto, err := e.checkV4Mapped(&addr, false)
	if err != nil {
		return stack.Route{}, 0, 0, err
	}

	localAddr := e.id.LocalAddress
	if header.IsV4MulticastAddress(addr.Addr) || header.IsV6MulticastAddress(addr.Addr) {
		if nicid == 0 {
			nicid = e.multicastNICID
		}
		if localAddr == "" {
			localAddr = e.multicastAddr
		}
	}

	// Find a route to the desired destination.
	r, err := e.stack.FindRoute(nicid, localAddr, addr.Addr, netProto, e.multicastLoop)
	if err != nil {
		return stack.Route{}, 0, 0, err
	}
	return r, nicid, netProto, nil
}

// Write writes data to the endpoint's peer. This method does not block
// if the data cannot be written.
func (e *endpoint) Write(p tcpip.Payload, opts tcpip.WriteOptions) (uintptr, <-chan struct{}, *tcpip.Error) {
	// MSG_MORE is unimplemented. (This also means that MSG_EOR is a no-op.)
	if opts.More {
		return 0, nil, tcpip.ErrInvalidOptionValue
	}

	if p.Size() > math.MaxUint16 {
		// Payload can't possibly fit in a packet.
		return 0, nil, tcpip.ErrMessageTooLong
	}

	to := opts.To

	e.mu.RLock()
	defer e.mu.RUnlock()

	// If we've shutdown with SHUT_WR we are in an invalid state for sending.
	if e.shutdownFlags&tcpip.ShutdownWrite != 0 {
		return 0, nil, tcpip.ErrClosedForSend
	}

	// Prepare for write.
	for {
		retry, err := e.prepareForWrite(to)
		if err != nil {
			return 0, nil, err
		}

		if !retry {
			break
		}
	}

	var route *stack.Route
	var dstPort uint16
	if to == nil {
		route = &e.route
		dstPort = e.dstPort

		if route.IsResolutionRequired() {
			// Promote lock to exclusive if using a shared route, given that it may need to
			// change in Route.Resolve() call below.
			e.mu.RUnlock()
			defer e.mu.RLock()

			e.mu.Lock()
			defer e.mu.Unlock()

			// Recheck state after lock was re-acquired.
			if e.state != stateConnected {
				return 0, nil, tcpip.ErrInvalidEndpointState
			}
		}
	} else {
		// Reject destination address if it goes through a different
		// NIC than the endpoint was bound to.
		nicid := to.NIC
		if e.bindNICID != 0 {
			if nicid != 0 && nicid != e.bindNICID {
				return 0, nil, tcpip.ErrNoRoute
			}

			nicid = e.bindNICID
		}

		if to.Addr == header.IPv4Broadcast && !e.broadcast {
			return 0, nil, tcpip.ErrBroadcastDisabled
		}

		r, _, _, err := e.connectRoute(nicid, *to)
		if err != nil {
			return 0, nil, err
		}
		defer r.Release()

		route = &r
		dstPort = to.Port
	}

	if route.IsResolutionRequired() {
		if ch, err := route.Resolve(nil); err != nil {
			if err == tcpip.ErrWouldBlock {
				return 0, ch, tcpip.ErrNoLinkAddress
			}
			return 0, nil, err
		}
	}

	v, err := p.Get(p.Size())
	if err != nil {
		return 0, nil, err
	}

	ttl := route.DefaultTTL()
	if header.IsV4MulticastAddress(route.RemoteAddress) || header.IsV6MulticastAddress(route.RemoteAddress) {
		ttl = e.multicastTTL
	}

	if err := sendUDP(route, buffer.View(v).ToVectorisedView(), e.id.LocalPort, dstPort, ttl); err != nil {
		return 0, nil, err
	}
	return uintptr(len(v)), nil, nil
}

// Peek only returns data from a single datagram, so do nothing here.
func (e *endpoint) Peek([][]byte) (uintptr, tcpip.ControlMessages, *tcpip.Error) {
	return 0, tcpip.ControlMessages{}, nil
}

// SetSockOpt sets a socket option. Currently not supported.
func (e *endpoint) SetSockOpt(opt interface{}) *tcpip.Error {
	switch v := opt.(type) {
	case tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.netProto != header.IPv6ProtocolNumber {
			return tcpip.ErrInvalidEndpointState
		}

		e.mu.Lock()
		defer e.mu.Unlock()

		// We only allow this to be set when we're in the initial state.
		if e.state != stateInitial {
			return tcpip.ErrInvalidEndpointState
		}

		e.v6only = v != 0

	case tcpip.MulticastTTLOption:
		e.mu.Lock()
		e.multicastTTL = uint8(v)
		e.mu.Unlock()

	case tcpip.MulticastInterfaceOption:
		e.mu.Lock()
		defer e.mu.Unlock()

		fa := tcpip.FullAddress{Addr: v.InterfaceAddr}
		netProto, err := e.checkV4Mapped(&fa, false)
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
				return tcpip.ErrBadLocalAddress
			}
		} else {
			nic = e.stack.CheckLocalAddress(0, netProto, addr)
			if nic == 0 {
				return tcpip.ErrBadLocalAddress
			}
		}

		if e.bindNICID != 0 && e.bindNICID != nic {
			return tcpip.ErrInvalidEndpointState
		}

		e.multicastNICID = nic
		e.multicastAddr = addr

	case tcpip.AddMembershipOption:
		if !header.IsV4MulticastAddress(v.MulticastAddr) && !header.IsV6MulticastAddress(v.MulticastAddr) {
			return tcpip.ErrInvalidOptionValue
		}

		nicID := v.NIC
		if v.InterfaceAddr == header.IPv4Any {
			if nicID == 0 {
				r, err := e.stack.FindRoute(0, "", v.MulticastAddr, header.IPv4ProtocolNumber, false /* multicastLoop */)
				if err == nil {
					nicID = r.NICID()
					r.Release()
				}
			}
		} else {
			nicID = e.stack.CheckLocalAddress(nicID, e.netProto, v.InterfaceAddr)
		}
		if nicID == 0 {
			return tcpip.ErrUnknownDevice
		}

		memToInsert := multicastMembership{nicID: nicID, multicastAddr: v.MulticastAddr}

		e.mu.Lock()
		defer e.mu.Unlock()

		for _, mem := range e.multicastMemberships {
			if mem == memToInsert {
				return tcpip.ErrPortInUse
			}
		}

		if err := e.stack.JoinGroup(e.netProto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		e.multicastMemberships = append(e.multicastMemberships, memToInsert)

	case tcpip.RemoveMembershipOption:
		if !header.IsV4MulticastAddress(v.MulticastAddr) && !header.IsV6MulticastAddress(v.MulticastAddr) {
			return tcpip.ErrInvalidOptionValue
		}

		nicID := v.NIC
		if v.InterfaceAddr == header.IPv4Any {
			if nicID == 0 {
				r, err := e.stack.FindRoute(0, "", v.MulticastAddr, header.IPv4ProtocolNumber, false /* multicastLoop */)
				if err == nil {
					nicID = r.NICID()
					r.Release()
				}
			}
		} else {
			nicID = e.stack.CheckLocalAddress(nicID, e.netProto, v.InterfaceAddr)
		}
		if nicID == 0 {
			return tcpip.ErrUnknownDevice
		}

		memToRemove := multicastMembership{nicID: nicID, multicastAddr: v.MulticastAddr}
		memToRemoveIndex := -1

		e.mu.Lock()
		defer e.mu.Unlock()

		for i, mem := range e.multicastMemberships {
			if mem == memToRemove {
				memToRemoveIndex = i
				break
			}
		}
		if memToRemoveIndex == -1 {
			return tcpip.ErrBadLocalAddress
		}

		if err := e.stack.LeaveGroup(e.netProto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		e.multicastMemberships[memToRemoveIndex] = e.multicastMemberships[len(e.multicastMemberships)-1]
		e.multicastMemberships = e.multicastMemberships[:len(e.multicastMemberships)-1]

	case tcpip.MulticastLoopOption:
		e.mu.Lock()
		e.multicastLoop = bool(v)
		e.mu.Unlock()

	case tcpip.ReusePortOption:
		e.mu.Lock()
		e.reusePort = v != 0
		e.mu.Unlock()

	case tcpip.BroadcastOption:
		e.mu.Lock()
		e.broadcast = v != 0
		e.mu.Unlock()

		return nil
	}
	return nil
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *endpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	switch o := opt.(type) {
	case tcpip.ErrorOption:
		return nil

	case *tcpip.SendBufferSizeOption:
		e.mu.Lock()
		*o = tcpip.SendBufferSizeOption(e.sndBufSize)
		e.mu.Unlock()
		return nil

	case *tcpip.ReceiveBufferSizeOption:
		e.rcvMu.Lock()
		*o = tcpip.ReceiveBufferSizeOption(e.rcvBufSizeMax)
		e.rcvMu.Unlock()
		return nil

	case *tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.netProto != header.IPv6ProtocolNumber {
			return tcpip.ErrUnknownProtocolOption
		}

		e.mu.Lock()
		v := e.v6only
		e.mu.Unlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.ReceiveQueueSizeOption:
		e.rcvMu.Lock()
		if e.rcvList.Empty() {
			*o = 0
		} else {
			p := e.rcvList.Front()
			*o = tcpip.ReceiveQueueSizeOption(p.data.Size())
		}
		e.rcvMu.Unlock()
		return nil

	case *tcpip.MulticastTTLOption:
		e.mu.Lock()
		*o = tcpip.MulticastTTLOption(e.multicastTTL)
		e.mu.Unlock()
		return nil

	case *tcpip.MulticastInterfaceOption:
		e.mu.Lock()
		*o = tcpip.MulticastInterfaceOption{
			e.multicastNICID,
			e.multicastAddr,
		}
		e.mu.Unlock()
		return nil

	case *tcpip.MulticastLoopOption:
		e.mu.RLock()
		v := e.multicastLoop
		e.mu.RUnlock()

		*o = tcpip.MulticastLoopOption(v)
		return nil

	case *tcpip.ReusePortOption:
		e.mu.RLock()
		v := e.reusePort
		e.mu.RUnlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.KeepaliveEnabledOption:
		*o = 0
		return nil

	case *tcpip.BroadcastOption:
		e.mu.RLock()
		v := e.broadcast
		e.mu.RUnlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// sendUDP sends a UDP segment via the provided network endpoint and under the
// provided identity.
func sendUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16, ttl uint8) *tcpip.Error {
	// Allocate a buffer for the UDP header.
	hdr := buffer.NewPrependable(header.UDPMinimumSize + int(r.MaxHeaderLength()))

	// Initialize the header.
	udp := header.UDP(hdr.Prepend(header.UDPMinimumSize))

	length := uint16(hdr.UsedLength() + data.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: localPort,
		DstPort: remotePort,
		Length:  length,
	})

	// Only calculate the checksum if offloading isn't supported.
	if r.Capabilities()&stack.CapabilityTXChecksumOffload == 0 {
		xsum := r.PseudoHeaderChecksum(ProtocolNumber, length)
		for _, v := range data.Views() {
			xsum = header.Checksum(v, xsum)
		}
		udp.SetChecksum(^udp.CalculateChecksum(xsum))
	}

	// Track count of packets sent.
	r.Stats().UDP.PacketsSent.Increment()

	return r.WritePacket(nil /* gso */, hdr, data, ProtocolNumber, ttl)
}

func (e *endpoint) checkV4Mapped(addr *tcpip.FullAddress, allowMismatch bool) (tcpip.NetworkProtocolNumber, *tcpip.Error) {
	netProto := e.netProto
	if header.IsV4MappedAddress(addr.Addr) {
		// Fail if using a v4 mapped address on a v6only endpoint.
		if e.v6only {
			return 0, tcpip.ErrNoRoute
		}

		netProto = header.IPv4ProtocolNumber
		addr.Addr = addr.Addr[header.IPv6AddressSize-header.IPv4AddressSize:]
		if addr.Addr == "\x00\x00\x00\x00" {
			addr.Addr = ""
		}

		// Fail if we are bound to an IPv6 address.
		if !allowMismatch && len(e.id.LocalAddress) == 16 {
			return 0, tcpip.ErrNetworkUnreachable
		}
	}

	// Fail if we're bound to an address length different from the one we're
	// checking.
	if l := len(e.id.LocalAddress); l != 0 && l != len(addr.Addr) {
		return 0, tcpip.ErrInvalidEndpointState
	}

	return netProto, nil
}

func (e *endpoint) disconnect() *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.state != stateConnected {
		return nil
	}
	id := stack.TransportEndpointID{}
	// Exclude ephemerally bound endpoints.
	if e.bindNICID != 0 || e.id.LocalAddress == "" {
		var err *tcpip.Error
		id = stack.TransportEndpointID{
			LocalPort:    e.id.LocalPort,
			LocalAddress: e.id.LocalAddress,
		}
		id, err = e.registerWithStack(e.regNICID, e.effectiveNetProtos, id)
		if err != nil {
			return err
		}
		e.state = stateBound
	} else {
		e.state = stateInitial
	}

	e.stack.UnregisterTransportEndpoint(e.regNICID, e.effectiveNetProtos, ProtocolNumber, e.id, e)
	e.id = id
	e.route.Release()
	e.route = stack.Route{}
	e.dstPort = 0

	return nil
}

// Connect connects the endpoint to its peer. Specifying a NIC is optional.
func (e *endpoint) Connect(addr tcpip.FullAddress) *tcpip.Error {
	if addr.Addr == "" {
		return e.disconnect()
	}
	if addr.Port == 0 {
		// We don't support connecting to port zero.
		return tcpip.ErrInvalidEndpointState
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	nicid := addr.NIC
	var localPort uint16
	switch e.state {
	case stateInitial:
	case stateBound, stateConnected:
		localPort = e.id.LocalPort
		if e.bindNICID == 0 {
			break
		}

		if nicid != 0 && nicid != e.bindNICID {
			return tcpip.ErrInvalidEndpointState
		}

		nicid = e.bindNICID
	default:
		return tcpip.ErrInvalidEndpointState
	}

	r, nicid, netProto, err := e.connectRoute(nicid, addr)
	if err != nil {
		return err
	}
	defer r.Release()

	id := stack.TransportEndpointID{
		LocalAddress:  e.id.LocalAddress,
		LocalPort:     localPort,
		RemotePort:    addr.Port,
		RemoteAddress: r.RemoteAddress,
	}

	if e.state == stateInitial {
		id.LocalAddress = r.LocalAddress
	}

	// Even if we're connected, this endpoint can still be used to send
	// packets on a different network protocol, so we register both even if
	// v6only is set to false and this is an ipv6 endpoint.
	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	if netProto == header.IPv6ProtocolNumber && !e.v6only {
		netProtos = []tcpip.NetworkProtocolNumber{
			header.IPv4ProtocolNumber,
			header.IPv6ProtocolNumber,
		}
	}

	id, err = e.registerWithStack(nicid, netProtos, id)
	if err != nil {
		return err
	}

	// Remove the old registration.
	if e.id.LocalPort != 0 {
		e.stack.UnregisterTransportEndpoint(e.regNICID, e.effectiveNetProtos, ProtocolNumber, e.id, e)
	}

	e.id = id
	e.route = r.Clone()
	e.dstPort = addr.Port
	e.regNICID = nicid
	e.effectiveNetProtos = netProtos

	e.state = stateConnected

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

// ConnectEndpoint is not supported.
func (*endpoint) ConnectEndpoint(tcpip.Endpoint) *tcpip.Error {
	return tcpip.ErrInvalidEndpointState
}

// Shutdown closes the read and/or write end of the endpoint connection
// to its peer.
func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// A socket in the bound state can still receive multicast messages,
	// so we need to notify waiters on shutdown.
	if e.state != stateBound && e.state != stateConnected {
		return tcpip.ErrNotConnected
	}

	e.shutdownFlags |= flags

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
func (*endpoint) Listen(int) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// Accept is not supported by UDP, it just fails.
func (*endpoint) Accept() (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	return nil, nil, tcpip.ErrNotSupported
}

func (e *endpoint) registerWithStack(nicid tcpip.NICID, netProtos []tcpip.NetworkProtocolNumber, id stack.TransportEndpointID) (stack.TransportEndpointID, *tcpip.Error) {
	if e.id.LocalPort == 0 {
		port, err := e.stack.ReservePort(netProtos, ProtocolNumber, id.LocalAddress, id.LocalPort, e.reusePort)
		if err != nil {
			return id, err
		}
		id.LocalPort = port
	}

	err := e.stack.RegisterTransportEndpoint(nicid, netProtos, ProtocolNumber, id, e, e.reusePort)
	if err != nil {
		e.stack.ReleasePort(netProtos, ProtocolNumber, id.LocalAddress, id.LocalPort)
	}
	return id, err
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress) *tcpip.Error {
	// Don't allow binding once endpoint is not in the initial state
	// anymore.
	if e.state != stateInitial {
		return tcpip.ErrInvalidEndpointState
	}

	netProto, err := e.checkV4Mapped(&addr, true)
	if err != nil {
		return err
	}

	// Expand netProtos to include v4 and v6 if the caller is binding to a
	// wildcard (empty) address, and this is an IPv6 endpoint with v6only
	// set to false.
	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	if netProto == header.IPv6ProtocolNumber && !e.v6only && addr.Addr == "" {
		netProtos = []tcpip.NetworkProtocolNumber{
			header.IPv6ProtocolNumber,
			header.IPv4ProtocolNumber,
		}
	}

	nicid := addr.NIC
	if len(addr.Addr) != 0 {
		// A local address was specified, verify that it's valid.
		nicid = e.stack.CheckLocalAddress(addr.NIC, netProto, addr.Addr)
		if nicid == 0 {
			return tcpip.ErrBadLocalAddress
		}
	}

	id := stack.TransportEndpointID{
		LocalPort:    addr.Port,
		LocalAddress: addr.Addr,
	}
	id, err = e.registerWithStack(nicid, netProtos, id)
	if err != nil {
		return err
	}

	e.id = id
	e.regNICID = nicid
	e.effectiveNetProtos = netProtos

	// Mark endpoint as bound.
	e.state = stateBound

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

// Bind binds the endpoint to a specific local address and port.
// Specifying a NIC is optional.
func (e *endpoint) Bind(addr tcpip.FullAddress) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	err := e.bindLocked(addr)
	if err != nil {
		return err
	}

	// Save the effective NICID generated by bindLocked.
	e.bindNICID = e.regNICID

	return nil
}

// GetLocalAddress returns the address to which the endpoint is bound.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return tcpip.FullAddress{
		NIC:  e.regNICID,
		Addr: e.id.LocalAddress,
		Port: e.id.LocalPort,
	}, nil
}

// GetRemoteAddress returns the address to which the endpoint is connected.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.state != stateConnected {
		return tcpip.FullAddress{}, tcpip.ErrNotConnected
	}

	return tcpip.FullAddress{
		NIC:  e.regNICID,
		Addr: e.id.RemoteAddress,
		Port: e.id.RemotePort,
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
func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, vv buffer.VectorisedView) {
	// Get the header then trim it from the view.
	hdr := header.UDP(vv.First())
	if int(hdr.Length()) > vv.Size() {
		// Malformed packet.
		e.stack.Stats().UDP.MalformedPacketsReceived.Increment()
		return
	}

	vv.TrimFront(header.UDPMinimumSize)

	e.rcvMu.Lock()
	e.stack.Stats().UDP.PacketsReceived.Increment()

	// Drop the packet if our buffer is currently full.
	if !e.rcvReady || e.rcvClosed || e.rcvBufSize >= e.rcvBufSizeMax {
		e.stack.Stats().UDP.ReceiveBufferErrors.Increment()
		e.rcvMu.Unlock()
		return
	}

	wasEmpty := e.rcvBufSize == 0

	// Push new packet into receive list and increment the buffer size.
	pkt := &udpPacket{
		senderAddress: tcpip.FullAddress{
			NIC:  r.NICID(),
			Addr: id.RemoteAddress,
			Port: hdr.SourcePort(),
		},
	}
	pkt.data = vv.Clone(pkt.views[:])
	e.rcvList.PushBack(pkt)
	e.rcvBufSize += vv.Size()

	pkt.timestamp = e.stack.NowNanoseconds()

	e.rcvMu.Unlock()

	// Notify any waiters that there's data to be read now.
	if wasEmpty {
		e.waiterQueue.Notify(waiter.EventIn)
	}
}

// HandleControlPacket implements stack.TransportEndpoint.HandleControlPacket.
func (e *endpoint) HandleControlPacket(id stack.TransportEndpointID, typ stack.ControlType, extra uint32, vv buffer.VectorisedView) {
}

// State implements socket.Socket.State.
func (e *endpoint) State() uint32 {
	// TODO(b/112063468): Translate internal state to values returned by Linux.
	return 0
}
