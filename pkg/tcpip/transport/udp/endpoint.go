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
	"io"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// +stateify savable
type udpPacket struct {
	udpPacketEntry
	senderAddress      tcpip.FullAddress
	destinationAddress tcpip.FullAddress
	packetInfo         tcpip.IPPacketInfo
	data               buffer.VectorisedView `state:".(buffer.VectorisedView)"`
	receivedAt         time.Time             `state:".(int64)"`
	// tos stores either the receiveTOS or receiveTClass value.
	tos uint8
}

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

// String implements fmt.Stringer.String.
func (s EndpointState) String() string {
	switch s {
	case StateInitial:
		return "INITIAL"
	case StateBound:
		return "BOUND"
	case StateConnected:
		return "CONNECTING"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// endpoint represents a UDP endpoint. This struct serves as the interface
// between users of the endpoint and the protocol implementation; it is legal to
// have concurrent goroutines make calls into the endpoint, they are properly
// synchronized.
//
// It implements tcpip.Endpoint.
//
// +stateify savable
type endpoint struct {
	stack.TransportEndpointInfo
	tcpip.DefaultSocketOptionsHandler

	// The following fields are initialized at creation time and do not
	// change throughout the lifetime of the endpoint.
	stack       *stack.Stack `state:"manual"`
	waiterQueue *waiter.Queue
	uniqueID    uint64

	// The following fields are used to manage the receive queue, and are
	// protected by rcvMu.
	rcvMu      sync.Mutex `state:"nosave"`
	rcvReady   bool
	rcvList    udpPacketList
	rcvBufSize int
	rcvClosed  bool

	// The following fields are protected by the mu mutex.
	mu sync.RWMutex `state:"nosave"`
	// state must be read/set using the EndpointState()/setEndpointState()
	// methods.
	state          uint32
	route          *stack.Route `state:"manual"`
	dstPort        uint16
	ttl            uint8
	multicastTTL   uint8
	multicastAddr  tcpip.Address
	multicastNICID tcpip.NICID
	portFlags      ports.Flags

	lastErrorMu sync.Mutex `state:"nosave"`
	lastError   tcpip.Error

	// Values used to reserve a port or register a transport endpoint.
	// (which ever happens first).
	boundBindToDevice tcpip.NICID
	boundPortFlags    ports.Flags

	// sendTOS represents IPv4 TOS or IPv6 TrafficClass,
	// applied while sending packets. Defaults to 0 as on Linux.
	sendTOS uint8

	// shutdownFlags represent the current shutdown state of the endpoint.
	shutdownFlags tcpip.ShutdownFlags

	// multicastMemberships that need to be remvoed when the endpoint is
	// closed. Protected by the mu mutex.
	multicastMemberships map[multicastMembership]struct{}

	// effectiveNetProtos contains the network protocols actually in use. In
	// most cases it will only contain "netProto", but in cases like IPv6
	// endpoints with v6only set to false, this could include multiple
	// protocols (e.g., IPv6 and IPv4) or a single different protocol (e.g.,
	// IPv4 when IPv6 endpoint is bound or connected to an IPv4 mapped
	// address).
	effectiveNetProtos []tcpip.NetworkProtocolNumber

	// TODO(b/142022063): Add ability to save and restore per endpoint stats.
	stats tcpip.TransportEndpointStats `state:"nosave"`

	// owner is used to get uid and gid of the packet.
	owner tcpip.PacketOwner

	// ops is used to get socket level options.
	ops tcpip.SocketOptions

	// frozen indicates if the packets should be delivered to the endpoint
	// during restore.
	frozen bool
}

// +stateify savable
type multicastMembership struct {
	nicID         tcpip.NICID
	multicastAddr tcpip.Address
}

func newEndpoint(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	e := &endpoint{
		stack: s,
		TransportEndpointInfo: stack.TransportEndpointInfo{
			NetProto:   netProto,
			TransProto: header.UDPProtocolNumber,
		},
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
		multicastTTL:         1,
		multicastMemberships: make(map[multicastMembership]struct{}),
		state:                uint32(StateInitial),
		uniqueID:             s.UniqueID(),
	}
	e.ops.InitHandler(e, e.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	e.ops.SetMulticastLoop(true)
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

	return e
}

// setEndpointState updates the state of the endpoint to state atomically. This
// method is unexported as the only place we should update the state is in this
// package but we allow the state to be read freely without holding e.mu.
//
// Precondition: e.mu must be held to call this method.
func (e *endpoint) setEndpointState(state EndpointState) {
	atomic.StoreUint32(&e.state, uint32(state))
}

// EndpointState() returns the current state of the endpoint.
func (e *endpoint) EndpointState() EndpointState {
	return EndpointState(atomic.LoadUint32(&e.state))
}

// UniqueID implements stack.TransportEndpoint.UniqueID.
func (e *endpoint) UniqueID() uint64 {
	return e.uniqueID
}

func (e *endpoint) LastError() tcpip.Error {
	e.lastErrorMu.Lock()
	defer e.lastErrorMu.Unlock()

	err := e.lastError
	e.lastError = nil
	return err
}

// UpdateLastError implements tcpip.SocketOptionsHandler.UpdateLastError.
func (e *endpoint) UpdateLastError(err tcpip.Error) {
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()
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

	switch e.EndpointState() {
	case StateBound, StateConnected:
		e.stack.UnregisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, e.ID, e, e.boundPortFlags, e.boundBindToDevice)
		portRes := ports.Reservation{
			Networks:     e.effectiveNetProtos,
			Transport:    ProtocolNumber,
			Addr:         e.ID.LocalAddress,
			Port:         e.ID.LocalPort,
			Flags:        e.boundPortFlags,
			BindToDevice: e.boundBindToDevice,
			Dest:         tcpip.FullAddress{},
		}
		e.stack.ReleasePort(portRes)
		e.boundBindToDevice = 0
		e.boundPortFlags = ports.Flags{}
	}

	for mem := range e.multicastMemberships {
		e.stack.LeaveGroup(e.NetProto, mem.nicID, mem.multicastAddr)
	}
	e.multicastMemberships = make(map[multicastMembership]struct{})

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
	e.setEndpointState(StateClosed)

	e.mu.Unlock()

	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (*endpoint) ModerateRecvBuf(int) {}

// Read implements tcpip.Endpoint.Read.
func (e *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	if err := e.LastError(); err != nil {
		return tcpip.ReadResult{}, err
	}

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

	// Control Messages
	cm := tcpip.ControlMessages{
		HasTimestamp: true,
		Timestamp:    p.receivedAt.UnixNano(),
	}
	if e.ops.GetReceiveTOS() {
		cm.HasTOS = true
		cm.TOS = p.tos
	}
	if e.ops.GetReceiveTClass() {
		cm.HasTClass = true
		// Although TClass is an 8-bit value it's read in the CMsg as a uint32.
		cm.TClass = uint32(p.tos)
	}
	if e.ops.GetReceivePacketInfo() {
		cm.HasIPPacketInfo = true
		cm.PacketInfo = p.packetInfo
	}
	if e.ops.GetReceiveOriginalDstAddress() {
		cm.HasOriginalDstAddress = true
		cm.OriginalDstAddress = p.destinationAddress
	}

	// Read Result
	res := tcpip.ReadResult{
		Total:           p.data.Size(),
		ControlMessages: cm,
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
	switch e.EndpointState() {
	case StateInitial:
	case StateConnected:
		return false, nil

	case StateBound:
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
	if e.EndpointState() != StateInitial {
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
func (e *endpoint) connectRoute(nicID tcpip.NICID, addr tcpip.FullAddress, netProto tcpip.NetworkProtocolNumber) (*stack.Route, tcpip.NICID, tcpip.Error) {
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
	if err := e.LastError(); err != nil {
		return 0, err
	}

	// MSG_MORE is unimplemented. (This also means that MSG_EOR is a no-op.)
	if opts.More {
		return 0, &tcpip.ErrInvalidOptionValue{}
	}

	to := opts.To

	e.mu.RLock()
	lockReleased := false
	defer func() {
		if lockReleased {
			return
		}
		e.mu.RUnlock()
	}()

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
	dstPort := e.dstPort
	if to != nil {
		// Reject destination address if it goes through a different
		// NIC than the endpoint was bound to.
		nicID := to.NIC
		if nicID == 0 {
			nicID = tcpip.NICID(e.ops.GetBindToDevice())
		}
		if e.BindNICID != 0 {
			if nicID != 0 && nicID != e.BindNICID {
				return 0, &tcpip.ErrNoRoute{}
			}

			nicID = e.BindNICID
		}

		if to.Port == 0 {
			// Port 0 is an invalid port to send to.
			return 0, &tcpip.ErrInvalidEndpointState{}
		}

		dst, netProto, err := e.checkV4MappedLocked(*to)
		if err != nil {
			return 0, err
		}

		r, _, err := e.connectRoute(nicID, dst, netProto)
		if err != nil {
			return 0, err
		}
		defer r.Release()

		route = r
		dstPort = dst.Port
	}

	if !e.ops.GetBroadcast() && route.IsOutboundBroadcast() {
		return 0, &tcpip.ErrBroadcastDisabled{}
	}

	v := make([]byte, p.Len())
	if _, err := io.ReadFull(p, v); err != nil {
		return 0, &tcpip.ErrBadBuffer{}
	}
	if len(v) > header.UDPMaximumPacketSize {
		// Payload can't possibly fit in a packet.
		so := e.SocketOptions()
		if so.GetRecvError() {
			so.QueueLocalErr(
				&tcpip.ErrMessageTooLong{},
				route.NetProto(),
				header.UDPMaximumPacketSize,
				tcpip.FullAddress{
					NIC:  route.NICID(),
					Addr: route.RemoteAddress(),
					Port: dstPort,
				},
				v,
			)
		}
		return 0, &tcpip.ErrMessageTooLong{}
	}

	ttl := e.ttl
	useDefaultTTL := ttl == 0

	if header.IsV4MulticastAddress(route.RemoteAddress()) || header.IsV6MulticastAddress(route.RemoteAddress()) {
		ttl = e.multicastTTL
		// Multicast allows a 0 TTL.
		useDefaultTTL = false
	}

	localPort := e.ID.LocalPort
	sendTOS := e.sendTOS
	owner := e.owner
	noChecksum := e.SocketOptions().GetNoChecksum()
	lockReleased = true
	e.mu.RUnlock()

	// Do not hold lock when sending as loopback is synchronous and if the UDP
	// datagram ends up generating an ICMP response then it can result in a
	// deadlock where the ICMP response handling ends up acquiring this endpoint's
	// mutex using e.mu.RLock() in endpoint.HandleControlPacket which can cause a
	// deadlock if another caller is trying to acquire e.mu in exclusive mode w/
	// e.mu.Lock(). Since e.mu.Lock() prevents any new read locks to ensure the
	// lock can be eventually acquired.
	//
	// See: https://golang.org/pkg/sync/#RWMutex for details on why recursive read
	// locking is prohibited.
	if err := sendUDP(route, buffer.View(v).ToVectorisedView(), localPort, dstPort, ttl, useDefaultTTL, sendTOS, owner, noChecksum); err != nil {
		return 0, err
	}
	return int64(len(v)), nil
}

// OnReuseAddressSet implements tcpip.SocketOptionsHandler.OnReuseAddressSet.
func (e *endpoint) OnReuseAddressSet(v bool) {
	e.mu.Lock()
	e.portFlags.MostRecent = v
	e.mu.Unlock()
}

// OnReusePortSet implements tcpip.SocketOptionsHandler.OnReusePortSet.
func (e *endpoint) OnReusePortSet(v bool) {
	e.mu.Lock()
	e.portFlags.LoadBalanced = v
	e.mu.Unlock()
}

// SetSockOptInt implements tcpip.Endpoint.SetSockOptInt.
func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
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

func (e *endpoint) HasNIC(id int32) bool {
	return id == 0 || e.stack.HasNIC(tcpip.NICID(id))
}

// SetSockOpt implements tcpip.Endpoint.SetSockOpt.
func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
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

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (e *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
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

	case tcpip.MTUDiscoverOption:
		// The only supported setting is path MTU discovery disabled.
		return tcpip.PMTUDiscoveryDont, nil

	case tcpip.MulticastTTLOption:
		e.mu.Lock()
		v := int(e.multicastTTL)
		e.mu.Unlock()
		return v, nil

	case tcpip.ReceiveQueueSizeOption:
		v := 0
		e.rcvMu.Lock()
		if !e.rcvList.Empty() {
			p := e.rcvList.Front()
			v = p.data.Size()
		}
		e.rcvMu.Unlock()
		return v, nil

	case tcpip.TTLOption:
		e.mu.Lock()
		v := int(e.ttl)
		e.mu.Unlock()
		return v, nil

	default:
		return -1, &tcpip.ErrUnknownProtocolOption{}
	}
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *endpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
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

// sendUDP sends a UDP segment via the provided network endpoint and under the
// provided identity.
func sendUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16, ttl uint8, useDefaultTTL bool, tos uint8, owner tcpip.PacketOwner, noChecksum bool) tcpip.Error {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(r.MaxHeaderLength()),
		Data:               data,
	})
	pkt.Owner = owner

	// Initialize the UDP header.
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = ProtocolNumber

	length := uint16(pkt.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: localPort,
		DstPort: remotePort,
		Length:  length,
	})

	// Set the checksum field unless TX checksum offload is enabled.
	// On IPv4, UDP checksum is optional, and a zero value indicates the
	// transmitter skipped the checksum generation (RFC768).
	// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
	if r.RequiresTXTransportChecksum() &&
		(!noChecksum || r.NetProto() == header.IPv6ProtocolNumber) {
		xsum := r.PseudoHeaderChecksum(ProtocolNumber, length)
		for _, v := range data.Views() {
			xsum = header.Checksum(v, xsum)
		}
		udp.SetChecksum(^udp.CalculateChecksum(xsum))
	}

	if useDefaultTTL {
		ttl = r.DefaultTTL()
	}
	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol: ProtocolNumber,
		TTL:      ttl,
		TOS:      tos,
	}, pkt); err != nil {
		r.Stats().UDP.PacketSendErrors.Increment()
		return err
	}

	// Track count of packets sent.
	r.Stats().UDP.PacketsSent.Increment()
	return nil
}

// checkV4MappedLocked determines the effective network protocol and converts
// addr to its canonical form.
func (e *endpoint) checkV4MappedLocked(addr tcpip.FullAddress) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, tcpip.Error) {
	unwrapped, netProto, err := e.TransportEndpointInfo.AddrNetProtoLocked(addr, e.ops.GetV6Only())
	if err != nil {
		return tcpip.FullAddress{}, 0, err
	}
	return unwrapped, netProto, nil
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (e *endpoint) Disconnect() tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.EndpointState() != StateConnected {
		return nil
	}
	var (
		id  stack.TransportEndpointID
		btd tcpip.NICID
	)

	// We change this value below and we need the old value to unregister
	// the endpoint.
	boundPortFlags := e.boundPortFlags

	// Exclude ephemerally bound endpoints.
	if e.BindNICID != 0 || e.ID.LocalAddress == "" {
		var err tcpip.Error
		id = stack.TransportEndpointID{
			LocalPort:    e.ID.LocalPort,
			LocalAddress: e.ID.LocalAddress,
		}
		id, btd, err = e.registerWithStack(e.effectiveNetProtos, id)
		if err != nil {
			return err
		}
		e.setEndpointState(StateBound)
		boundPortFlags = e.boundPortFlags
	} else {
		if e.ID.LocalPort != 0 {
			// Release the ephemeral port.
			portRes := ports.Reservation{
				Networks:     e.effectiveNetProtos,
				Transport:    ProtocolNumber,
				Addr:         e.ID.LocalAddress,
				Port:         e.ID.LocalPort,
				Flags:        boundPortFlags,
				BindToDevice: e.boundBindToDevice,
				Dest:         tcpip.FullAddress{},
			}
			e.stack.ReleasePort(portRes)
			e.boundPortFlags = ports.Flags{}
		}
		e.setEndpointState(StateInitial)
	}

	e.stack.UnregisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, e.ID, e, boundPortFlags, e.boundBindToDevice)
	e.ID = id
	e.boundBindToDevice = btd
	e.route.Release()
	e.route = nil
	e.dstPort = 0

	return nil
}

// Connect connects the endpoint to its peer. Specifying a NIC is optional.
func (e *endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	nicID := addr.NIC
	var localPort uint16
	switch e.EndpointState() {
	case StateInitial:
	case StateBound, StateConnected:
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

	r, nicID, err := e.connectRoute(nicID, addr, netProto)
	if err != nil {
		return err
	}

	id := stack.TransportEndpointID{
		LocalAddress:  e.ID.LocalAddress,
		LocalPort:     localPort,
		RemotePort:    addr.Port,
		RemoteAddress: r.RemoteAddress(),
	}

	if e.EndpointState() == StateInitial {
		id.LocalAddress = r.LocalAddress()
	}

	// Even if we're connected, this endpoint can still be used to send
	// packets on a different network protocol, so we register both even if
	// v6only is set to false and this is an ipv6 endpoint.
	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	if netProto == header.IPv6ProtocolNumber && !e.ops.GetV6Only() {
		netProtos = []tcpip.NetworkProtocolNumber{
			header.IPv4ProtocolNumber,
			header.IPv6ProtocolNumber,
		}
	}

	oldPortFlags := e.boundPortFlags

	id, btd, err := e.registerWithStack(netProtos, id)
	if err != nil {
		r.Release()
		return err
	}

	// Remove the old registration.
	if e.ID.LocalPort != 0 {
		e.stack.UnregisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, e.ID, e, oldPortFlags, e.boundBindToDevice)
	}

	e.ID = id
	e.boundBindToDevice = btd
	if e.route != nil {
		// If the endpoint was already connected then make sure we release the
		// previous route.
		e.route.Release()
	}
	e.route = r
	e.dstPort = addr.Port
	e.RegisterNICID = nicID
	e.effectiveNetProtos = netProtos

	e.setEndpointState(StateConnected)

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

	// A socket in the bound state can still receive multicast messages,
	// so we need to notify waiters on shutdown.
	if state := e.EndpointState(); state != StateBound && state != StateConnected {
		return &tcpip.ErrNotConnected{}
	}

	e.shutdownFlags |= flags

	if flags&tcpip.ShutdownRead != 0 {
		e.rcvMu.Lock()
		wasClosed := e.rcvClosed
		e.rcvClosed = true
		e.rcvMu.Unlock()

		if !wasClosed {
			e.waiterQueue.Notify(waiter.ReadableEvents)
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

func (e *endpoint) registerWithStack(netProtos []tcpip.NetworkProtocolNumber, id stack.TransportEndpointID) (stack.TransportEndpointID, tcpip.NICID, tcpip.Error) {
	bindToDevice := tcpip.NICID(e.ops.GetBindToDevice())
	if e.ID.LocalPort == 0 {
		portRes := ports.Reservation{
			Networks:     netProtos,
			Transport:    ProtocolNumber,
			Addr:         id.LocalAddress,
			Port:         id.LocalPort,
			Flags:        e.portFlags,
			BindToDevice: bindToDevice,
			Dest:         tcpip.FullAddress{},
		}
		port, err := e.stack.ReservePort(e.stack.Rand(), portRes, nil /* testPort */)
		if err != nil {
			return id, bindToDevice, err
		}
		id.LocalPort = port
	}
	e.boundPortFlags = e.portFlags

	err := e.stack.RegisterTransportEndpoint(netProtos, ProtocolNumber, id, e, e.boundPortFlags, bindToDevice)
	if err != nil {
		portRes := ports.Reservation{
			Networks:     netProtos,
			Transport:    ProtocolNumber,
			Addr:         id.LocalAddress,
			Port:         id.LocalPort,
			Flags:        e.boundPortFlags,
			BindToDevice: bindToDevice,
			Dest:         tcpip.FullAddress{},
		}
		e.stack.ReleasePort(portRes)
		e.boundPortFlags = ports.Flags{}
	}
	return id, bindToDevice, err
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress) tcpip.Error {
	// Don't allow binding once endpoint is not in the initial state
	// anymore.
	if e.EndpointState() != StateInitial {
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
	if netProto == header.IPv6ProtocolNumber && !e.ops.GetV6Only() && addr.Addr == "" {
		netProtos = []tcpip.NetworkProtocolNumber{
			header.IPv6ProtocolNumber,
			header.IPv4ProtocolNumber,
		}
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
		LocalPort:    addr.Port,
		LocalAddress: addr.Addr,
	}
	id, btd, err := e.registerWithStack(netProtos, id)
	if err != nil {
		return err
	}

	e.ID = id
	e.boundBindToDevice = btd
	e.RegisterNICID = nicID
	e.effectiveNetProtos = netProtos

	// Mark endpoint as bound.
	e.setEndpointState(StateBound)

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

	// Save the effective NICID generated by bindLocked.
	e.BindNICID = e.RegisterNICID

	return nil
}

// GetLocalAddress returns the address to which the endpoint is bound.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	addr := e.ID.LocalAddress
	if e.EndpointState() == StateConnected {
		addr = e.route.LocalAddress()
	}

	return tcpip.FullAddress{
		NIC:  e.RegisterNICID,
		Addr: addr,
		Port: e.ID.LocalPort,
	}, nil
}

// GetRemoteAddress returns the address to which the endpoint is connected.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.EndpointState() != StateConnected || e.dstPort == 0 {
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
	result := waiter.WritableEvents & mask

	// Determine if the endpoint is readable if requested.
	if mask&waiter.ReadableEvents != 0 {
		e.rcvMu.Lock()
		if !e.rcvList.Empty() || e.rcvClosed {
			result |= waiter.ReadableEvents
		}
		e.rcvMu.Unlock()
	}

	e.lastErrorMu.Lock()
	hasError := e.lastError != nil
	e.lastErrorMu.Unlock()
	if hasError {
		result |= waiter.EventErr
	}
	return result
}

// verifyChecksum verifies the checksum unless RX checksum offload is enabled.
func verifyChecksum(hdr header.UDP, pkt *stack.PacketBuffer) bool {
	if pkt.RXTransportChecksumValidated {
		return true
	}

	// On IPv4, UDP checksum is optional, and a zero value means the transmitter
	// omitted the checksum generation, as per RFC 768:
	//
	//   An all zero transmitted checksum value means that the transmitter
	//   generated  no checksum  (for debugging or for higher level protocols that
	//   don't care).
	//
	// On IPv6, UDP checksum is not optional, as per RFC 2460 Section 8.1:
	//
	//   Unlike IPv4, when UDP packets are originated by an IPv6 node, the UDP
	//   checksum is not optional.
	if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber && hdr.Checksum() == 0 {
		return true
	}

	netHdr := pkt.Network()
	payloadChecksum := pkt.Data().AsRange().Checksum()
	return hdr.IsChecksumValid(netHdr.SourceAddress(), netHdr.DestinationAddress(), payloadChecksum)
}

// HandlePacket is called by the stack when new packets arrive to this transport
// endpoint.
func (e *endpoint) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	// Get the header then trim it from the view.
	hdr := header.UDP(pkt.TransportHeader().View())
	if int(hdr.Length()) > pkt.Data().Size()+header.UDPMinimumSize {
		// Malformed packet.
		e.stack.Stats().UDP.MalformedPacketsReceived.Increment()
		e.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
		return
	}

	if !verifyChecksum(hdr, pkt) {
		e.stack.Stats().UDP.ChecksumErrors.Increment()
		e.stats.ReceiveErrors.ChecksumErrors.Increment()
		return
	}

	e.stack.Stats().UDP.PacketsReceived.Increment()
	e.stats.PacketsReceived.Increment()

	e.rcvMu.Lock()
	// Drop the packet if our buffer is currently full.
	if !e.rcvReady || e.rcvClosed {
		e.rcvMu.Unlock()
		e.stack.Stats().UDP.ReceiveBufferErrors.Increment()
		e.stats.ReceiveErrors.ClosedReceiver.Increment()
		return
	}

	rcvBufSize := e.ops.GetReceiveBufferSize()
	if e.frozen || e.rcvBufSize >= int(rcvBufSize) {
		e.rcvMu.Unlock()
		e.stack.Stats().UDP.ReceiveBufferErrors.Increment()
		e.stats.ReceiveErrors.ReceiveBufferOverflow.Increment()
		return
	}

	wasEmpty := e.rcvBufSize == 0

	// Push new packet into receive list and increment the buffer size.
	packet := &udpPacket{
		senderAddress: tcpip.FullAddress{
			NIC:  pkt.NICID,
			Addr: id.RemoteAddress,
			Port: hdr.SourcePort(),
		},
		destinationAddress: tcpip.FullAddress{
			NIC:  pkt.NICID,
			Addr: id.LocalAddress,
			Port: hdr.DestinationPort(),
		},
		data: pkt.Data().ExtractVV(),
	}
	e.rcvList.PushBack(packet)
	e.rcvBufSize += packet.data.Size()

	// Save any useful information from the network header to the packet.
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		packet.tos, _ = header.IPv4(pkt.NetworkHeader().View()).TOS()
	case header.IPv6ProtocolNumber:
		packet.tos, _ = header.IPv6(pkt.NetworkHeader().View()).TOS()
	}

	// TODO(gvisor.dev/issue/3556): r.LocalAddress may be a multicast or broadcast
	// address. packetInfo.LocalAddr should hold a unicast address that can be
	// used to respond to the incoming packet.
	localAddr := pkt.Network().DestinationAddress()
	packet.packetInfo.LocalAddr = localAddr
	packet.packetInfo.DestinationAddr = localAddr
	packet.packetInfo.NIC = pkt.NICID
	packet.receivedAt = e.stack.Clock().Now()

	e.rcvMu.Unlock()

	// Notify any waiters that there's data to be read now.
	if wasEmpty {
		e.waiterQueue.Notify(waiter.ReadableEvents)
	}
}

func (e *endpoint) onICMPError(err tcpip.Error, transErr stack.TransportError, pkt *stack.PacketBuffer) {
	// Update last error first.
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()

	// Update the error queue if IP_RECVERR is enabled.
	if e.SocketOptions().GetRecvError() {
		// Linux passes the payload without the UDP header.
		var payload []byte
		udp := header.UDP(pkt.Data().AsRange().ToOwnedView())
		if len(udp) >= header.UDPMinimumSize {
			payload = udp.Payload()
		}

		e.SocketOptions().QueueErr(&tcpip.SockError{
			Err:     err,
			Cause:   transErr,
			Payload: payload,
			Dst: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: e.ID.RemoteAddress,
				Port: e.ID.RemotePort,
			},
			Offender: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: e.ID.LocalAddress,
				Port: e.ID.LocalPort,
			},
			NetProto: pkt.NetworkProtocolNumber,
		})
	}

	// Notify of the error.
	e.waiterQueue.Notify(waiter.EventErr)
}

// HandleError implements stack.TransportEndpoint.
func (e *endpoint) HandleError(transErr stack.TransportError, pkt *stack.PacketBuffer) {
	// TODO(gvisor.dev/issues/5270): Handle all transport errors.
	switch transErr.Kind() {
	case stack.DestinationPortUnreachableTransportError:
		if e.EndpointState() == StateConnected {
			e.onICMPError(&tcpip.ErrConnectionRefused{}, transErr, pkt)
		}
	}
}

// State implements tcpip.Endpoint.State.
func (e *endpoint) State() uint32 {
	return uint32(e.EndpointState())
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

// Wait implements tcpip.Endpoint.Wait.
func (*endpoint) Wait() {}

func (e *endpoint) isBroadcastOrMulticast(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	return addr == header.IPv4Broadcast || header.IsV4MulticastAddress(addr) || header.IsV6MulticastAddress(addr) || e.stack.IsSubnetBroadcast(nicID, netProto, addr)
}

// SetOwner implements tcpip.Endpoint.SetOwner.
func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.owner = owner
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
