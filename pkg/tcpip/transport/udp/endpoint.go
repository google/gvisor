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
	"fmt"

	"gvisor.dev/gvisor/pkg/sleep"
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
	senderAddress tcpip.FullAddress
	packetInfo    tcpip.IPPacketInfo
	data          buffer.VectorisedView `state:".(buffer.VectorisedView)"`
	timestamp     int64
	// tos stores either the receiveTOS or receiveTClass value.
	tos uint8
}

// EndpointState represents the state of a UDP endpoint.
type EndpointState uint32

// Endpoint states. Note that are represented in a netstack-specific manner and
// may not be meaningful externally. Specifically, they need to be translated to
// Linux's representation for these states if presented to userspace.
const (
	StateInitial EndpointState = iota
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

	// The following fields are initialized at creation time and do not
	// change throughout the lifetime of the endpoint.
	stack       *stack.Stack `state:"manual"`
	waiterQueue *waiter.Queue
	uniqueID    uint64

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
	sndBufSizeMax  int
	state          EndpointState
	route          stack.Route `state:"manual"`
	dstPort        uint16
	v6only         bool
	ttl            uint8
	multicastTTL   uint8
	multicastAddr  tcpip.Address
	multicastNICID tcpip.NICID
	multicastLoop  bool
	portFlags      ports.Flags
	bindToDevice   tcpip.NICID
	broadcast      bool
	noChecksum     bool

	lastErrorMu sync.Mutex   `state:"nosave"`
	lastError   *tcpip.Error `state:".(string)"`

	// Values used to reserve a port or register a transport endpoint.
	// (which ever happens first).
	boundBindToDevice tcpip.NICID
	boundPortFlags    ports.Flags

	// sendTOS represents IPv4 TOS or IPv6 TrafficClass,
	// applied while sending packets. Defaults to 0 as on Linux.
	sendTOS uint8

	// receiveTOS determines if the incoming IPv4 TOS header field is passed
	// as ancillary data to ControlMessages on Read.
	receiveTOS bool

	// receiveTClass determines if the incoming IPv6 TClass header field is
	// passed as ancillary data to ControlMessages on Read.
	receiveTClass bool

	// receiveIPPacketInfo determines if the packet info is returned by Read.
	receiveIPPacketInfo bool

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

	// linger is used for SO_LINGER socket option.
	linger tcpip.LingerOption
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
		multicastLoop:        true,
		rcvBufSizeMax:        32 * 1024,
		sndBufSizeMax:        32 * 1024,
		multicastMemberships: make(map[multicastMembership]struct{}),
		state:                StateInitial,
		uniqueID:             s.UniqueID(),
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

	return e
}

// UniqueID implements stack.TransportEndpoint.UniqueID.
func (e *endpoint) UniqueID() uint64 {
	return e.uniqueID
}

func (e *endpoint) LastError() *tcpip.Error {
	e.lastErrorMu.Lock()
	defer e.lastErrorMu.Unlock()

	err := e.lastError
	e.lastError = nil
	return err
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
	case StateBound, StateConnected:
		e.stack.UnregisterTransportEndpoint(e.RegisterNICID, e.effectiveNetProtos, ProtocolNumber, e.ID, e, e.boundPortFlags, e.boundBindToDevice)
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.ID.LocalAddress, e.ID.LocalPort, e.boundPortFlags, e.boundBindToDevice, tcpip.FullAddress{})
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

	e.route.Release()

	// Update the state.
	e.state = StateClosed

	e.mu.Unlock()

	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.EventIn | waiter.EventOut)
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (e *endpoint) ModerateRecvBuf(copied int) {}

// Read reads data from the endpoint. This method does not block if
// there is no data pending.
func (e *endpoint) Read(addr *tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, *tcpip.Error) {
	if err := e.LastError(); err != nil {
		return buffer.View{}, tcpip.ControlMessages{}, err
	}

	e.rcvMu.Lock()

	if e.rcvList.Empty() {
		err := tcpip.ErrWouldBlock
		if e.rcvClosed {
			e.stats.ReadErrors.ReadClosed.Increment()
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

	cm := tcpip.ControlMessages{
		HasTimestamp: true,
		Timestamp:    p.timestamp,
	}
	e.mu.RLock()
	receiveTOS := e.receiveTOS
	receiveTClass := e.receiveTClass
	receiveIPPacketInfo := e.receiveIPPacketInfo
	e.mu.RUnlock()
	if receiveTOS {
		cm.HasTOS = true
		cm.TOS = p.tos
	}
	if receiveTClass {
		cm.HasTClass = true
		// Although TClass is an 8-bit value it's read in the CMsg as a uint32.
		cm.TClass = uint32(p.tos)
	}
	if receiveIPPacketInfo {
		cm.HasIPPacketInfo = true
		cm.PacketInfo = p.packetInfo
	}
	return p.data.ToView(), cm, nil
}

// prepareForWrite prepares the endpoint for sending data. In particular, it
// binds it if it's still in the initial state. To do so, it must first
// reacquire the mutex in exclusive mode.
//
// Returns true for retry if preparation should be retried.
func (e *endpoint) prepareForWrite(to *tcpip.FullAddress) (retry bool, err *tcpip.Error) {
	switch e.state {
	case StateInitial:
	case StateConnected:
		return false, nil

	case StateBound:
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
	if e.state != StateInitial {
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
func (e *endpoint) connectRoute(nicID tcpip.NICID, addr tcpip.FullAddress, netProto tcpip.NetworkProtocolNumber) (stack.Route, tcpip.NICID, *tcpip.Error) {
	localAddr := e.ID.LocalAddress
	if isBroadcastOrMulticast(localAddr) {
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
	r, err := e.stack.FindRoute(nicID, localAddr, addr.Addr, netProto, e.multicastLoop)
	if err != nil {
		return stack.Route{}, 0, err
	}
	return r, nicID, nil
}

// Write writes data to the endpoint's peer. This method does not block
// if the data cannot be written.
func (e *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, <-chan struct{}, *tcpip.Error) {
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
	if err := e.LastError(); err != nil {
		return 0, nil, err
	}

	// MSG_MORE is unimplemented. (This also means that MSG_EOR is a no-op.)
	if opts.More {
		return 0, nil, tcpip.ErrInvalidOptionValue
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
	var resolve func(waker *sleep.Waker) (ch <-chan struct{}, err *tcpip.Error)
	var dstPort uint16
	if to == nil {
		route = &e.route
		dstPort = e.dstPort
		resolve = func(waker *sleep.Waker) (ch <-chan struct{}, err *tcpip.Error) {
			// Promote lock to exclusive if using a shared route, given that it may
			// need to change in Route.Resolve() call below.
			e.mu.RUnlock()
			e.mu.Lock()

			// Recheck state after lock was re-acquired.
			if e.state != StateConnected {
				err = tcpip.ErrInvalidEndpointState
			}
			if err == nil && route.IsResolutionRequired() {
				ch, err = route.Resolve(waker)
			}

			e.mu.Unlock()
			e.mu.RLock()

			// Recheck state after lock was re-acquired.
			if e.state != StateConnected {
				err = tcpip.ErrInvalidEndpointState
			}
			return
		}
	} else {
		// Reject destination address if it goes through a different
		// NIC than the endpoint was bound to.
		nicID := to.NIC
		if e.BindNICID != 0 {
			if nicID != 0 && nicID != e.BindNICID {
				return 0, nil, tcpip.ErrNoRoute
			}

			nicID = e.BindNICID
		}

		dst, netProto, err := e.checkV4MappedLocked(*to)
		if err != nil {
			return 0, nil, err
		}

		r, _, err := e.connectRoute(nicID, dst, netProto)
		if err != nil {
			return 0, nil, err
		}
		defer r.Release()

		route = &r
		dstPort = dst.Port
		resolve = route.Resolve
	}

	if !e.broadcast && route.IsOutboundBroadcast() {
		return 0, nil, tcpip.ErrBroadcastDisabled
	}

	if route.IsResolutionRequired() {
		if ch, err := resolve(nil); err != nil {
			if err == tcpip.ErrWouldBlock {
				return 0, ch, tcpip.ErrNoLinkAddress
			}
			return 0, nil, err
		}
	}

	v, err := p.FullPayload()
	if err != nil {
		return 0, nil, err
	}
	if len(v) > header.UDPMaximumPacketSize {
		// Payload can't possibly fit in a packet.
		return 0, nil, tcpip.ErrMessageTooLong
	}

	ttl := e.ttl
	useDefaultTTL := ttl == 0

	if header.IsV4MulticastAddress(route.RemoteAddress) || header.IsV6MulticastAddress(route.RemoteAddress) {
		ttl = e.multicastTTL
		// Multicast allows a 0 TTL.
		useDefaultTTL = false
	}

	if err := sendUDP(route, buffer.View(v).ToVectorisedView(), e.ID.LocalPort, dstPort, ttl, useDefaultTTL, e.sendTOS, e.owner, e.noChecksum); err != nil {
		return 0, nil, err
	}
	return int64(len(v)), nil, nil
}

// Peek only returns data from a single datagram, so do nothing here.
func (e *endpoint) Peek([][]byte) (int64, tcpip.ControlMessages, *tcpip.Error) {
	return 0, tcpip.ControlMessages{}, nil
}

// SetSockOptBool implements tcpip.Endpoint.SetSockOptBool.
func (e *endpoint) SetSockOptBool(opt tcpip.SockOptBool, v bool) *tcpip.Error {
	switch opt {
	case tcpip.BroadcastOption:
		e.mu.Lock()
		e.broadcast = v
		e.mu.Unlock()

	case tcpip.MulticastLoopOption:
		e.mu.Lock()
		e.multicastLoop = v
		e.mu.Unlock()

	case tcpip.NoChecksumOption:
		e.mu.Lock()
		e.noChecksum = v
		e.mu.Unlock()

	case tcpip.ReceiveTOSOption:
		e.mu.Lock()
		e.receiveTOS = v
		e.mu.Unlock()

	case tcpip.ReceiveTClassOption:
		// We only support this option on v6 endpoints.
		if e.NetProto != header.IPv6ProtocolNumber {
			return tcpip.ErrNotSupported
		}

		e.mu.Lock()
		e.receiveTClass = v
		e.mu.Unlock()

	case tcpip.ReceiveIPPacketInfoOption:
		e.mu.Lock()
		e.receiveIPPacketInfo = v
		e.mu.Unlock()

	case tcpip.ReuseAddressOption:
		e.mu.Lock()
		e.portFlags.MostRecent = v
		e.mu.Unlock()

	case tcpip.ReusePortOption:
		e.mu.Lock()
		e.portFlags.LoadBalanced = v
		e.mu.Unlock()

	case tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.NetProto != header.IPv6ProtocolNumber {
			return tcpip.ErrInvalidEndpointState
		}

		e.mu.Lock()
		defer e.mu.Unlock()

		// We only allow this to be set when we're in the initial state.
		if e.state != StateInitial {
			return tcpip.ErrInvalidEndpointState
		}

		e.v6only = v
	}

	return nil
}

// SetSockOptInt implements tcpip.Endpoint.SetSockOptInt.
func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) *tcpip.Error {
	switch opt {
	case tcpip.MTUDiscoverOption:
		// Return not supported if the value is not disabling path
		// MTU discovery.
		if v != tcpip.PMTUDiscoveryDont {
			return tcpip.ErrNotSupported
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

	case tcpip.ReceiveBufferSizeOption:
		// Make sure the receive buffer size is within the min and max
		// allowed.
		var rs stack.ReceiveBufferSizeOption
		if err := e.stack.Option(&rs); err != nil {
			panic(fmt.Sprintf("e.stack.Option(%#v) = %s", rs, err))
		}

		if v < rs.Min {
			v = rs.Min
		}
		if v > rs.Max {
			v = rs.Max
		}

		e.mu.Lock()
		e.rcvBufSizeMax = v
		e.mu.Unlock()
		return nil
	case tcpip.SendBufferSizeOption:
		// Make sure the send buffer size is within the min and max
		// allowed.
		var ss stack.SendBufferSizeOption
		if err := e.stack.Option(&ss); err != nil {
			panic(fmt.Sprintf("e.stack.Option(%#v) = %s", ss, err))
		}

		if v < ss.Min {
			v = ss.Min
		}
		if v > ss.Max {
			v = ss.Max
		}

		e.mu.Lock()
		e.sndBufSizeMax = v
		e.mu.Unlock()
		return nil
	}

	return nil
}

// SetSockOpt implements tcpip.Endpoint.SetSockOpt.
func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) *tcpip.Error {
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
				return tcpip.ErrBadLocalAddress
			}
		} else {
			nic = e.stack.CheckLocalAddress(0, netProto, addr)
			if nic == 0 {
				return tcpip.ErrBadLocalAddress
			}
		}

		if e.BindNICID != 0 && e.BindNICID != nic {
			return tcpip.ErrInvalidEndpointState
		}

		e.multicastNICID = nic
		e.multicastAddr = addr

	case *tcpip.AddMembershipOption:
		if !header.IsV4MulticastAddress(v.MulticastAddr) && !header.IsV6MulticastAddress(v.MulticastAddr) {
			return tcpip.ErrInvalidOptionValue
		}

		nicID := v.NIC

		// The interface address is considered not-set if it is empty or contains
		// all-zeros. The former represent the zero-value in golang, the latter the
		// same in a setsockopt(IP_ADD_MEMBERSHIP, &ip_mreqn) syscall.
		allZeros := header.IPv4Any
		if len(v.InterfaceAddr) == 0 || v.InterfaceAddr == allZeros {
			if nicID == 0 {
				r, err := e.stack.FindRoute(0, "", v.MulticastAddr, header.IPv4ProtocolNumber, false /* multicastLoop */)
				if err == nil {
					nicID = r.NICID()
					r.Release()
				}
			}
		} else {
			nicID = e.stack.CheckLocalAddress(nicID, e.NetProto, v.InterfaceAddr)
		}
		if nicID == 0 {
			return tcpip.ErrUnknownDevice
		}

		memToInsert := multicastMembership{nicID: nicID, multicastAddr: v.MulticastAddr}

		e.mu.Lock()
		defer e.mu.Unlock()

		if _, ok := e.multicastMemberships[memToInsert]; ok {
			return tcpip.ErrPortInUse
		}

		if err := e.stack.JoinGroup(e.NetProto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		e.multicastMemberships[memToInsert] = struct{}{}

	case *tcpip.RemoveMembershipOption:
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
			nicID = e.stack.CheckLocalAddress(nicID, e.NetProto, v.InterfaceAddr)
		}
		if nicID == 0 {
			return tcpip.ErrUnknownDevice
		}

		memToRemove := multicastMembership{nicID: nicID, multicastAddr: v.MulticastAddr}

		e.mu.Lock()
		defer e.mu.Unlock()

		if _, ok := e.multicastMemberships[memToRemove]; !ok {
			return tcpip.ErrBadLocalAddress
		}

		if err := e.stack.LeaveGroup(e.NetProto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		delete(e.multicastMemberships, memToRemove)

	case *tcpip.BindToDeviceOption:
		id := tcpip.NICID(*v)
		if id != 0 && !e.stack.HasNIC(id) {
			return tcpip.ErrUnknownDevice
		}
		e.mu.Lock()
		e.bindToDevice = id
		e.mu.Unlock()

	case *tcpip.SocketDetachFilterOption:
		return nil

	case *tcpip.LingerOption:
		e.mu.Lock()
		e.linger = *v
		e.mu.Unlock()
	}
	return nil
}

// GetSockOptBool implements tcpip.Endpoint.GetSockOptBool.
func (e *endpoint) GetSockOptBool(opt tcpip.SockOptBool) (bool, *tcpip.Error) {
	switch opt {
	case tcpip.BroadcastOption:
		e.mu.RLock()
		v := e.broadcast
		e.mu.RUnlock()
		return v, nil

	case tcpip.KeepaliveEnabledOption:
		return false, nil

	case tcpip.MulticastLoopOption:
		e.mu.RLock()
		v := e.multicastLoop
		e.mu.RUnlock()
		return v, nil

	case tcpip.NoChecksumOption:
		e.mu.RLock()
		v := e.noChecksum
		e.mu.RUnlock()
		return v, nil

	case tcpip.ReceiveTOSOption:
		e.mu.RLock()
		v := e.receiveTOS
		e.mu.RUnlock()
		return v, nil

	case tcpip.ReceiveTClassOption:
		// We only support this option on v6 endpoints.
		if e.NetProto != header.IPv6ProtocolNumber {
			return false, tcpip.ErrNotSupported
		}

		e.mu.RLock()
		v := e.receiveTClass
		e.mu.RUnlock()
		return v, nil

	case tcpip.ReceiveIPPacketInfoOption:
		e.mu.RLock()
		v := e.receiveIPPacketInfo
		e.mu.RUnlock()
		return v, nil

	case tcpip.ReuseAddressOption:
		e.mu.RLock()
		v := e.portFlags.MostRecent
		e.mu.RUnlock()

		return v, nil

	case tcpip.ReusePortOption:
		e.mu.RLock()
		v := e.portFlags.LoadBalanced
		e.mu.RUnlock()

		return v, nil

	case tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.NetProto != header.IPv6ProtocolNumber {
			return false, tcpip.ErrUnknownProtocolOption
		}

		e.mu.RLock()
		v := e.v6only
		e.mu.RUnlock()

		return v, nil

	case tcpip.AcceptConnOption:
		return false, nil

	default:
		return false, tcpip.ErrUnknownProtocolOption
	}
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (e *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, *tcpip.Error) {
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

	case tcpip.TTLOption:
		e.mu.Lock()
		v := int(e.ttl)
		e.mu.Unlock()
		return v, nil

	default:
		return -1, tcpip.ErrUnknownProtocolOption
	}
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *endpoint) GetSockOpt(opt tcpip.GettableSocketOption) *tcpip.Error {
	switch o := opt.(type) {
	case *tcpip.MulticastInterfaceOption:
		e.mu.Lock()
		*o = tcpip.MulticastInterfaceOption{
			e.multicastNICID,
			e.multicastAddr,
		}
		e.mu.Unlock()

	case *tcpip.BindToDeviceOption:
		e.mu.RLock()
		*o = tcpip.BindToDeviceOption(e.bindToDevice)
		e.mu.RUnlock()

	case *tcpip.LingerOption:
		e.mu.RLock()
		*o = e.linger
		e.mu.RUnlock()

	default:
		return tcpip.ErrUnknownProtocolOption
	}
	return nil
}

// sendUDP sends a UDP segment via the provided network endpoint and under the
// provided identity.
func sendUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16, ttl uint8, useDefaultTTL bool, tos uint8, owner tcpip.PacketOwner, noChecksum bool) *tcpip.Error {
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
	if !r.HasTXTransportChecksumOffloadCapability() &&
		(!noChecksum || r.NetProto == header.IPv6ProtocolNumber) {
		xsum := r.PseudoHeaderChecksum(ProtocolNumber, length)
		for _, v := range data.Views() {
			xsum = header.Checksum(v, xsum)
		}
		udp.SetChecksum(^udp.CalculateChecksum(xsum))
	}

	if useDefaultTTL {
		ttl = r.DefaultTTL()
	}
	if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{
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
func (e *endpoint) checkV4MappedLocked(addr tcpip.FullAddress) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, *tcpip.Error) {
	unwrapped, netProto, err := e.TransportEndpointInfo.AddrNetProtoLocked(addr, e.v6only)
	if err != nil {
		return tcpip.FullAddress{}, 0, err
	}
	return unwrapped, netProto, nil
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (e *endpoint) Disconnect() *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.state != StateConnected {
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
		var err *tcpip.Error
		id = stack.TransportEndpointID{
			LocalPort:    e.ID.LocalPort,
			LocalAddress: e.ID.LocalAddress,
		}
		id, btd, err = e.registerWithStack(e.RegisterNICID, e.effectiveNetProtos, id)
		if err != nil {
			return err
		}
		e.state = StateBound
		boundPortFlags = e.boundPortFlags
	} else {
		if e.ID.LocalPort != 0 {
			// Release the ephemeral port.
			e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.ID.LocalAddress, e.ID.LocalPort, boundPortFlags, e.boundBindToDevice, tcpip.FullAddress{})
			e.boundPortFlags = ports.Flags{}
		}
		e.state = StateInitial
	}

	e.stack.UnregisterTransportEndpoint(e.RegisterNICID, e.effectiveNetProtos, ProtocolNumber, e.ID, e, boundPortFlags, e.boundBindToDevice)
	e.ID = id
	e.boundBindToDevice = btd
	e.route.Release()
	e.route = stack.Route{}
	e.dstPort = 0

	return nil
}

// Connect connects the endpoint to its peer. Specifying a NIC is optional.
func (e *endpoint) Connect(addr tcpip.FullAddress) *tcpip.Error {
	if addr.Port == 0 {
		// We don't support connecting to port zero.
		return tcpip.ErrInvalidEndpointState
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	nicID := addr.NIC
	var localPort uint16
	switch e.state {
	case StateInitial:
	case StateBound, StateConnected:
		localPort = e.ID.LocalPort
		if e.BindNICID == 0 {
			break
		}

		if nicID != 0 && nicID != e.BindNICID {
			return tcpip.ErrInvalidEndpointState
		}

		nicID = e.BindNICID
	default:
		return tcpip.ErrInvalidEndpointState
	}

	addr, netProto, err := e.checkV4MappedLocked(addr)
	if err != nil {
		return err
	}

	r, nicID, err := e.connectRoute(nicID, addr, netProto)
	if err != nil {
		return err
	}
	defer r.Release()

	id := stack.TransportEndpointID{
		LocalAddress:  e.ID.LocalAddress,
		LocalPort:     localPort,
		RemotePort:    addr.Port,
		RemoteAddress: r.RemoteAddress,
	}

	if e.state == StateInitial {
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

	oldPortFlags := e.boundPortFlags

	id, btd, err := e.registerWithStack(nicID, netProtos, id)
	if err != nil {
		return err
	}

	// Remove the old registration.
	if e.ID.LocalPort != 0 {
		e.stack.UnregisterTransportEndpoint(e.RegisterNICID, e.effectiveNetProtos, ProtocolNumber, e.ID, e, oldPortFlags, e.boundBindToDevice)
	}

	e.ID = id
	e.boundBindToDevice = btd
	e.route = r.Clone()
	e.dstPort = addr.Port
	e.RegisterNICID = nicID
	e.effectiveNetProtos = netProtos

	e.state = StateConnected

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
	if e.state != StateBound && e.state != StateConnected {
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
func (*endpoint) Accept(*tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	return nil, nil, tcpip.ErrNotSupported
}

func (e *endpoint) registerWithStack(nicID tcpip.NICID, netProtos []tcpip.NetworkProtocolNumber, id stack.TransportEndpointID) (stack.TransportEndpointID, tcpip.NICID, *tcpip.Error) {
	if e.ID.LocalPort == 0 {
		port, err := e.stack.ReservePort(netProtos, ProtocolNumber, id.LocalAddress, id.LocalPort, e.portFlags, e.bindToDevice, tcpip.FullAddress{}, nil /* testPort */)
		if err != nil {
			return id, e.bindToDevice, err
		}
		id.LocalPort = port
	}
	e.boundPortFlags = e.portFlags

	err := e.stack.RegisterTransportEndpoint(nicID, netProtos, ProtocolNumber, id, e, e.boundPortFlags, e.bindToDevice)
	if err != nil {
		e.stack.ReleasePort(netProtos, ProtocolNumber, id.LocalAddress, id.LocalPort, e.boundPortFlags, e.bindToDevice, tcpip.FullAddress{})
		e.boundPortFlags = ports.Flags{}
	}
	return id, e.bindToDevice, err
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress) *tcpip.Error {
	// Don't allow binding once endpoint is not in the initial state
	// anymore.
	if e.state != StateInitial {
		return tcpip.ErrInvalidEndpointState
	}

	addr, netProto, err := e.checkV4MappedLocked(addr)
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

	nicID := addr.NIC
	if len(addr.Addr) != 0 && !isBroadcastOrMulticast(addr.Addr) {
		// A local unicast address was specified, verify that it's valid.
		nicID = e.stack.CheckLocalAddress(addr.NIC, netProto, addr.Addr)
		if nicID == 0 {
			return tcpip.ErrBadLocalAddress
		}
	}

	id := stack.TransportEndpointID{
		LocalPort:    addr.Port,
		LocalAddress: addr.Addr,
	}
	id, btd, err := e.registerWithStack(nicID, netProtos, id)
	if err != nil {
		return err
	}

	e.ID = id
	e.boundBindToDevice = btd
	e.RegisterNICID = nicID
	e.effectiveNetProtos = netProtos

	// Mark endpoint as bound.
	e.state = StateBound

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
	e.BindNICID = e.RegisterNICID

	return nil
}

// GetLocalAddress returns the address to which the endpoint is bound.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	addr := e.ID.LocalAddress
	if e.state == StateConnected {
		addr = e.route.LocalAddress
	}

	return tcpip.FullAddress{
		NIC:  e.RegisterNICID,
		Addr: addr,
		Port: e.ID.LocalPort,
	}, nil
}

// GetRemoteAddress returns the address to which the endpoint is connected.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.state != StateConnected {
		return tcpip.FullAddress{}, tcpip.ErrNotConnected
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

	e.lastErrorMu.Lock()
	hasError := e.lastError != nil
	e.lastErrorMu.Unlock()
	if hasError {
		result |= waiter.EventErr
	}
	return result
}

// verifyChecksum verifies the checksum unless RX checksum offload is enabled.
// On IPv4, UDP checksum is optional, and a zero value means the transmitter
// omitted the checksum generation (RFC768).
// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
func verifyChecksum(hdr header.UDP, pkt *stack.PacketBuffer) bool {
	if !pkt.RXTransportChecksumValidated &&
		(hdr.Checksum() != 0 || pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber) {
		netHdr := pkt.Network()
		xsum := header.PseudoHeaderChecksum(ProtocolNumber, netHdr.DestinationAddress(), netHdr.SourceAddress(), hdr.Length())
		for _, v := range pkt.Data.Views() {
			xsum = header.Checksum(v, xsum)
		}
		return hdr.CalculateChecksum(xsum) == 0xffff
	}
	return true
}

// HandlePacket is called by the stack when new packets arrive to this transport
// endpoint.
func (e *endpoint) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	// Get the header then trim it from the view.
	hdr := header.UDP(pkt.TransportHeader().View())
	if int(hdr.Length()) > pkt.Data.Size()+header.UDPMinimumSize {
		// Malformed packet.
		e.stack.Stats().UDP.MalformedPacketsReceived.Increment()
		e.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
		return
	}

	if !verifyChecksum(hdr, pkt) {
		// Checksum Error.
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

	if e.rcvBufSize >= e.rcvBufSizeMax {
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
			Port: header.UDP(hdr).SourcePort(),
		},
	}
	packet.data = pkt.Data
	e.rcvList.PushBack(packet)
	e.rcvBufSize += pkt.Data.Size()

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
	packet.timestamp = e.stack.Clock().NowNanoseconds()

	e.rcvMu.Unlock()

	// Notify any waiters that there's data to be read now.
	if wasEmpty {
		e.waiterQueue.Notify(waiter.EventIn)
	}
}

// HandleControlPacket implements stack.TransportEndpoint.HandleControlPacket.
func (e *endpoint) HandleControlPacket(id stack.TransportEndpointID, typ stack.ControlType, extra uint32, pkt *stack.PacketBuffer) {
	if typ == stack.ControlPortUnreachable {
		e.mu.RLock()
		if e.state == StateConnected {
			e.lastErrorMu.Lock()
			e.lastError = tcpip.ErrConnectionRefused
			e.lastErrorMu.Unlock()
			e.mu.RUnlock()

			e.waiterQueue.Notify(waiter.EventErr)
			return
		}
		e.mu.RUnlock()
	}
}

// State implements tcpip.Endpoint.State.
func (e *endpoint) State() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return uint32(e.state)
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

func isBroadcastOrMulticast(a tcpip.Address) bool {
	return a == header.IPv4Broadcast || header.IsV4MulticastAddress(a) || header.IsV6MulticastAddress(a)
}

func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.owner = owner
}
