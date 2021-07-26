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
	"gvisor.dev/gvisor/pkg/tcpip/transport/network"
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

// String implements fmt.Stringer.
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

	net network.Endpoint

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
	state     uint32
	dstPort   uint16
	portFlags ports.Flags

	lastErrorMu sync.Mutex `state:"nosave"`
	lastError   tcpip.Error

	// Values used to reserve a port or register a transport endpoint.
	// (which ever happens first).
	boundBindToDevice tcpip.NICID
	boundPortFlags    ports.Flags

	// shutdownFlags represent the current shutdown state of the endpoint.
	shutdownFlags tcpip.ShutdownFlags

	// effectiveNetProtos contains the network protocols actually in use. In
	// most cases it will only contain "netProto", but in cases like IPv6
	// endpoints with v6only set to false, this could include multiple
	// protocols (e.g., IPv6 and IPv4) or a single different protocol (e.g.,
	// IPv4 when IPv6 endpoint is bound or connected to an IPv4 mapped
	// address).
	effectiveNetProtos []tcpip.NetworkProtocolNumber

	// TODO(b/142022063): Add ability to save and restore per endpoint stats.
	stats tcpip.TransportEndpointStats `state:"nosave"`

	// ops is used to get socket level options.
	ops tcpip.SocketOptions

	// frozen indicates if the packets should be delivered to the endpoint
	// during restore.
	frozen bool
}

func newEndpoint(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	e := &endpoint{
		stack: s,
		TransportEndpointInfo: stack.TransportEndpointInfo{
			NetProto:   netProto,
			TransProto: header.UDPProtocolNumber,
		},
		waiterQueue: waiterQueue,
		state:       uint32(StateInitial),
		uniqueID:    s.UniqueID(),
	}
	e.ops.InitHandler(e, e.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	e.ops.SetMulticastLoop(true)
	e.ops.SetSendBufferSize(32*1024, false /* notify */)
	e.ops.SetReceiveBufferSize(32*1024, false /* notify */)
	e.net.Init(s, netProto, header.UDPProtocolNumber, &e.ops)

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

// UniqueID implements stack.TransportEndpoint.
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

// UpdateLastError implements tcpip.SocketOptionsHandler.
func (e *endpoint) UpdateLastError(err tcpip.Error) {
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()
}

// Abort implements stack.TransportEndpoint.
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

	// Close the receive list and drain it.
	e.rcvMu.Lock()
	e.rcvClosed = true
	e.rcvBufSize = 0
	for !e.rcvList.Empty() {
		p := e.rcvList.Front()
		e.rcvList.Remove(p)
	}
	e.rcvMu.Unlock()

	// Update the state.
	e.setEndpointState(StateClosed)

	e.mu.Unlock()

	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

// ModerateRecvBuf implements tcpip.Endpoint.
func (*endpoint) ModerateRecvBuf(int) {}

// Read implements tcpip.Endpoint.
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
// +checklocks:e.mu
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
	e.mu.Lock()
	defer e.mu.DowngradeLock()

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

func (e *endpoint) buildUDPPacketInfo(p tcpip.Payloader, opts tcpip.WriteOptions, netProto tcpip.NetworkProtocolNumber, dst tcpip.Address) (udpPacketInfo, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// If we've shutdown with SHUT_WR we are in an invalid state for sending.
	if e.shutdownFlags&tcpip.ShutdownWrite != 0 {
		return udpPacketInfo{}, &tcpip.ErrClosedForSend{}
	}

	// Prepare for write.
	for {
		retry, err := e.prepareForWrite(opts.To)
		if err != nil {
			return udpPacketInfo{}, err
		}

		if !retry {
			break
		}
	}

	dstPort := e.dstPort
	if opts.To != nil {
		if opts.To.Port == 0 {
			// Port 0 is an invalid port to send to.
			return udpPacketInfo{}, &tcpip.ErrInvalidEndpointState{}
		}

		dstPort = opts.To.Port
	}

	v := make([]byte, p.Len())
	if _, err := io.ReadFull(p, v); err != nil {
		return udpPacketInfo{}, &tcpip.ErrBadBuffer{}
	}
	if len(v) > header.UDPMaximumPacketSize {
		// Payload can't possibly fit in a packet.
		so := e.SocketOptions()
		if so.GetRecvError() {
			so.QueueLocalErr(
				&tcpip.ErrMessageTooLong{},
				netProto,
				header.UDPMaximumPacketSize,
				tcpip.FullAddress{
					//NIC:  route.NICID(),
					Addr: dst,
					Port: dstPort,
				},
				v,
			)
		}
		return udpPacketInfo{}, &tcpip.ErrMessageTooLong{}
	}

	return udpPacketInfo{
		e:          e,
		data:       buffer.View(v),
		localPort:  e.ID.LocalPort,
		remotePort: dstPort,
		noChecksum: e.SocketOptions().GetNoChecksum(),
	}, nil
}

func (e *endpoint) write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	if err := e.LastError(); err != nil {
		return 0, err
	}

	// MSG_MORE is unimplemented. (This also means that MSG_EOR is a no-op.)
	if opts.More {
		return 0, &tcpip.ErrInvalidOptionValue{}
	}

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
	var n int64
	if _, err := e.net.Write(func(netProto tcpip.NetworkProtocolNumber, src, dst tcpip.Address, maxHeaderLength int, requiresTXChecksum bool) (*stack.PacketBuffer, tcpip.Error) {
		u, err := e.buildUDPPacketInfo(p, opts, netProto, dst)
		if err != nil {
			return nil, err
		}
		n = int64(len(u.data))

		vv := u.data.ToVectorisedView()
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: header.UDPMinimumSize + maxHeaderLength,
			Data:               vv,
		})

		// Initialize the UDP header.
		udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
		pkt.TransportProtocolNumber = ProtocolNumber

		length := uint16(pkt.Size())
		udp.Encode(&header.UDPFields{
			SrcPort: u.localPort,
			DstPort: u.remotePort,
			Length:  length,
		})

		// Set the checksum field unless TX checksum offload is enabled.
		// On IPv4, UDP checksum is optional, and a zero value indicates the
		// transmitter skipped the checksum generation (RFC768).
		// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
		if requiresTXChecksum &&
			(!u.noChecksum || netProto == header.IPv6ProtocolNumber) {
			xsum := header.PseudoHeaderChecksum(ProtocolNumber, src, dst, length)
			for _, v := range vv.Views() {
				xsum = header.Checksum(v, xsum)
			}
			udp.SetChecksum(^udp.CalculateChecksum(xsum))
		}
		return pkt, nil
	}, opts); err != nil {
		e.stack.Stats().UDP.PacketSendErrors.Increment()
		return 0, err
	}

	// Track count of pack≈≈ets sent.
	e.stack.Stats().UDP.PacketsSent.Increment()
	return n, nil

	//n, err := u.send()
	//if err != nil {
	//		return 0, err
	//}
	//return int64(n), nil
}

// OnReuseAddressSet implements tcpip.SocketOptionsHandler.
func (e *endpoint) OnReuseAddressSet(v bool) {
	e.mu.Lock()
	e.portFlags.MostRecent = v
	e.mu.Unlock()
}

// OnReusePortSet implements tcpip.SocketOptionsHandler.
func (e *endpoint) OnReusePortSet(v bool) {
	e.mu.Lock()
	e.portFlags.LoadBalanced = v
	e.mu.Unlock()
}

// SetSockOptInt implements tcpip.Endpoint.
func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	return e.net.SetSockOptInt(opt, v)
}

var _ tcpip.SocketOptionsHandler = (*endpoint)(nil)

// HasNIC implements tcpip.SocketOptionsHandler.
func (e *endpoint) HasNIC(id int32) bool {
	return e.stack.HasNIC(tcpip.NICID(id))
}

// SetSockOpt implements tcpip.Endpoint.
func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	return e.net.SetSockOpt(opt)
}

// GetSockOptInt implements tcpip.Endpoint.
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
		return e.net.GetSockOptInt(opt)
	}
}

// GetSockOpt implements tcpip.Endpoint.
func (e *endpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	return e.net.GetSockOpt(opt)
}

// udpPacketInfo contains all information required to send a UDP packet.
//
// This should be used as a value-only type, which exists in order to simplify
// return value syntax. It should not be exported or extended.
type udpPacketInfo struct {
	e          *endpoint
	data       buffer.View
	localPort  uint16
	remotePort uint16
	noChecksum bool
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

// Disconnect implements tcpip.Endpoint.
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
	e.dstPort = 0

	e.net.Disconnect()

	return nil
}

// Connect connects the endpoint to its peer. Specifying a NIC is optional.
func (e *endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.net.ConnectWith(addr, func(netProto tcpip.NetworkProtocolNumber, src, dst tcpip.Address) tcpip.Error {
		id := e.ID
		id.RemotePort = addr.Port
		id.RemoteAddress = dst

		if e.EndpointState() == StateInitial {
			id.LocalAddress = src
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
			return err
		}

		// Remove the old registration.
		if e.ID.LocalPort != 0 {
			e.stack.UnregisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, e.ID, e, oldPortFlags, e.boundBindToDevice)
		}

		e.ID = id
		e.boundBindToDevice = btd
		e.dstPort = addr.Port
		e.effectiveNetProtos = netProtos
		return nil
	}); err != nil {
		return err
	}

	e.RegisterNICID = e.net.RegisterNICID
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

	id := stack.TransportEndpointID{
		LocalPort:    addr.Port,
		LocalAddress: addr.Addr,
	}
	id, btd, err := e.registerWithStack(netProtos, id)
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

	if err := e.net.Bind(addr); err != nil {
		e.stack.UnregisterTransportEndpoint(netProtos, ProtocolNumber, id, e, e.boundPortFlags, btd)
		if e.ID.LocalPort == 0 {
			portRes := ports.Reservation{
				Networks:     netProtos,
				Transport:    ProtocolNumber,
				Addr:         id.LocalAddress,
				Port:         id.LocalPort,
				Flags:        e.boundPortFlags,
				BindToDevice: btd,
				Dest:         tcpip.FullAddress{},
			}
			e.stack.ReleasePort(portRes)
		}
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

	addr := e.net.GetLocalAddress()
	addr.Port = e.ID.LocalPort
	return addr, nil
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

// State implements tcpip.Endpoint.
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

// Wait implements tcpip.Endpoint.
func (*endpoint) Wait() {}

func (e *endpoint) isBroadcastOrMulticast(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	return addr == header.IPv4Broadcast || header.IsV4MulticastAddress(addr) || header.IsV6MulticastAddress(addr) || e.stack.IsSubnetBroadcast(nicID, netProto, addr)
}

// SetOwner implements tcpip.Endpoint.
func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.net.SetOwner(owner)
}

// SocketOptions implements tcpip.Endpoint.
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
